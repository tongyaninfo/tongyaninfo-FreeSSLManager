using System.Text.Json;
using System.Text;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl;

public sealed partial class CertificateManagementService
{
    private static readonly JsonSerializerOptions McpJson = new(JsonSerializerDefaults.Web);

    /// <summary>复用原证书队列，先以持久租约锁定唯一派发者；Dispatching 后绝不因过期再次申请。</summary>
    private async Task DispatchMcpApplicationAsync(string jobId, CancellationToken ct)
    {
        await OperationGate.WaitAsync(ct);
        try
        {
            var operation = await db.McpOperations.AsNoTracking().SingleOrDefaultAsync(row => row.CertificateJobId == jobId, ct);
            if (operation is null || operation.Status != "Queued") return;
            if (Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(operation.ArgumentsJson))) != operation.ArgumentsDigest)
            { await StopMcpApplicationAsync(operation.Id, jobId, "Blocked", "MCP_SNAPSHOT_INVALID", "申请输入快照摘要不一致，未发送云端请求。", ct); return; }
            var permission = mcpGate is null ? null : await mcpGate.CheckOperationAsync(operation.Id, ct);
            if (permission?.Success != true)
            {
                await StopMcpApplicationAsync(operation.Id, jobId, "Blocked", permission?.Code ?? "MCP_GATE_UNAVAILABLE",
                    permission?.Message ?? "MCP 执行门禁未注册，未发送云端请求。", ct);
                return;
            }
            var request = JsonSerializer.Deserialize<Models.CertificateApplyRequest>(operation.ArgumentsJson, McpJson);
            if (request is null) { await StopMcpApplicationAsync(operation.Id, jobId, "Blocked", "MCP_SNAPSHOT_INVALID", "申请输入快照无法读取。", ct); return; }
            var prepared = await PrepareApplicationInternalAsync(request, ct);
            if (!prepared.Success || prepared.Data is null)
            { await StopMcpApplicationAsync(operation.Id, jobId, "Failed", prepared.Code, prepared.Message, ct); return; }
            var now = DateTime.UtcNow;
            var lease = ids.NewId();
            await using (var transaction = await db.Database.BeginTransactionAsync(ct))
            {
                var claimed = await db.McpOperations.Where(row => row.Id == operation.Id && row.Status == "Queued" && row.Version == operation.Version &&
                    (row.LeaseUntilUtc == null || row.LeaseUntilUtc < now))
                    .ExecuteUpdateAsync(update => update.SetProperty(row => row.Status, "Dispatching").SetProperty(row => row.LeaseToken, lease)
                        .SetProperty(row => row.LeaseUntilUtc, now.AddMinutes(5)).SetProperty(row => row.UpdatedAtUtc, now)
                        .SetProperty(row => row.Version, row => row.Version + 1), ct);
                if (claimed != 1) return;
                var jobClaimed = await db.CertificateJobs.Where(row => row.Id == jobId && row.Status == "McpQueued")
                    .ExecuteUpdateAsync(update => update.SetProperty(row => row.Status, "Submitting").SetProperty(row => row.LeaseUntilUtc, now.AddMinutes(5)), ct);
                if (jobClaimed != 1) return;
                await transaction.CommitAsync(ct);
            }
            db.ChangeTracker.Clear();
            var job = await db.CertificateJobs.SingleAsync(row => row.Id == jobId, ct);
            var certificate = await db.Certificates.SingleAsync(row => row.Id == operation.CertificateId, ct);
            if (job.CertificateId != certificate.Id || job.Kind != "Apply" || certificate.Status != "Submitting" ||
                certificate.AccountId != prepared.Data.Request.AccountId || certificate.Domain != prepared.Data.Domain)
            { await StopMcpApplicationAsync(operation.Id, jobId, "Blocked", "MCP_INTENT_CHANGED", "原证书申请意图已变化，未发送云端请求。", ct); return; }
            // 租约持久化后、真正发送前再检查；已知未发送时可明确停止，无需伪造未知结果。
            permission = await mcpGate!.CheckOperationAsync(operation.Id, ct);
            if (!permission.Success)
            { await StopMcpApplicationAsync(operation.Id, jobId, "Blocked", permission.Code, permission.Message, ct); return; }
            try
            {
                using var cloudWrites = Common.Mcp.McpCloudMutationGuard.Enter(async token =>
                {
                    var current = await mcpGate!.CheckOperationAsync(operation.Id, token);
                    if (!current.Success) throw new McpExecutionDeniedException(current.Code, "原申请授权已失效，未发送云端写入。");
                }, operation.Id);
                var dispatched = await DispatchApplicationInternalAsync(certificate, job, prepared.Data.Request, prepared.Data.Context, ct);
                var publicMessage = dispatched.Success ? "原申请已派发，等待云端验证处理。" : "原申请未完成或结果待核对，请在 Web 查看关联证书任务。";
                await db.McpOperations.Where(row => row.Id == operation.Id && row.Status == "Dispatching" && row.LeaseToken == lease)
                    .ExecuteUpdateAsync(update => update.SetProperty(row => row.Status, dispatched.Success ? "Waiting" : certificate.Status == "SubmissionUnknown" ? "Unknown" : "Failed")
                        .SetProperty(row => row.Code, dispatched.Code).SetProperty(row => row.Message, publicMessage)
                        .SetProperty(row => row.LeaseUntilUtc, (DateTime?)null).SetProperty(row => row.UpdatedAtUtc, DateTime.UtcNow)
                        .SetProperty(row => row.Version, row => row.Version + 1), CancellationToken.None);
            }
            catch (Exception)
            {
                // 包括请求取消：可能已经发送，保留原证书/Job/operation，任何重试均只返回原身份。
                await StopMcpApplicationAsync(operation.Id, jobId, "Unknown", "SUBMISSION_UNKNOWN", "申请派发中断，结果未知；请核对原云端申请，不能重发。", CancellationToken.None);
                if (ct.IsCancellationRequested) throw;
            }
        }
        finally { OperationGate.Release(); }
    }

    private async Task StopMcpApplicationAsync(string operationId, string jobId, string status, string code, string message, CancellationToken ct)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await db.McpOperations.Where(row => row.Id == operationId).ExecuteUpdateAsync(update => update
            .SetProperty(row => row.Status, status).SetProperty(row => row.Code, code).SetProperty(row => row.Message, "原 MCP 申请已停止或结果待核对，请在 Web 查看关联证书任务。")
            .SetProperty(row => row.LeaseUntilUtc, (DateTime?)null).SetProperty(row => row.UpdatedAtUtc, DateTime.UtcNow)
            .SetProperty(row => row.Version, row => row.Version + 1), ct);
        var certificateId = await db.CertificateJobs.AsNoTracking().Where(row => row.Id == jobId).Select(row => row.CertificateId).SingleAsync(ct);
        await db.CertificateJobs.Where(row => row.Id == jobId).ExecuteUpdateAsync(update => update
            .SetProperty(row => row.Status, status == "Unknown" ? "SubmissionUnknown" : "Failed").SetProperty(row => row.Message, message)
            .SetProperty(row => row.LeaseUntilUtc, (DateTime?)null), ct);
        await db.Certificates.Where(row => row.Id == certificateId && (row.Status == "Submitting" || row.Status == "SubmissionUnknown")).ExecuteUpdateAsync(update => update
            .SetProperty(row => row.Status, status == "Unknown" ? "SubmissionUnknown" : "Failed"), ct);
        await transaction.CommitAsync(ct);
    }

    private async Task RefreshMcpApplicationStateAsync(string jobId, string jobStatus, string message, CancellationToken ct)
    {
        var status = jobStatus switch { "Completed" => "Succeeded", "Failed" => "Failed", "SubmissionUnknown" => "Unknown", _ => "Waiting" };
        var publicMessage = status == "Succeeded" ? "原证书申请已完成。" : "原证书申请处理中或待核对，可在 Web 查看关联任务。";
        await db.McpOperations.Where(row => row.CertificateJobId == jobId && row.Status != "Blocked")
            .ExecuteUpdateAsync(update => update.SetProperty(row => row.Status, status).SetProperty(row => row.Message, publicMessage)
                .SetProperty(row => row.LeaseUntilUtc, (DateTime?)null).SetProperty(row => row.UpdatedAtUtc, DateTime.UtcNow)
                .SetProperty(row => row.Version, row => row.Version + 1), ct);
    }
}
