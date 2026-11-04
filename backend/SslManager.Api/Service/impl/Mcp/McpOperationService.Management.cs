using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Mcp;

public sealed partial class McpOperationService
{
    public async Task<ApiResult<McpOperationView>> GetAsync(McpCallerContext caller, string operationId, CancellationToken ct)
    {
        var operation = await db.McpOperations.AsNoTracking().SingleOrDefaultAsync(row => row.Id == operationId, ct);
        if (operation is null || !SameCaller(operation, caller)) return Fail("NOT_FOUND", "当前客户端没有此操作。");
        var permission = await AuthorizeResourcesAsync(caller, "ssl_operations_get", ReadResources(operation).Resources, false, ct);
        return permission.Success ? ApiResult<McpOperationView>.Ok(await ViewAsync(operation, ct)) : Fail(permission.Code, permission.Message);
    }

    public async Task<ApiResult<McpOperationView>> GetForAdminAsync(string operationId, CancellationToken ct)
    {
        var operation = await db.McpOperations.AsNoTracking().SingleOrDefaultAsync(row => row.Id == operationId, ct);
        return operation is null ? Fail("NOT_FOUND", "MCP 操作不存在。") : ApiResult<McpOperationView>.Ok(await ViewAsync(operation, ct));
    }

    public async Task<ApiResult<PageResult<McpOperationView>>> ListForAdminAsync(int page, int pageSize, string? status, CancellationToken ct)
    {
        page = Math.Max(1, page); pageSize = Math.Clamp(pageSize, 1, 100);
        var query = db.McpOperations.AsNoTracking();
        if (!string.IsNullOrEmpty(status)) query = query.Where(row => row.Status == status);
        var total = await query.CountAsync(ct);
        var rows = await query.OrderByDescending(row => row.CreatedAtUtc).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        var views = new List<McpOperationView>();
        foreach (var row in rows) views.Add(await ViewAsync(row, ct));
        return ApiResult<PageResult<McpOperationView>>.Ok(new(views, total, page, pageSize));
    }

    public async Task<ApiResult<McpOperationView>> ApproveAsync(string operationId, string adminUserId, bool approve, int expectedVersion, CancellationToken ct)
    {
        if (!await db.Users.AsNoTracking().AnyAsync(user => user.Id == adminUserId && user.Enabled && user.Role == "admin", ct))
            return Fail("FORBIDDEN", "只有当前有效 Web 管理员可以批准或拒绝操作。");
        var operation = await db.McpOperations.SingleOrDefaultAsync(row => row.Id == operationId, ct);
        if (operation is null) return Fail("NOT_FOUND", "MCP 操作不存在。");
        if (operation.Version != expectedVersion || operation.Status != "Prepared" || operation.ConsumedAtUtc is not null)
            return Fail("CONFLICT", "操作已被批准、拒绝或修改，请刷新后核对。");
        if (Digest(operation.ArgumentsJson) != operation.ArgumentsDigest || operation.ApprovalExpiresAtUtc is not { } expiry || expiry <= DateTime.UtcNow)
            return Fail("MCP_APPROVAL_STALE", "准备操作已过期或输入快照变化，请重新准备。");
        if (approve)
        {
            var permission = await AuthorizeResourcesAsync(Caller(operation), operation.ToolName, ReadResources(operation).Resources, true, ct);
            if (!permission.Success || permission.Data is null) return Fail(permission.Code, permission.Message);
            if (!RevisionsMatch(operation, permission.Data)) return Fail("MCP_APPROVAL_STALE", "权限或配置修订已经改变，请重新准备。");
            if (operation.Kind is "TargetTest" or "TaskInspection")
            {
                var fixedArguments = JsonSerializer.Deserialize<AuxiliaryArguments>(operation.ArgumentsJson, Json);
                if (fixedArguments is null || !await db.DeploymentTargets.AsNoTracking().AnyAsync(target => target.Id == fixedArguments.TargetId && target.Enabled && target.ConfigRevision == fixedArguments.ConfigRevision, ct))
                    return Fail("MCP_APPROVAL_STALE", "原目标连接配置已改变，请重新准备后审批。");
            }
            if (!string.IsNullOrEmpty(operation.BatchId))
            {
                var tasks = await db.DeploymentTasks.AsNoTracking().Where(task => task.BatchId == operation.BatchId).ToListAsync(ct);
                foreach (var task in tasks)
                    if (!await db.DeploymentTargets.AsNoTracking().AnyAsync(target => target.Id == task.TargetId && target.Enabled && target.ConfigRevision == task.ConfigRevision, ct))
                        return Fail("PLAN_STALE", "部署目标配置或启用状态变化，请重新准备计划。");
            }
        }
        var now = DateTime.UtcNow;
        operation.Status = approve ? "Approved" : "Rejected";
        operation.ApprovedBy = adminUserId; operation.ApprovedAtUtc = approve ? now : null;
        operation.ApprovalExpiresAtUtc = approve ? now.AddMinutes(10) : null;
        operation.UpdatedAtUtc = now; operation.Version++;
        operation.Code = approve ? "APPROVED" : "REJECTED";
        operation.Message = approve ? "Web 管理员已批准此不可变操作；提交时将再次复核授权。" : "Web 管理员已拒绝此操作。";
        db.AuditLogs.Add(new() { Id = ids.NewId(), UserId = adminUserId, Username = "WebAdmin", Action = approve ? "ApproveMcpOperation" : "RejectMcpOperation",
            ResourceId = operation.Id, Success = true, Code = operation.Code, Message = "操作客户端：" + operation.ClientId + "；参数摘要：" + operation.ArgumentsDigest, CreatedAtUtc = now });
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateConcurrencyException) { return Fail("CONFLICT", "操作已被其他管理员处理，请刷新。"); }
        return ApiResult<McpOperationView>.Ok(await ViewAsync(operation, ct));
    }

    private async Task<McpOperationView> ViewAsync(McpOperation operation, CancellationToken ct)
    {
        var status = operation.Status;
        var message = PublicOperationMessage(status);
        var summary = ReadResources(operation).SummaryJson;
        if (operation.Status is "Executing" or "Dispatching" && operation.LeaseUntilUtc <= DateTime.UtcNow)
        {
            status = "Unknown";
            message = "原执行租约已中断，请核对原操作；不会重新发送。";
        }
        if (!string.IsNullOrEmpty(operation.BatchId) && operation.ConsumedAtUtc is not null)
        {
            var batch = await db.DeploymentBatches.AsNoTracking().SingleOrDefaultAsync(row => row.Id == operation.BatchId, ct);
            if (batch is not null) status = batch.Status == "NeedsAttention" ? "Unknown" : batch.Status;
        }
        message = PublicOperationMessage(status);
        if (operation.Kind is "TargetTest" or "TaskInspection")
        {
            // 旧记录也不能把远端错误、版本 banner 或任意响应正文带回 MCP。
            var arguments = JsonSerializer.Deserialize<AuxiliaryArguments>(operation.ArgumentsJson, Json);
            bool? matchesExpected = null;
            string? verificationLevel = null;
            if (operation.Kind == "TaskInspection" && operation.ConsumedAtUtc is not null)
            {
                try
                {
                    using var originalSummary = JsonDocument.Parse(summary);
                    if (originalSummary.RootElement.TryGetProperty("result", out var result) && result.ValueKind == JsonValueKind.Object)
                    {
                        if (result.TryGetProperty("matchesExpected", out var matches) && matches.ValueKind is JsonValueKind.True or JsonValueKind.False)
                            matchesExpected = matches.GetBoolean();
                        if (result.TryGetProperty("verificationLevel", out var level) && level.ValueKind == JsonValueKind.String &&
                            level.GetString() is "None" or "FilesChecked" or "PlatformReadback" or "TlsObserved" or "FileHashReadback")
                            verificationLevel = level.GetString();
                    }
                }
                catch (JsonException) { }
            }
            summary = JsonSerializer.Serialize(new { resourceId = arguments?.ResourceId, configRevision = arguments?.ConfigRevision,
                result = operation.ConsumedAtUtc is null ? null : (object)new { success = status == "Succeeded", code = operation.Code, message,
                    matchesExpected, verificationLevel } }, Json);
        }
        return new(operation.Id, operation.Kind, operation.ToolName, status, operation.IdempotencyKey, operation.EffectiveUserId,
            operation.PreparedBy, operation.ApprovedBy, operation.ApprovalExpiresAtUtc, operation.ApprovedAtUtc,
            operation.ConsumedAtUtc, operation.CertificateId, operation.CertificateJobId, operation.BatchId, operation.TaskId,
            operation.PlanRevision, operation.Version, operation.CreatedAtUtc, operation.UpdatedAtUtc, message, operation.Code, summary,
            operation.ClientId, operation.ArgumentsDigest, operation.Status == "Prepared" && operation.ConsumedAtUtc is null && operation.ApprovalExpiresAtUtc > DateTime.UtcNow);
    }

    private static string PublicOperationMessage(string status) => status switch
    {
        "Preparing" => "正在准备操作。",
        "Prepared" => "操作已准备，等待 Web 管理员批准。",
        "Approved" => "操作已批准，首次提交前仍将复核当前授权。",
        "Queued" => "操作已持久受理，等待现有后台任务执行。",
        "Dispatching" or "Executing" or "Running" => "操作正在执行，可查询关联业务任务。",
        "Waiting" => "已提交原业务申请，等待验证和处理完成。",
        "Succeeded" => "操作已完成。",
        "Rejected" => "操作已由 Web 管理员拒绝。",
        "Blocked" => "操作已停止，请在 Web 核对当前权限和关联任务。",
        "Unknown" or "NeedsAttention" => "原操作结果待核对，系统不会重新发送。",
        "Failed" => "操作未完成，请在 Web 查看关联业务任务或目标。",
        "Expired" => "操作已过期，请重新准备。",
        _ => "操作状态已更新。"
    };
}
