using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Api.Service.impl;

public sealed partial class CertificateManagementService
{
    internal async Task<ApiResult<IReadOnlyList<McpCertificateChallenge>>> ReadValidationsForMcpAsync(string certificateId, CancellationToken ct)
    {
        var certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(x => x.Id == certificateId, ct);
        if (certificate is null) return ApiResult<IReadOnlyList<McpCertificateChallenge>>.Fail("NOT_FOUND", "证书不存在。");
        var rows = await db.ValidationRecords.AsNoTracking().Where(x => x.CertificateId == certificateId).Take(1001)
            .Select(x => new McpCertificateChallenge("Application", x.Domain, x.Name, x.Type, x.Value, x.IsPersistent, false)).ToListAsync(ct);
        if (rows.Count > 1000) return ApiResult<IReadOnlyList<McpCertificateChallenge>>.Fail("VALIDATION_LIMIT", "验证记录过多。");
        if (HasReference(Reference(certificate)))
        {
            var context = await ResolveAccountAsync(certificate.AccountId, ct);
            if (!context.Success || context.Data is null) return ApiResult<IReadOnlyList<McpCertificateChallenge>>.Fail("ACCOUNT_UNAVAILABLE", "原证书账号不可用。");
            var detail = await context.Data.Provider.GetAsync(context.Data.Account, Reference(certificate), ct);
            if (!detail.Success || detail.Data is null) return ApiResult<IReadOnlyList<McpCertificateChallenge>>.Fail("CLOUD_QUERY_FAILED", "原云端验证状态暂不可用。");
            if (detail.Data.Challenges.Count + (detail.Data.RevocationChallenges?.Count ?? 0) > 1000)
                return ApiResult<IReadOnlyList<McpCertificateChallenge>>.Fail("VALIDATION_LIMIT", "验证记录过多。");
            rows.AddRange(detail.Data.Challenges.Select(x => new McpCertificateChallenge("Application", x.Domain, x.Name, x.Type, x.Value, x.IsPersistent, x.IsRelative)));
            rows.AddRange((detail.Data.RevocationChallenges ?? []).Select(x => new McpCertificateChallenge("Revocation", x.Domain, x.Name, x.Type, x.Value, x.IsPersistent, x.IsRelative)));
        }
        return ApiResult<IReadOnlyList<McpCertificateChallenge>>.Ok(rows.Distinct().ToArray());
    }
    private string? mcpMaintenanceOperationId;
    private Func<CancellationToken, Task<ApiResult<bool>>>? mcpBeforeMaintenanceWrite;
    internal sealed record McpMaintenanceResult(bool Success, string Code, string Status, object? PublicResult = null);

    /// <summary>复用原证书维护服务，原操作身份贯穿首次云提交及后续既有Job；不会隐式重发结果未知的请求。</summary>
    internal async Task<McpMaintenanceResult> InvokeMaintenanceForMcpAsync(string tool, string certificateId, string reason,
        string operationId, Func<CancellationToken, Task<ApiResult<bool>>> beforeWrite, CancellationToken ct)
    {
        var previous = mcpMaintenanceOperationId; var previousGuard = mcpBeforeMaintenanceWrite;
        mcpMaintenanceOperationId = operationId; mcpBeforeMaintenanceWrite = beforeWrite;
        try
        {
            using var exactSourceBoundary = McpCloudMutationGuard.Enter(token => DemandMcpMaintenanceWriteAsync(token), operationId);
            ApiResult<CloudOperation>? cloud = null;
            if (tool == "ssl_certificates_revoke") cloud = await RevokeAsync(certificateId, reason, ct);
            else if (tool == "ssl_certificates_cancel") cloud = await CancelAsync(certificateId, ct);
            else if (tool == "ssl_certificates_delete") cloud = await DeleteAsync(certificateId, ct);
            else if (tool == "ssl_certificates_cleanup_retry")
            {
                var retry = await RetryCleanupAsync(certificateId, ct);
                return retry.Success ? new(true, "QUEUED", "Waiting", new { certificateId }) : new(false, "CERTIFICATE_MAINTENANCE_FAILED", "Failed");
            }
            if (cloud is null) return new(false, "TOOL_NOT_FOUND", "Failed");
            if (!cloud.Success) return new(false, IsUncertain(cloud.Code) ? "RESULT_UNKNOWN" : "CERTIFICATE_MAINTENANCE_FAILED",
                IsUncertain(cloud.Code) ? "Unknown" : "Failed");
            var jobId = await db.McpOperations.AsNoTracking().Where(x => x.Id == operationId).Select(x => x.CertificateJobId).SingleAsync(ct);
            var pending = jobId.Length > 0 && await db.CertificateJobs.AsNoTracking().AnyAsync(job => job.Id == jobId
                && (job.Status == "Waiting" || job.Status == "Submitting"), ct);
            return new(true, "OK", pending ? "Waiting" : "Succeeded", new { certificateId });
        }
        finally { mcpMaintenanceOperationId = previous; mcpBeforeMaintenanceWrite = previousGuard; }
    }

    internal async Task<ApiResult<int>> SyncForMcpAsync(string accountId, string operationId, CancellationToken ct)
    {
        var previous = mcpMaintenanceOperationId; mcpMaintenanceOperationId = operationId;
        try { return await SyncCoreAsync(accountId, token => DemandMcpMaintenanceWriteAsync(token), ct); }
        finally { mcpMaintenanceOperationId = previous; }
    }

    private async Task DemandMcpMaintenanceWriteAsync(CancellationToken ct, bool firstWrite = false)
    {
        var source = mcpMaintenanceOperationId ?? McpCloudMutationGuard.CurrentOperationId;
        if (source is null) return;
        if (firstWrite && mcpBeforeMaintenanceWrite is { } guard)
        {
            var allowed = await guard(ct);
            if (!allowed.Success) throw new McpExecutionDeniedException(allowed.Code, "原证书维护资源或权限已变化，未执行写入。");
            mcpBeforeMaintenanceWrite = null;
        }
        var permission = mcpGate is null ? ApiResult<bool>.Fail("MCP_GATE_UNAVAILABLE", "MCP 执行门禁不可用。")
            : await mcpGate.CheckOperationAsync(source, ct);
        if (!permission.Success) throw new McpExecutionDeniedException(permission.Code, "原 MCP 维护授权已失效，未执行写入。");
    }

    private async Task<ApiResult<bool>> CheckMcpCertificateWriteAsync(string certificateId, CancellationToken ct)
    {
        var source = mcpMaintenanceOperationId ?? McpCloudMutationGuard.CurrentOperationId;
        if (source is not null)
            return mcpGate is null ? ApiResult<bool>.Fail("MCP_GATE_UNAVAILABLE", "MCP 执行门禁不可用。") : await mcpGate.CheckOperationAsync(source, ct);
        return mcpGate is null ? ApiResult<bool>.Ok(true) : await mcpGate.CheckCertificateAsync(certificateId, ct);
    }

    private async Task LinkMcpMaintenanceJobAsync(CertificateJob job, CancellationToken ct)
    {
        if (mcpMaintenanceOperationId is not null)
        {
            var operation = await db.McpOperations.SingleAsync(x => x.Id == mcpMaintenanceOperationId, ct);
            operation.CertificateId = job.CertificateId; operation.CertificateJobId = job.Id; return;
        }
        var source = McpCloudMutationGuard.CurrentOperationId;
        if (source is null) return;
        // 周期策略可产生多张证书、多轮维护Job；每个Job独立保留原来源，不覆盖策略本身的单一关联字段。
        var parent = await db.McpOperations.AsNoTracking().SingleAsync(x => x.Id == source, ct);
        if (await db.McpOperations.AnyAsync(x => x.Kind == "ScheduleMaintenance" && x.CertificateJobId == job.Id, ct)) return;
        var certificate = await db.Certificates.SingleAsync(x => x.Id == job.CertificateId, ct);
        var argumentJson = JsonSerializer.Serialize(new { bindingDigest = await McpCertificateBindingHashAsync(db, certificate, ct) }, McpJson);
        var resource = JsonSerializer.Deserialize<McpOperationResourceSnapshot>(parent.ResourceJson, McpJson)
            ?? throw new McpExecutionDeniedException("MCP_SOURCE_INVALID", "原周期策略缺少来源范围。");
        var now = DateTime.UtcNow;
        db.McpOperations.Add(new McpOperation
        {
            Id = ids.NewId(), Kind = "ScheduleMaintenance", ToolName = parent.ToolName, ClientId = parent.ClientId,
            EffectiveUserId = parent.EffectiveUserId, AuthorizationId = parent.AuthorizationId,
            AuthenticationType = parent.AuthenticationType, ApiKeyId = parent.ApiKeyId, ScopesJson = parent.ScopesJson,
            SourceIp = parent.SourceIp, PreparedBy = parent.PreparedBy, ApprovedBy = parent.ApprovedBy,
            SettingsRevision = parent.SettingsRevision, ClientRevision = parent.ClientRevision, PolicyRevision = parent.PolicyRevision,
            IdempotencyKey = "mcp-maintenance-job-" + job.Id, CertificateId = job.CertificateId, CertificateJobId = job.Id,
            ArgumentsJson = argumentJson, ArgumentsDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(argumentJson))),
            ResourceJson = JsonSerializer.Serialize(resource with { ParentOperationId = parent.Id }, McpJson),
            Status = "Waiting", ConsumedAtUtc = now, CreatedAtUtc = now, UpdatedAtUtc = now
        });
    }

    private async Task RefreshMcpMaintenanceJobAsync(string jobId, string status, CancellationToken ct)
    {
        var state = status switch { "Completed" => "Succeeded", "Failed" => "Failed", "SubmissionUnknown" => "Unknown", _ => "Waiting" };
        await db.McpOperations.Where(x => (x.Kind == "Business" || x.Kind == "ScheduleMaintenance") && x.CertificateJobId == jobId && x.Status != "Blocked")
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, state).SetProperty(x => x.UpdatedAtUtc, DateTime.UtcNow)
                .SetProperty(x => x.Message, "原证书维护任务已更新，请按公开状态核对。")
                .SetProperty(x => x.Version, x => x.Version + 1), ct);
    }

    internal static async Task<string> McpCertificateBindingHashAsync(AppDbContext database, ManagedCertificate item, CancellationToken ct)
    {
        var zone = item.DnsZoneId is { Length: > 0 } ? await database.Domains.AsNoTracking().Where(x => x.Id == item.DnsZoneId)
            .Select(x => new { x.Id, x.AccountId, x.ZoneId, x.Provider, x.Name, x.Status }).SingleOrDefaultAsync(ct) : null;
        var accountIds = new[] { item.AccountId, zone?.AccountId ?? "" };
        var accounts = await database.CloudAccounts.AsNoTracking().Where(x => accountIds.Contains(x.Id)).OrderBy(x => x.Id)
            .Select(x => new { x.Id, x.Provider, x.Enabled, x.UseForCertificates, x.UseForDns, x.ProtectedAccessKeyId,
                x.ProtectedAccessKeySecret, x.AcmeDirectoryUrl, x.AcmeAccountMode, x.AcmeRegistrationStatus, x.AliyunContactId, x.UpdatedAtUtc }).ToArrayAsync(ct);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new
        { item.Id, item.AccountId, item.Provider, item.Domain, item.CertificateId, item.OrderId, item.InstanceId,
            item.ApiVersion, item.ValidationMode, item.AutoCleanup, item.DnsZoneId, zone, accounts }, McpJson))));
    }
}
