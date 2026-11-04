using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Models;
using SslManager.Api.Common.Mcp;
using System.Security.Cryptography;
using System.Text;

namespace SslManager.Api.Service.impl.Mcp;

/// <summary>只持久保存来源身份及 scope，不保存 HTTP 上下文或原 access token。</summary>
public sealed class McpExecutionGate(AppDbContext db, IMcpAuthorizationService authorization) : IMcpExecutionGate
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<ApiResult<bool>> CheckCertificateAsync(string certificateId, CancellationToken ct)
    {
        var operationId = await db.McpOperations.AsNoTracking().Where(row => row.CertificateId == certificateId && row.Kind == "CertificateApplication")
            .Select(row => row.Id).FirstOrDefaultAsync(ct);
        operationId ??= await McpScheduleOrigin.FindForCertificateAsync(db, certificateId, ct);
        return operationId is null ? ApiResult<bool>.Ok(true) : await CheckOperationAsync(operationId, ct);
    }

    public async Task<ApiResult<bool>> CheckDeploymentAsync(string batchId, CancellationToken ct)
    {
        var operationIds = await db.McpOperations.AsNoTracking().Where(row => row.BatchId == batchId && row.ConsumedAtUtc != null)
            .Select(row => row.Id).ToArrayAsync(ct);
        foreach (var id in operationIds)
        {
            var allowed = await CheckOperationAsync(id, ct);
            if (!allowed.Success) return allowed;
        }
        if (operationIds.Length > 0) return ApiResult<bool>.Ok(true);
        var source = await McpScheduleOrigin.FindForBatchAsync(db, batchId, ct);
        return source is null ? ApiResult<bool>.Ok(true) : await CheckOperationAsync(source, ct);
    }

    public Task<ApiResult<bool>> CheckOperationAsync(string operationId, CancellationToken ct)
        => CheckOperationCoreAsync(operationId, new(StringComparer.Ordinal), ct);

    private async Task<ApiResult<bool>> CheckOperationCoreAsync(string operationId, HashSet<string> chain, CancellationToken ct)
    {
        if (chain.Count >= 16 || !chain.Add(operationId)) return ApiResult<bool>.Fail("MCP_SOURCE_INVALID", "MCP 来源链存在循环或过深，未执行写入。");
        var operation = await db.McpOperations.AsNoTracking().SingleOrDefaultAsync(row => row.Id == operationId, ct);
        if (operation is null) return ApiResult<bool>.Fail("MCP_OPERATION_MISSING", "MCP 操作来源已不存在。");
        if (operation.ConsumedAtUtc is null || operation.Status is "Rejected" or "Blocked" or "Failed" or "Unknown")
            return ApiResult<bool>.Fail("MCP_OPERATION_NOT_ACCEPTED", "MCP 操作尚未受理或已停止。");
        McpResourceScope[] resources;
        bool allDomainsRequired;
        string parentOperationId;
        McpCallerContext caller;
        try
        {
            var snapshot = JsonSerializer.Deserialize<McpOperationResourceSnapshot>(operation.ResourceJson, Json);
            resources = snapshot?.Resources ?? [];
            allDomainsRequired = snapshot?.AllDomainsRequired == true;
            parentOperationId = snapshot?.ParentOperationId ?? "";
            caller = new(operation.ClientId, operation.EffectiveUserId, operation.AuthorizationId,
                JsonSerializer.Deserialize<string[]>(operation.ScopesJson, Json) ?? [], operation.SourceIp,
                AuthenticationType: operation.AuthenticationType, ApiKeyId: operation.ApiKeyId);
        }
        catch (JsonException) { return ApiResult<bool>.Fail("MCP_OPERATION_INVALID", "MCP 操作来源快照无法核对。"); }
        if (resources.Length == 0) return ApiResult<bool>.Fail("MCP_OPERATION_INVALID", "MCP 操作缺少明确的资源范围。");
        if (operation.ArgumentsDigest.Length > 0 && Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(operation.ArgumentsJson))) != operation.ArgumentsDigest)
            return ApiResult<bool>.Fail("MCP_SNAPSHOT_INVALID", "MCP 操作输入摘要不一致，未执行写入。");
        if (parentOperationId.Length > 0)
        {
            var parent = await CheckOperationCoreAsync(parentOperationId, chain, ct);
            if (!parent.Success) return parent;
        }
        if (!string.IsNullOrEmpty(operation.CertificateId))
        {
            var certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(row => row.Id == operation.CertificateId, ct);
            var domain = certificate is null ? "" : CertificateManagementService.PrimaryDomain(certificate.Domain).Trim().TrimEnd('.').ToLowerInvariant();
            if (certificate is null || !resources.Any(resource => resource.AccountId == certificate.AccountId && resource.Domain == domain))
                return ApiResult<bool>.Fail("MCP_RESOURCE_CHANGED", "原证书账号或业务域名已改变，不能沿用旧授权继续写入。");
            if (operation.Kind is "Business" or "ScheduleMaintenance")
            {
                using var arguments = JsonDocument.Parse(operation.ArgumentsJson);
                if (arguments.RootElement.TryGetProperty("bindingDigest", out var binding) && binding.ValueKind == JsonValueKind.String
                    && binding.GetString() is { Length: > 0 } expected && expected != await CertificateManagementService.McpCertificateBindingHashAsync(db, certificate, ct))
                    return ApiResult<bool>.Fail("MCP_RESOURCE_CHANGED", "原证书、DNS 区域或账号配置已改变，维护任务已停止。");
            }
        }
        var tool = operation.Kind switch
        {
            "CertificateApplication" => "ssl_certificate_application_submit",
            "Deployment" => "ssl_deployment_submit",
            _ => operation.ToolName
        };
        // 已接受任务不检查旧令牌或已消费批准的自然到期，仍逐边界检查实时撤销及资源规则。
        foreach (var resource in resources)
        {
            var allowed = await authorization.AuthorizeAsync(caller, tool, resource, true, ct);
            if (!allowed.Success) return ApiResult<bool>.Fail(allowed.Code, allowed.Message);
            if (allDomainsRequired && allowed.Data?.Rules.Any(rule => rule.AllDomains) != true)
                return ApiResult<bool>.Fail("FORBIDDEN", "此账号级操作需要明确授权全部域名。");
        }
        if (!string.IsNullOrEmpty(operation.BatchId))
        {
            var revisions = await db.DeploymentTasks.AsNoTracking().Where(task => task.BatchId == operation.BatchId)
                .Select(task => new { task.TargetId, task.ConfigRevision }).ToListAsync(ct);
            foreach (var revision in revisions)
                if (!await db.DeploymentTargets.AsNoTracking().AnyAsync(target => target.Id == revision.TargetId && target.Enabled && target.ConfigRevision == revision.ConfigRevision, ct))
                    return ApiResult<bool>.Fail("MCP_TARGET_CHANGED", "MCP 批次的部署目标已停用或配置已改变。");
        }
        return ApiResult<bool>.Ok(true);
    }
}

/// <summary>资源快照只包含公开身份和审批展示摘要，永不包含凭据、材料或任意脚本。</summary>
internal sealed record McpOperationResourceSnapshot(McpResourceScope[] Resources, string SummaryJson = "{}", bool AllDomainsRequired = false, string ParentOperationId = "");
