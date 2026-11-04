using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl.Mcp;

/// <summary>只持久保存来源身份及 scope，不保存 HTTP 上下文或原 access token。</summary>
public sealed class McpExecutionGate(AppDbContext db, IMcpAuthorizationService authorization) : IMcpExecutionGate
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<ApiResult<bool>> CheckCertificateAsync(string certificateId, CancellationToken ct)
    {
        var operationId = await db.McpOperations.AsNoTracking().Where(row => row.CertificateId == certificateId && row.Kind == "CertificateApplication")
            .Select(row => row.Id).FirstOrDefaultAsync(ct);
        return operationId is null ? ApiResult<bool>.Ok(true) : await CheckOperationAsync(operationId, ct);
    }

    public async Task<ApiResult<bool>> CheckDeploymentAsync(string batchId, CancellationToken ct)
    {
        var operationId = await db.McpOperations.AsNoTracking().Where(row => row.BatchId == batchId && row.Kind == "Deployment")
            .Select(row => row.Id).FirstOrDefaultAsync(ct);
        return operationId is null ? ApiResult<bool>.Ok(true) : await CheckOperationAsync(operationId, ct);
    }

    public async Task<ApiResult<bool>> CheckOperationAsync(string operationId, CancellationToken ct)
    {
        var operation = await db.McpOperations.AsNoTracking().SingleOrDefaultAsync(row => row.Id == operationId, ct);
        if (operation is null) return ApiResult<bool>.Fail("MCP_OPERATION_MISSING", "MCP 操作来源已不存在。");
        if (operation.ConsumedAtUtc is null || operation.Status is "Rejected" or "Blocked" or "Failed" or "Unknown")
            return ApiResult<bool>.Fail("MCP_OPERATION_NOT_ACCEPTED", "MCP 操作尚未受理或已停止。");
        McpResourceScope[] resources;
        McpCallerContext caller;
        try
        {
            var snapshot = JsonSerializer.Deserialize<McpOperationResourceSnapshot>(operation.ResourceJson, Json);
            resources = snapshot?.Resources ?? [];
            caller = new(operation.ClientId, operation.EffectiveUserId, operation.AuthorizationId,
                JsonSerializer.Deserialize<string[]>(operation.ScopesJson, Json) ?? [], operation.SourceIp,
                AuthenticationType: operation.AuthenticationType, ApiKeyId: operation.ApiKeyId);
        }
        catch (JsonException) { return ApiResult<bool>.Fail("MCP_OPERATION_INVALID", "MCP 操作来源快照无法核对。"); }
        if (resources.Length == 0) return ApiResult<bool>.Fail("MCP_OPERATION_INVALID", "MCP 操作缺少明确的资源范围。");
        if (!string.IsNullOrEmpty(operation.CertificateId))
        {
            var certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(row => row.Id == operation.CertificateId, ct);
            var domain = certificate is null ? "" : CertificateManagementService.PrimaryDomain(certificate.Domain).Trim().TrimEnd('.').ToLowerInvariant();
            if (certificate is null || !resources.Any(resource => resource.AccountId == certificate.AccountId && resource.Domain == domain))
                return ApiResult<bool>.Fail("MCP_RESOURCE_CHANGED", "原证书账号或业务域名已改变，不能沿用旧授权继续写入。");
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
internal sealed record McpOperationResourceSnapshot(McpResourceScope[] Resources, string SummaryJson = "{}");
