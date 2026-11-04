using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service.impl.Deployment;

namespace SslManager.Api.Service.impl.Mcp;

/// <summary>准备、Web 审批与持久受理分离；调用重试始终沿用原参数和原有效用户。</summary>
public sealed partial class McpOperationService(AppDbContext db, IMcpAuthorizationService authorization,
    CertificateManagementService certificates, IDeploymentService deployments, IDeploymentTargetService targets,
    IIdGenerator ids, DomainManagementService? businessDomains = null, IDataProtectionProvider? businessProtection = null,
    ICertificateScheduleService? businessSchedules = null, ICloudAccountStore? businessAccounts = null,
    ICloudProviderResolver? businessProviders = null) : IMcpOperationService
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private sealed record DeploymentArguments(string CertificateId, DeploymentPlanRequest Request);
    private sealed record AuxiliaryArguments(string ResourceId, int ConfigRevision, string TargetId);

    public async Task<ApiResult<McpOperationView>> PrepareApplicationAsync(McpCallerContext caller, CertificateApplyRequest request,
        string idempotencyKey, CancellationToken ct)
    {
        request = request with { Domain = NormalizeDomain(request.Domain), Alias = request.Alias?.Trim() ?? "", ApiVersion = request.ApiVersion?.Trim() ?? "V2" };
        if (!CertificateManagementService.IsValidDomain(request.Domain) || request.Alias.Length > 100 ||
            request.ValidationMode is not ("NativeAutoDns" or "ManagedDns" or "ManualDns" or "File") || request.ApiVersion != "V2")
            return Fail("VALIDATION", "请提供有效单域名、免费 V2 证书规格和受支持的验证方式。");
        var primaryPermission = await authorization.AuthorizeAsync(caller, "ssl_certificate_application_prepare", new(request.AccountId, request.Domain), false, ct);
        if (!primaryPermission.Success) return Fail(primaryPermission.Code, primaryPermission.Message);
        var account = await db.CloudAccounts.AsNoTracking().SingleOrDefaultAsync(row => row.Id == request.AccountId && row.Enabled && row.UseForCertificates, ct);
        if (account is null || account.Provider is not ("TencentCloud" or "Aliyun" or "Acme")) return Fail("ACCOUNT_UNAVAILABLE", "所选免费证书账号不可用。");
        var resources = new List<McpResourceScope> { new(request.AccountId, request.Domain) };
        if (!string.IsNullOrEmpty(request.DnsZoneId))
        {
            var zone = await db.Domains.AsNoTracking().SingleOrDefaultAsync(row => row.Id == request.DnsZoneId && row.Status != "NotPresent", ct);
            if (zone is null || !CertificateManagementService.BelongsTo(request.Domain, zone.Name)) return Fail("DNS_ZONE_MISMATCH", "验证区域不覆盖申请域名。");
            if (zone.AccountId != request.AccountId) resources.Add(new(zone.AccountId, request.Domain));
        }
        var summary = JsonSerializer.Serialize(new { request.AccountId, request.Domain, request.ValidationMode, request.AutoCleanup,
            provider = account.Provider, isStaging = account.AcmeDirectoryUrl.Contains("staging", StringComparison.Ordinal),
            apiVersion = request.ApiVersion, instanceId = request.InstanceId,
            free = true, freeSpecification = account.Provider switch { "TencentCloud" => "83", "Aliyun" => AliyunCloudService.FreeProduct, _ => "LetsEncrypt" },
            dnsImpact = request.ValidationMode is "NativeAutoDns" or "ManagedDns" ? "将创建或复用 DNS 验证记录，按申请的自动清理设置处理。" : "需要完成所选域名验证。" }, Json);
        return await PrepareAsync(caller, "CertificateApplication", "ssl_certificate_application_prepare", request,
            resources.ToArray(), summary, idempotencyKey, ct);
    }

    public async Task<ApiResult<McpOperationView>> PrepareDeploymentAsync(McpCallerContext caller, string certificateId,
        DeploymentPlanRequest request, string idempotencyKey, CancellationToken ct)
    {
        if (request.Targets is not { Count: > 0 and <= 20 } || request.Targets.Any(target => string.IsNullOrWhiteSpace(target.TargetId) ||
            !string.IsNullOrEmpty(target.RemoteCertificateId) || target.SiteIds is { Length: > 0 }) ||
            request.Targets.Select(target => target.TargetId).Distinct().Count() != request.Targets.Count)
            return Fail("VALIDATION", "请选择 1～20 个已保存目标；MCP 不接受临时站点或远端资源覆盖。");
        request = new(request.Targets.OrderBy(target => target.TargetId, StringComparer.Ordinal).ToArray());
        var certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(row => row.Id == certificateId && row.Status == "Issued", ct);
        if (certificate is null || !certificate.CanDeploy) return Fail("CERTIFICATE_UNAVAILABLE", "请选择持有私钥的正式已签发证书。");
        var resources = new List<McpResourceScope>();
        foreach (var selection in request.Targets)
        {
            var target = await db.DeploymentTargets.AsNoTracking().SingleOrDefaultAsync(row => row.Id == selection.TargetId && row.Enabled, ct);
            if (target is null) return Fail("TARGET_UNAVAILABLE", "部分部署目标不存在或已停用。");
            DeploymentTargetConfiguration? configuration;
            try { configuration = JsonSerializer.Deserialize<DeploymentTargetConfiguration>(target.ConfigurationJson, Json); }
            catch (JsonException) { return Fail("TARGET_INVALID", "目标配置无法读取。"); }
            if (configuration is null || !string.IsNullOrEmpty(configuration.SourceDomain) &&
                NormalizeDomain(configuration.SourceDomain) != NormalizeDomain(certificate.Domain))
                return Fail("TARGET_DOMAIN_MISMATCH", "证书与目标绑定的域名不一致。");
            resources.Add(new(certificate.AccountId, NormalizeDomain(certificate.Domain), selection.TargetId));
        }
        var result = await PrepareAsync(caller, "Deployment", "ssl_deployment_plan", new DeploymentArguments(certificateId, request),
            resources.ToArray(), "{}", idempotencyKey, ct, preparing: true);
        if (!result.Success || result.Data is null || result.Data.Code == "IDEMPOTENCY_REUSED") return result;
        var operation = await db.McpOperations.SingleAsync(row => row.Id == result.Data.Id, ct);
        if (deployments is not DeploymentService concrete) return await FailedPreparationAsync(operation, "MCP_DEPLOYMENT_UNSUPPORTED", "部署服务不支持持久 MCP 来源关联。", ct);
        var plan = await concrete.PlanForMcpAsync(certificateId, request, operation, ct);
        if (!plan.Success || plan.Data is null) return await FailedPreparationAsync(operation, plan.Code, plan.Message, ct);
        var summary = JsonSerializer.Serialize(new
        {
            certificateId, fingerprint = plan.Data.Certificate.Fingerprint, planRevision = plan.Data.PlanRevision,
            targets = plan.Data.Targets.Select(target => new { target.TargetId, target.TargetName, target.ConfigRevision,
                action = target.Plan.Action, summary = target.Plan.Summary })
        }, Json);
        var snapshot = ReadResources(operation);
        operation.ResourceJson = JsonSerializer.Serialize(snapshot with { SummaryJson = summary }, Json);
        operation.Status = operation.ApprovedAtUtc.HasValue ? "Approved" : "Prepared";
        operation.Message = operation.Status == "Prepared" ? "部署计划已生成，等待 Web 管理员批准。" : "部署计划已按客户端显式预授权策略准备。";
        operation.Code = "PREPARED"; operation.UpdatedAtUtc = DateTime.UtcNow; operation.Version++;
        await db.SaveChangesAsync(ct);
        return ApiResult<McpOperationView>.Ok(await ViewAsync(operation, ct));
    }

    private async Task<ApiResult<McpOperationView>> PrepareAsync<T>(McpCallerContext caller, string kind, string tool, T arguments,
        McpResourceScope[] resources, string summary, string idempotencyKey, CancellationToken ct, bool preparing = false, bool allDomainsRequired = false)
    {
        if (!ValidKey(idempotencyKey)) return Fail("VALIDATION", "业务幂等键必须为 1～128 个非控制字符。");
        var json = JsonSerializer.Serialize(arguments, Json);
        var digest = Digest(json);
        var permissions = await AuthorizeResourcesAsync(caller, tool, resources, false, ct);
        if (!permissions.Success || permissions.Data is null) return Fail(permissions.Code, permissions.Message);
        var existing = await db.McpOperations.AsNoTracking().SingleOrDefaultAsync(row => row.ClientId == caller.ClientId && row.IdempotencyKey == idempotencyKey, ct);
        if (existing is not null) return await ReuseAsync(existing, caller, kind, digest, ct);
        var now = DateTime.UtcNow;
        var permission = permissions.Data;
        var operation = new McpOperation
        {
            Id = ids.NewId(), ClientId = caller.ClientId, AuthorizationId = caller.AuthorizationId, EffectiveUserId = caller.EffectiveUserId,
            AuthenticationType = caller.AuthenticationType, ApiKeyId = caller.ApiKeyId,
            PreparedBy = caller.EffectiveUserId, ToolName = tool, Kind = kind, IdempotencyKey = idempotencyKey,
            ArgumentsJson = json, ArgumentsDigest = digest, ResourceJson = JsonSerializer.Serialize(new McpOperationResourceSnapshot(resources, summary, allDomainsRequired), Json),
            SourceIp = caller.SourceIp, ScopesJson = JsonSerializer.Serialize(caller.Scopes, Json), SettingsRevision = permission.SettingsRevision,
            TaskId = kind == "TaskInspection" && arguments is AuxiliaryArguments auxiliary ? auxiliary.ResourceId : "",
            ClientRevision = permission.ClientRevision, PolicyRevision = permission.PolicyRevision,
            Status = preparing ? "Preparing" : permission.Preauthorized ? "Approved" : "Prepared", ApprovalExpiresAtUtc = now.AddMinutes(10),
            ApprovedAtUtc = permission.Preauthorized ? now : null, CreatedAtUtc = now, UpdatedAtUtc = now,
            Message = permission.Preauthorized ? "已按客户端显式预授权策略准备；首次提交仍需复核授权。" : "操作已准备，等待 Web 管理员批准。", Code = "PREPARED"
        };
        db.McpOperations.Add(operation);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException)
        {
            db.Entry(operation).State = EntityState.Detached;
            var raced = await db.McpOperations.AsNoTracking().SingleOrDefaultAsync(row => row.ClientId == caller.ClientId && row.IdempotencyKey == idempotencyKey, ct);
            if (raced is null) throw;
            return await ReuseAsync(raced, caller, kind, digest, ct);
        }
        return ApiResult<McpOperationView>.Ok(await ViewAsync(operation, ct));
    }

    public async Task<ApiResult<McpOperationView>> SubmitAsync(McpCallerContext caller, string operationId, string idempotencyKey, CancellationToken ct)
    {
        var operation = await db.McpOperations.SingleOrDefaultAsync(row => row.Id == operationId, ct);
        var valid = await ValidateConsumptionAsync(operation, caller, idempotencyKey, ct);
        if (valid is not null) return valid;
        if (operation!.ConsumedAtUtc is not null) return ApiResult<McpOperationView>.Ok(await ViewAsync(operation, ct), "返回原受理操作，未再次提交。");
        if (operation.Kind == "CertificateApplication")
        {
            var request = JsonSerializer.Deserialize<CertificateApplyRequest>(operation.ArgumentsJson, Json);
            if (request is null) return Fail("MCP_SNAPSHOT_INVALID", "申请快照无法读取。");
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            operation.ConsumedAtUtc = DateTime.UtcNow; operation.UpdatedAtUtc = DateTime.UtcNow; operation.Version++;
            try
            {
                var queued = await certificates.QueueForMcpAsync(request, operation, ct);
                if (!queued.Success)
                {
                    await transaction.RollbackAsync(CancellationToken.None);
                    await db.Entry(operation).ReloadAsync(ct);
                    return Fail(queued.Code, queued.Message);
                }
                await transaction.CommitAsync(ct);
            }
            catch (DbUpdateConcurrencyException)
            {
                await transaction.RollbackAsync(CancellationToken.None);
                db.ChangeTracker.Clear();
                var accepted = await db.McpOperations.AsNoTracking().SingleAsync(row => row.Id == operationId, ct);
                return ApiResult<McpOperationView>.Ok(await ViewAsync(accepted, ct), "返回已受理的原操作。");
            }
            return ApiResult<McpOperationView>.Ok(await ViewAsync(operation, ct));
        }
        if (operation.Kind == "Deployment")
        {
            if (deployments is not DeploymentService concrete) return Fail("MCP_DEPLOYMENT_UNSUPPORTED", "部署服务不支持持久 MCP 来源关联。");
            var submitted = await concrete.SubmitForMcpAsync(operation.BatchId, new(operation.PlanRevision, "mcp-" + operation.Id), operation, ct);
            if (submitted.Success) await db.Entry(operation).ReloadAsync(ct);
            return submitted.Success ? ApiResult<McpOperationView>.Ok(await ViewAsync(operation, ct)) : Fail(submitted.Code, "操作未完成，请在 Web 查看关联部署计划或任务。");
        }
        return Fail("MCP_OPERATION_KIND_INVALID", "此操作需要由原测试或核对工具消费。");
    }

    private async Task<ApiResult<McpOperationView>?> ValidateConsumptionAsync(McpOperation? operation, McpCallerContext caller, string key, CancellationToken ct)
    {
        if (operation is null || !SameCaller(operation, caller)) return Fail("NOT_FOUND", "当前客户端没有此操作。");
        if (!ValidKey(key) || operation.IdempotencyKey != key || Digest(operation.ArgumentsJson) != operation.ArgumentsDigest)
            return Fail("IDEMPOTENCY_CONFLICT", "幂等键或不可变操作快照不一致。");
        var tool = operation.Kind switch { "CertificateApplication" => "ssl_certificate_application_submit", "Deployment" => "ssl_deployment_submit", _ => operation.ToolName };
        var permission = await AuthorizeResourcesAsync(caller, tool, ReadResources(operation).Resources, false, ct);
        if (!permission.Success || permission.Data is null) return Fail(permission.Code, permission.Message);
        if (operation.ConsumedAtUtc is not null) return null;
        if (operation.Status != "Approved") return Fail("MCP_APPROVAL_REQUIRED", "请先由 Web 管理员批准原操作；客户端确认参数不构成批准。");
        if (operation.ApprovalExpiresAtUtc is not { } expiry || expiry <= DateTime.UtcNow || !RevisionsMatch(operation, permission.Data))
            return Fail("MCP_APPROVAL_STALE", "操作批准已过期或配置/权限修订变化，请重新准备。");
        return null;
    }

    private async Task<ApiResult<McpEffectivePermission>> AuthorizeResourcesAsync(McpCallerContext caller, string tool,
        IReadOnlyList<McpResourceScope> resources, bool worker, CancellationToken ct)
    {
        if (resources.Count == 0) return ApiResult<McpEffectivePermission>.Fail("MCP_RESOURCE_REQUIRED", "操作必须包含明确资源范围。");
        McpEffectivePermission? effective = null;
        var preauthorized = true;
        foreach (var resource in resources)
        {
            var allowed = await authorization.AuthorizeAsync(caller, tool, resource, worker, ct);
            if (!allowed.Success || allowed.Data is null) return allowed;
            effective ??= allowed.Data;
            if (effective.SettingsRevision != allowed.Data.SettingsRevision || effective.ClientRevision != allowed.Data.ClientRevision || effective.PolicyRevision != allowed.Data.PolicyRevision)
                return ApiResult<McpEffectivePermission>.Fail("MCP_POLICY_CHANGED", "授权策略在核对过程中发生变化，请重试。");
            preauthorized &= allowed.Data.Preauthorized;
        }
        return ApiResult<McpEffectivePermission>.Ok(effective! with { Preauthorized = preauthorized });
    }

    private static bool ValidKey(string key) => !string.IsNullOrWhiteSpace(key) && key.Length <= 128 && !key.Any(char.IsControl);
    private static string NormalizeDomain(string? domain) => domain?.Trim().TrimEnd('.').ToLowerInvariant() ?? "";
    private static string Digest(string value) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    private static bool SameCaller(McpOperation operation, McpCallerContext caller) => operation.ClientId == caller.ClientId
        && operation.EffectiveUserId == caller.EffectiveUserId && operation.AuthorizationId == caller.AuthorizationId
        && operation.AuthenticationType == caller.AuthenticationType && operation.ApiKeyId == caller.ApiKeyId;
    private static bool RevisionsMatch(McpOperation operation, McpEffectivePermission permission) => operation.SettingsRevision == permission.SettingsRevision && operation.ClientRevision == permission.ClientRevision && operation.PolicyRevision == permission.PolicyRevision;
    private static McpCallerContext Caller(McpOperation operation) => new(operation.ClientId, operation.EffectiveUserId, operation.AuthorizationId,
        JsonSerializer.Deserialize<string[]>(operation.ScopesJson, Json) ?? [], operation.SourceIp,
        AuthenticationType: operation.AuthenticationType, ApiKeyId: operation.ApiKeyId);
    private static McpOperationResourceSnapshot ReadResources(McpOperation operation) => JsonSerializer.Deserialize<McpOperationResourceSnapshot>(operation.ResourceJson, Json) ?? new([]);
    private static ApiResult<McpOperationView> Fail(string code, string message) => ApiResult<McpOperationView>.Fail(code, message);

    private async Task<ApiResult<McpOperationView>> ReuseAsync(McpOperation operation, McpCallerContext caller, string kind, string digest, CancellationToken ct)
    {
        if (!SameCaller(operation, caller) || operation.Kind != kind || operation.ArgumentsDigest != digest || Digest(operation.ArgumentsJson) != digest)
            return Fail("IDEMPOTENCY_CONFLICT", "此客户端幂等键已绑定其他身份或参数。");
        return new(true, "IDEMPOTENCY_REUSED", "返回原操作，没有重新创建。", (await ViewAsync(operation, ct)) with { Code = "IDEMPOTENCY_REUSED" });
    }

    private async Task<ApiResult<McpOperationView>> FailedPreparationAsync(McpOperation operation, string code, string message, CancellationToken ct)
    {
        operation.Status = "Failed"; operation.Code = code; operation.Message = "操作准备或核对未完成，请在 Web 查看关联任务或目标。";
        operation.UpdatedAtUtc = DateTime.UtcNow; operation.Version++;
        await db.SaveChangesAsync(ct);
        return new(false, code, "操作准备或核对未完成，请在 Web 查看关联任务或目标。", await ViewAsync(operation, ct));
    }
}
