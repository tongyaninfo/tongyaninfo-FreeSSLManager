using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Mcp;

/// <summary>固定工具适配层：先实时授权和 schema 校验，再调用共享查询或持久化操作服务。</summary>
public sealed partial class McpToolDispatcher(AppDbContext db, IMcpAuthorizationService authorization,
    DomainManagementService domains, IDeploymentExecutorResolver executors, IMcpOperationService operations,
    CertificateManagementService? certificateService = null) : IMcpToolDispatcher
{
    public IReadOnlyList<McpToolDescriptor> Catalog => McpToolCatalog.All;

    public async Task<IReadOnlyList<McpToolDescriptor>> ListAsync(McpCallerContext caller, CancellationToken ct)
    {
        var available = new List<McpToolDescriptor>();
        var identity = McpInstanceIdentity.From(await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(ct));
        foreach (var tool in Catalog)
            if ((await authorization.AuthorizeAsync(caller, tool.Name, null, false, ct)).Success)
                available.Add(tool with { Title = $"[{identity.SystemName}] {tool.Title}",
                    Description = $"当前系统：{identity.SystemName}；systemInstanceId：{identity.InstanceId}；MCP：{identity.McpUrl}。 {tool.Description}" });
        return available;
    }

    public async Task<ApiResult<object>> CallAsync(McpCallerContext caller, string toolName, JsonElement arguments, CancellationToken ct)
    {
        var descriptor = Catalog.SingleOrDefault(tool => tool.Name == toolName);
        if (descriptor is null) return Fail("TOOL_NOT_FOUND", "工具不存在或未授权。");
        var allowed = await authorization.AuthorizeAsync(caller, toolName, null, false, ct);
        if (!allowed.Success || allowed.Data is null) return Fail(allowed.Code, allowed.Message);
        if (!McpArgumentValidator.Validate(arguments, descriptor.InputSchema, out var error)) return Fail("INVALID_ARGUMENTS", error);
        if (!descriptor.ReadOnly)
        {
            var identity = McpInstanceIdentity.From(await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(ct));
            if (identity.InstanceId.Length == 0 || Text(arguments, "systemInstanceId") != identity.InstanceId)
                return Fail("INSTANCE_MISMATCH", "目标系统实例不匹配；请先查询当前连接的 ssl_system_status_get，核对系统名称后携带正确的 systemInstanceId。");
        }
        var permission = allowed.Data;
        // 参数只能来自固定 schema，禁止客户端额外传入调用用户、凭据、路径或命令。
        return toolName switch
        {
            "ssl_accounts_list" => await AccountsAsync(permission, arguments, ct),
            "ssl_domains_list" => await DomainsAsync(permission, arguments, ct),
            "ssl_dns_records_list" => await DnsRecordsAsync(caller, permission, arguments, ct),
            "ssl_certificates_list" => await CertificatesAsync(permission, arguments, ct),
            "ssl_certificates_get" => await CertificateAsync(permission, Text(arguments, "certificateId"), ct),
            "ssl_certificates_validations_get" => await CertificateValidationsAsync(caller, Text(arguments, "certificateId"), ct),
            "ssl_deployment_executors_list" => ApiResult<object>.Ok(executors.List()),
            "ssl_deployment_targets_list" => await TargetsAsync(permission, arguments, ct),
            "ssl_deployments_list" => await BatchesAsync(permission, arguments, ct),
            "ssl_deployments_get" => await BatchAsync(permission, Text(arguments, "batchId"), ct),
            "ssl_deployment_tasks_get" => await TaskAsync(permission, Text(arguments, "taskId"), ct),
            "ssl_schedules_list" => await SchedulesAsync(permission, arguments, ct),
            "ssl_schedules_get" => await ScheduleAsync(permission, Text(arguments, "scheduleId"), ct),
            "ssl_schedule_runs_list" => await ScheduleRunsAsync(permission, arguments, ct),
            "ssl_expiry_alerts_list" => await AlertsAsync(permission, arguments, ct),
            "ssl_operations_get" => Box(await operations.GetAsync(caller, Text(arguments, "operationId"), ct)),
            "ssl_system_status_get" => await SystemStatusAsync(caller, ct),
            "ssl_certificate_application_prepare" => await PrepareApplicationAsync(caller, arguments, ct),
            "ssl_certificate_application_submit" => await SubmitAsync(caller, arguments, "CertificateApplication", ct),
            "ssl_deployment_plan" => Box(await operations.PrepareDeploymentAsync(caller, Text(arguments, "certificateId"),
                new(arguments.GetProperty("targetIds").EnumerateArray().Select(id => new DeploymentSelection(id.GetString()!)).ToArray()), Text(arguments, "idempotencyKey"), ct)),
            "ssl_deployment_submit" => await SubmitAsync(caller, arguments, "Deployment", ct),
            "ssl_deployment_targets_test" => Box(await operations.InvokeTargetTestAsync(caller, Text(arguments, "targetId"), Text(arguments, "idempotencyKey"), Optional(arguments, "operationId"), ct)),
            "ssl_deployment_tasks_inspect" => Box(await operations.InvokeInspectionAsync(caller, Text(arguments, "taskId"), Text(arguments, "idempotencyKey"), Optional(arguments, "operationId"), ct)),
            "ssl_dns_records_create" or "ssl_dns_records_update" or "ssl_dns_records_delete" or "ssl_dns_records_status"
                or "ssl_certificates_revoke" or "ssl_certificates_cancel" or "ssl_certificates_delete" or "ssl_certificates_cleanup_retry"
                or "ssl_domains_sync" or "ssl_certificates_sync" => Box(await operations.InvokeBusinessAsync(caller, toolName, arguments,
                    Text(arguments, "idempotencyKey"), Optional(arguments, "operationId"), ct)),
            _ when !descriptor.ReadOnly => Box(await operations.InvokeBusinessAsync(caller, toolName, arguments,
                Text(arguments, "idempotencyKey"), Optional(arguments, "operationId"), ct)),
            _ => Fail("TOOL_NOT_FOUND", "工具不存在或未授权。")
        };
    }

    private async Task<ApiResult<object>> SystemStatusAsync(McpCallerContext caller, CancellationToken ct)
    {
        var identity = McpInstanceIdentity.From(await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(ct));
        return ApiResult<object>.Ok(new { service = "Free SSL Manager", systemName = identity.SystemName,
            instanceId = identity.InstanceId, systemInstanceId = identity.InstanceId, mcpUrl = identity.McpUrl,
            version = ApplicationVersion.Current, protocolVersions = new[] { "2026-07-28", "2025-11-25" },
            availableTools = (await ListAsync(caller, ct)).Count });
    }

    private async Task<ApiResult<object>> PrepareApplicationAsync(McpCallerContext caller, JsonElement arguments, CancellationToken ct)
    {
        var accountId = Text(arguments, "accountId");
        // ACME 没有云平台原生 DNS 模式；有显式托管域时默认系统 DNS，否则默认手动 DNS-01。
        var provider = await db.CloudAccounts.AsNoTracking().Where(x => x.Id == accountId).Select(x => x.Provider).SingleOrDefaultAsync(ct);
        var fallback = provider == "Acme" ? string.IsNullOrWhiteSpace(Optional(arguments, "dnsZoneId")) ? "ManualDns" : "ManagedDns" : "NativeAutoDns";
        return Box(await operations.PrepareApplicationAsync(caller,
            new(accountId, Text(arguments, "domain"), Text(arguments, "alias"), Text(arguments, "validationMode", fallback),
                Flag(arguments, "autoCleanup", true), Optional(arguments, "dnsZoneId"), Optional(arguments, "instanceId"),
                Text(arguments, "apiVersion", "V2")), Text(arguments, "idempotencyKey"), ct));
    }

    private async Task<ApiResult<object>> SubmitAsync(McpCallerContext caller, JsonElement input, string kind, CancellationToken ct)
    {
        var existing = await operations.GetAsync(caller, Text(input, "operationId"), ct);
        if (!existing.Success || existing.Data is null) return Fail(existing.Code, existing.Message);
        // 同一提交接口不能消费另一类已经批准的操作，避免跨工具权限借用。
        if (existing.Data.Kind != kind) return Fail("OPERATION_KIND_MISMATCH", "操作类型与提交工具不一致。");
        return Box(await operations.SubmitAsync(caller, existing.Data.Id, Text(input, "idempotencyKey"), ct));
    }

    private static string Text(JsonElement input, string key, string fallback = "") => input.TryGetProperty(key, out var value) ? value.GetString() ?? fallback : fallback;
    private static string? Optional(JsonElement input, string key) => input.TryGetProperty(key, out var value) ? value.GetString() : null;
    private static int Number(JsonElement input, string key, int fallback) => input.TryGetProperty(key, out var value) ? value.GetInt32() : fallback;
    private static bool Flag(JsonElement input, string key, bool fallback) => input.TryGetProperty(key, out var value) ? value.GetBoolean() : fallback;
    private static ApiResult<object> Fail(string code, string message) => ApiResult<object>.Fail(code, message);
    private static ApiResult<object> Box<T>(ApiResult<T> result) => new(result.Success, result.Code, result.Message, result.Data);
    private static ApiResult<object> Missing() => Fail("NOT_FOUND", "资源不存在或不在允许范围内。");

    private static async Task<ApiResult<object>> PageAsync<T>(IQueryable<T> query, JsonElement input, CancellationToken ct)
    {
        var page = Number(input, "page", 1); var size = Number(input, "pageSize", 20);
        var total = await query.CountAsync(ct);
        var rows = await query.Skip((page - 1) * size).Take(size).ToListAsync(ct);
        return ApiResult<object>.Ok(new PageResult<T>(rows, total, page, size));
    }
}
