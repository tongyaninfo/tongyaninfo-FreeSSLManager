using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Data;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Mcp;

/// <summary>管理配置采用乐观并发，API Key 可独立运行，OAuth 只在配置材料后提供。</summary>
public sealed class McpConfigurationService(AppDbContext db, McpRuntimeOptions runtime, IIdGenerator ids) : IMcpConfigurationService
{
    public async Task<ApiResult<McpSettingsView>> GetAsync(CancellationToken ct) =>
        ApiResult<McpSettingsView>.Ok(View(await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(ct) ?? new()));
    public async Task<ApiResult<McpSettingsView>> SaveAsync(McpSettingsInput input, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(input.SystemName) || input.SystemName.Trim().Length > 100 || input.SystemName.Any(char.IsControl))
            return ApiResult<McpSettingsView>.Fail("VALIDATION", "请输入 1 至 100 字且不包含控制字符的系统名称。");
        if (input.Mode is not ("ReadOnly" or "ControlledWrite") || input.RateLimitPerMinute is < 1 or > 600
            || input.MaxConcurrentCalls is < 1 or > 32 || input.LogRetentionDays is < 1 or > 365)
            return ApiResult<McpSettingsView>.Fail("VALIDATION", "模式、限流、并发或日志期限超出允许范围。");
        if (input.AllowedCidrs is null || input.AllowedOrigins is null || input.AllowedTools is null
            || input.AllowedCidrs.Length > 100 || input.AllowedOrigins.Length > 50 || input.AllowedTools.Length > 100
            || input.AllowedCidrs.Any(value => !McpNetwork.ValidCidr(value)) || input.AllowedOrigins.Any(value => !McpNetwork.ValidOrigin(value))
            || input.AllowedTools.Any(value => !McpToolCatalog.All.Any(tool => tool.Name == value)))
            return ApiResult<McpSettingsView>.Fail("VALIDATION", "请输入有效且数量有界的 CIDR、Origin 和工具白名单。");
        var address = input.PublicBaseUrl?.Trim().TrimEnd('/') ?? "";
        if (address.Length > 0 && !McpNetwork.ValidBaseUrl(address))
            return ApiResult<McpSettingsView>.Fail("VALIDATION", "服务基址须为不含路径、查询和账号密码的HTTP/HTTPS origin；HTTP仅允许内网IP、回环、IPv6 ULA或管理员配置的DNS主机名。");
        if (address.Length > 0) address = McpNetwork.NormalizeOrigin(address);
        if (input.Enabled && (!runtime.Supported || address.Length == 0 || input.AllowedCidrs.Length == 0))
            return ApiResult<McpSettingsView>.Fail("MCP_NOT_READY", "请先配置HTTP/HTTPS服务基址和来源白名单；HTTP仅支持经核验内网API Key，桌面模式不支持外部 MCP。");
        var row = await db.McpSettings.SingleOrDefaultAsync(ct);
        if (row is not null && input.ConfigRevision != row.ConfigRevision)
            return ApiResult<McpSettingsView>.Fail("CONFLICT", "MCP 配置已变化，请刷新后重试。");
        if (row is null) { row = new(); db.McpSettings.Add(row); }
        else row.ConfigRevision++;
        row.Enabled = input.Enabled; row.PublicBaseUrl = address; row.Mode = input.Mode;
        row.SystemName = input.SystemName.Trim();
        if (row.InstanceId.Length == 0) row.InstanceId = ids.NewId();
        row.AllowedCidrsJson = JsonSerializer.Serialize(input.AllowedCidrs.Distinct());
        row.AllowedOriginsJson = JsonSerializer.Serialize(input.AllowedOrigins.Select(McpNetwork.NormalizeOrigin).Distinct());
        row.AllowedToolsJson = JsonSerializer.Serialize(input.AllowedTools.Distinct());
        row.RateLimitPerMinute = input.RateLimitPerMinute; row.MaxConcurrentCalls = input.MaxConcurrentCalls;
        row.LogRetentionDays = input.LogRetentionDays; row.UpdatedAtUtc = DateTime.UtcNow;
        try { await db.SaveChangesAsync(ct); return ApiResult<McpSettingsView>.Ok(View(row)); }
        catch (DbUpdateException) { db.ChangeTracker.Clear(); return ApiResult<McpSettingsView>.Fail("CONFLICT", "配置已被其他请求修改，请刷新。"); }
    }
    public async Task<ApiResult<McpStatusView>> StatusAsync(CancellationToken ct)
    {
        var row = await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(ct) ?? new();
        var available = await db.McpClients.AsNoTracking().AnyAsync(x => x.Enabled && (x.ExpiresAtUtc == null || x.ExpiresAtUtc > DateTime.UtcNow), ct);
        var state = !runtime.Supported ? "Unsupported" : !row.Enabled ? "Disabled" : !available ? "NoAuthorizedClients" : "Ready";
        return ApiResult<McpStatusView>.Ok(new(runtime.Supported, row.Enabled, runtime.OAuthReady, state,
            !runtime.Supported ? runtime.Message : runtime.OAuthReady ? "API Key可经HTTPS或核验内网HTTP使用；OAuth只在启动HTTPS issuer入口可用，实际调用仍检查授权和白名单。"
                : "API Key可经HTTPS或核验内网HTTP使用；OAuth尚未配置，需要时配置HTTPS issuer及签名材料并重启。",
            row.PublicBaseUrl.Length == 0 ? "" : row.PublicBaseUrl + "/mcp", ["2026-07-28", "2025-11-25"], "2.3.0", runtime.ApiKeyReady,
            row.SystemName, row.InstanceId));
    }
    internal static McpSettingsView View(McpSettings row) => new(row.Enabled, row.PublicBaseUrl, row.Mode,
        Strings(row.AllowedCidrsJson), Strings(row.AllowedOriginsJson), Strings(row.AllowedToolsJson), row.RateLimitPerMinute,
        row.MaxConcurrentCalls, row.LogRetentionDays, row.ConfigRevision, row.UpdatedAtUtc == default ? null : row.UpdatedAtUtc,
        row.SystemName, row.InstanceId);
    internal static string[] Strings(string json)
    { try { return JsonSerializer.Deserialize<string[]>(json) ?? []; } catch (JsonException) { return []; } }
}
