using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Data;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Mcp;

/// <summary>每次从拥有者数据源核验身份和授权，规则仅缩小权限，不以目录缓存替代执行检查。</summary>
public sealed class McpAuthorizationService(AppDbContext db, McpRuntimeOptions runtime) : IMcpAuthorizationService
{
    public async Task<ApiResult<McpEffectivePermission>> AuthorizeAsync(McpCallerContext caller, string toolName,
        McpResourceScope? resource, bool worker, CancellationToken ct)
    {
        var settings = await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(ct);
        if (!runtime.Supported || settings is null || !settings.Enabled)
            return Denied("MCP_DISABLED", "MCP 当前未启用或认证能力未就绪。");
        var descriptor = McpToolCatalog.All.FirstOrDefault(x => x.Name == toolName);
        if (descriptor is null) return Denied("TOOL_NOT_FOUND", "工具不存在。");
        var now = DateTime.UtcNow;
        var client = await db.McpClients.AsNoTracking().SingleOrDefaultAsync(x => x.ClientId == caller.ClientId, ct);
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == caller.EffectiveUserId, ct);
        if (client is null || !client.Enabled || client.ExpiresAtUtc <= now || user is null || !user.Enabled || client.BoundUserId != user.Id)
            return Denied("FORBIDDEN", "客户端或绑定用户无效。");
        if (McpToolCatalog.RequiresAdmin(toolName) && user.Role != "admin" || !descriptor.ReadOnly && user.Role != "admin")
            return Denied("FORBIDDEN", "当前用户角色不能使用该工具。");
        if (caller.AuthenticationType == "ApiKey")
        {
            if (!runtime.ApiKeyReady || caller.ApiKeyId.Length == 0 || caller.AuthorizationId.Length != 0
                || !await db.McpApiKeys.AsNoTracking().AnyAsync(x => x.Id == caller.ApiKeyId && x.ClientId == client.ClientId
                    && x.Enabled && x.RevokedAtUtc == null && (x.ExpiresAtUtc == null || x.ExpiresAtUtc > now), ct))
                return Denied("API_KEY_REVOKED", "API Key 已过期、停用或撤销。");
        }
        else if (caller.AuthenticationType != "OAuth" || !runtime.OAuthReady || caller.ApiKeyId.Length != 0
            || string.IsNullOrEmpty(caller.AuthorizationId) || !await db.Set<McpOAuthAuthorization>().AsNoTracking()
                .AnyAsync(x => x.Id == caller.AuthorizationId && x.Status == OpenIddictConstants.Statuses.Valid
                    && x.Subject == user.Id && x.Application != null && x.Application.Id == client.OAuthApplicationId, ct))
            return Denied("AUTHORIZATION_REVOKED", "OAuth 授权已失效或撤销。");
        var configuredScopes = McpConfigurationService.Strings(client.ScopesJson);
        if (descriptor.Scopes.Any(scope => !caller.Scopes.Contains(scope) || !configuredScopes.Contains(scope)))
            return Denied("INSUFFICIENT_SCOPE", "授权 scope 不足。");
        if (!descriptor.ReadOnly && settings.Mode != "ControlledWrite") return Denied("READ_ONLY", "当前只允许查询工具。");
        if (!McpConfigurationService.Strings(settings.AllowedToolsJson).Contains(toolName)
            || !McpNetwork.Contains(McpConfigurationService.Strings(settings.AllowedCidrsJson), caller.SourceIp))
            return Denied("FORBIDDEN", "工具或来源不在全局白名单中。");
        var rows = await db.McpAllowRules.AsNoTracking().Where(x => x.ClientId == client.ClientId && x.Enabled
            && (x.ExpiresAtUtc == null || x.ExpiresAtUtc > now)).ToListAsync(ct);
        var rules = rows.Select(McpClientService.Rule).Where(rule => rule.ToolNames.Contains(toolName)
            && descriptor.Scopes.All(scope => rule.Scopes.Contains(scope)) && McpNetwork.Contains(rule.AllowedCidrs, caller.SourceIp))
            .Where(rule => resource is null || Matches(rule, resource)).ToArray();
        if (rules.Length == 0) return Denied("FORBIDDEN", "没有完整匹配该工具、来源及业务资源的授权规则。");
        return ApiResult<McpEffectivePermission>.Ok(new(settings.ConfigRevision, client.ConfigRevision, client.ConfigRevision,
            rules, rules.Any(rule => rule.ApprovalMode == "Preauthorized")));
    }
    private static bool Matches(McpAllowRuleInput rule, McpResourceScope resource) =>
        (resource.AccountId.Length == 0 || rule.AllAccounts || rule.AccountIds.Contains(resource.AccountId))
        && (resource.Domain.Length == 0 || rule.AllDomains || rule.Domains.Any(domain => McpNetwork.DomainMatches(domain, resource.Domain)))
        && (resource.TargetId.Length == 0 || rule.AllTargets || rule.TargetIds.Contains(resource.TargetId));
    private static ApiResult<McpEffectivePermission> Denied(string code, string message) => ApiResult<McpEffectivePermission>.Fail(code, message);
}
