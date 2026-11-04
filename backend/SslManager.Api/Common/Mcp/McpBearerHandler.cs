using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Validation.AspNetCore;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Data;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Api.Common.Mcp;

/// <summary>接受预分配 API Key 或标准 OAuth Bearer，不接受 Cookie、查询凭据或冲突的双重凭据。</summary>
public sealed class McpBearerHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger,
    UrlEncoder encoder, McpRuntimeOptions runtime, AppDbContext db, McpRequestLimiter limiter,
    IMcpApiKeyService apiKeys) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var authorization = Request.Headers.Authorization;
        var apiKeyHeader = Request.Headers["X-API-Key"];
        if (authorization.Count > 1 || apiKeyHeader.Count > 1 || authorization.Count > 0 && apiKeyHeader.Count > 0)
            return AuthenticateResult.Fail("不能同时提供多份调用凭据。");
        var value = authorization.ToString();
        var secret = apiKeyHeader.ToString();
        if (secret.Length == 0)
        {
            if (!value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            { if (!Request.IsHttps) Context.Items["McpHttpApiKeyRequired"] = true; return AuthenticateResult.NoResult(); }
            secret = value[7..];
        }
        if (secret.Length == 0 || secret.Length > 4096 || secret.Any(char.IsWhiteSpace) || secret.Contains(','))
            return AuthenticateResult.Fail("调用凭据格式无效。");
        ClaimsPrincipal principal;
        McpApiKey? apiKey = null;
        if (apiKeyHeader.Count > 0 || secret.StartsWith("sslm_", StringComparison.Ordinal))
        {
            if (!runtime.ApiKeyReady || (apiKey = await apiKeys.ValidateAsync(secret, Context.RequestAborted)) is null)
                return AuthenticateResult.Fail("API Key 无效、已过期或撤销。");
            var keyClient = await db.McpClients.AsNoTracking().SingleOrDefaultAsync(x => x.ClientId == apiKey.ClientId, Context.RequestAborted);
            if (keyClient is null) return AuthenticateResult.Fail("客户端不存在。");
            var keyIdentity = new ClaimsIdentity(Scheme.Name, OpenIddictConstants.Claims.Name, OpenIddictConstants.Claims.Role);
            keyIdentity.AddClaim(new("mcp_client", keyClient.ClientId));
            keyIdentity.AddClaim(new(OpenIddictConstants.Claims.Subject, keyClient.BoundUserId));
            keyIdentity.AddClaim(new("mcp_authentication_type", "ApiKey"));
            keyIdentity.AddClaim(new("mcp_api_key_id", apiKey.Id));
            principal = new ClaimsPrincipal(keyIdentity);
            principal.SetScopes(McpConfigurationService.Strings(keyClient.ScopesJson));
        }
        else
        {
            // 内网明文只接受预分配API Key，合法OAuth令牌也不能通过HTTP使用。
            if (!Request.IsHttps) { Context.Items["McpHttpApiKeyRequired"] = true; return AuthenticateResult.Fail("HTTP MCP 仅接受 API Key。"); }
            if (!runtime.OAuthReady) return AuthenticateResult.Fail("OAuth 尚未就绪。");
            if (McpNetwork.ValidHttpsOrigin(runtime.Issuer) && !McpNetwork.MatchesExactAddress(Request, runtime.Issuer))
                return AuthenticateResult.Fail("OAuth令牌仅允许在配置的HTTPS issuer入口使用。");
            var result = await Context.AuthenticateAsync(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
            if (!result.Succeeded || result.Principal is null) return AuthenticateResult.Fail("MCP Bearer 无效或已撤销。");
            principal = result.Principal;
        }
        var clientId = principal.GetClaim("mcp_client");
        var userId = principal.GetClaim(OpenIddictConstants.Claims.Subject);
        var client = await db.McpClients.AsNoTracking().SingleOrDefaultAsync(x => x.ClientId == clientId, Context.RequestAborted);
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == userId, Context.RequestAborted);
        if (client is null || !client.Enabled || client.ExpiresAtUtc <= DateTime.UtcNow || user is null || !user.Enabled || client.BoundUserId != user.Id)
            return AuthenticateResult.Fail("客户端或绑定用户已失效。");
        var settings = await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(Context.RequestAborted);
        if (settings is null || !settings.Enabled) return AuthenticateResult.Fail("MCP 已停用。");
        var lease = limiter.TryEnter("client:" + client.ClientId, settings.RateLimitPerMinute, settings.MaxConcurrentCalls);
        if (lease is null) { Context.Items["McpRateLimited"] = true; return AuthenticateResult.Fail("MCP 客户端限流。"); }
        Context.Response.RegisterForDispose(lease);
        await db.McpClients.Where(x => x.Id == client.Id).ExecuteUpdateAsync(update => update.SetProperty(x => x.LastUsedAtUtc, DateTime.UtcNow), Context.RequestAborted);
        if (apiKey is not null)
            await db.McpApiKeys.Where(x => x.Id == apiKey.Id && x.Enabled && x.RevokedAtUtc == null)
                .ExecuteUpdateAsync(update => update.SetProperty(x => x.LastUsedAtUtc, DateTime.UtcNow), Context.RequestAborted);
        var identity = new ClaimsIdentity(principal.Claims, Scheme.Name, OpenIddictConstants.Claims.Name, OpenIddictConstants.Claims.Role);
        // API Key 的角色取自当前绑定用户，不能由调用方声明；OAuth 执行授权仍逐次核对数据库。
        if (apiKey is not null) identity.AddClaim(new(OpenIddictConstants.Claims.Role, user.Role));
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name));
    }
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = Context.Items.ContainsKey("McpRateLimited") ? StatusCodes.Status429TooManyRequests : StatusCodes.Status401Unauthorized;
        if (Response.StatusCode == 429) Response.Headers.RetryAfter = "60";
        var issuer = runtime.Issuer;
        Response.Headers.WWWAuthenticate = !Request.IsHttps || !runtime.OAuthReady || issuer.Length == 0 ? "Bearer realm=\"MCP API Key\""
            : "Bearer resource_metadata=\"" + issuer + "/.well-known/oauth-protected-resource/mcp\"";
        return Task.CompletedTask;
    }
    public static McpCallerContext Caller(HttpContext context) => new(
        context.User.GetClaim("mcp_client") ?? context.User.GetPresenters().FirstOrDefault() ?? "",
        context.User.GetClaim(OpenIddictConstants.Claims.Subject) ?? "", context.User.GetAuthorizationId() ?? "",
        context.User.GetScopes().ToArray(), context.Connection.RemoteIpAddress?.ToString() ?? "",
        context.User.GetClaim(OpenIddictConstants.Claims.Role) ?? "", context.TraceIdentifier,
        context.Items.TryGetValue("McpActualRemoteIp", out var peer) ? peer?.ToString() ?? "" : context.Connection.RemoteIpAddress?.ToString() ?? "",
        context.User.GetClaim("mcp_authentication_type") ?? "OAuth", context.User.GetClaim("mcp_api_key_id") ?? "");
}
