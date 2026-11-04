using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using SslManager.Api.Data;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Service.impl.Mcp;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace SslManager.Api.Controllers;

/// <summary>标准 OAuth 授权码/PKCE 与机器流程；实际登录用户必须等于客户端绑定用户。</summary>
public sealed class McpOAuthController(AppDbContext db, IOpenIddictAuthorizationManager authorizations,
    IAntiforgery antiforgery, McpRuntimeOptions runtime) : Controller
{
    private const string Scheme = OpenIddictServerAspNetCoreDefaults.AuthenticationScheme;

    [HttpGet("/oauth/mcp/authorize")]
    public async Task<IActionResult> Authorize(CancellationToken ct)
    {
        var request = HttpContext.GetOpenIddictServerRequest()!;
        var login = await HttpContext.AuthenticateAsync("Cookies");
        if (!login.Succeeded)
            return Redirect("/user/login?redirect=" + Uri.EscapeDataString(Request.Path + Request.QueryString));
        var userId = login.Principal!.FindFirstValue(ClaimTypes.NameIdentifier);
        var checkedClient = await ClientAsync(request, userId, ct);
        if (checkedClient is null) return Error(Errors.AccessDenied, "客户端、绑定用户、资源或 scope 无效。");
        var token = antiforgery.GetAndStoreTokens(HttpContext).RequestToken!;
        var encode = HtmlEncoder.Default;
        var action = encode.Encode(Request.Path + Request.QueryString);
        var name = encode.Encode(checkedClient.Name);
        var scopes = encode.Encode(string.Join("、", request.GetScopes()));
        // OAuth POST 由框架从表单提取参数；只复制已知授权参数，避免依赖 GET 查询或回显任何客户端秘密。
        var hidden = string.Concat(new[] { "client_id", "response_type", "redirect_uri", "scope", "resource", "state", "code_challenge", "code_challenge_method", "nonce" }
            .SelectMany(key => Request.Query[key].Select(value => $"<input type=\"hidden\" name=\"{key}\" value=\"{encode.Encode(value ?? "")}\">")));
        Response.Headers.CacheControl = "no-store";
        Response.Headers.ContentSecurityPolicy = "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'";
        return Content($"<!doctype html><html lang=\"zh-CN\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>MCP 授权确认</title>" +
            $"<body><main><h1>授权 {name} 访问 MCP</h1><p>申请权限：{scopes}</p><p>实际操作仍受工具和业务资源白名单限制。</p>" +
            $"<form method=\"post\" action=\"{action}\">{hidden}<input type=\"hidden\" name=\"__RequestVerificationToken\" value=\"{encode.Encode(token)}\">" +
            "<button name=\"decision\" value=\"allow\">同意授权</button><button name=\"decision\" value=\"deny\">拒绝</button></form></main></body></html>", "text/html; charset=utf-8");
    }

    [HttpPost("/oauth/mcp/authorize")]
    public async Task<IActionResult> Accept(CancellationToken ct)
    {
        // 本项目仅注册 API Controllers；直接使用既有 antiforgery 服务，不依赖 MVC Views 的过滤器。
        if (!await antiforgery.IsRequestValidAsync(HttpContext))
            return BadRequest(SslManager.Api.Common.ApiResult<bool>.Fail("CSRF_INVALID", "授权确认的请求验证已失效，请重新打开授权页面。"));
        var request = HttpContext.GetOpenIddictServerRequest()!;
        var login = await HttpContext.AuthenticateAsync("Cookies");
        if (!login.Succeeded) return Error(Errors.LoginRequired, "请重新登录。");
        var client = await ClientAsync(request, login.Principal!.FindFirstValue(ClaimTypes.NameIdentifier), ct);
        if (client is null) return Error(Errors.AccessDenied, "客户端、绑定用户、资源或 scope 无效。");
        if (Request.Form["decision"] != "allow") return Error(Errors.AccessDenied, "用户拒绝授权。");
        return SignIn(await PrincipalAsync(client, request.GetScopes().ToArray(), ct), Scheme);
    }

    [HttpPost("/oauth/mcp/token")]
    public async Task<IActionResult> Token(CancellationToken ct)
    {
        var request = HttpContext.GetOpenIddictServerRequest()!;
        if (request.IsClientCredentialsGrantType())
        {
            var client = await ClientAsync(request, null, ct);
            if (client is null || client.GrantType != "client_credentials") return Error(Errors.InvalidGrant, "客户端授权已失效。");
            return SignIn(await PrincipalAsync(client, request.GetScopes().ToArray(), ct), Scheme);
        }
        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            return Error(Errors.UnsupportedGrantType, "不支持该授权方式。");
        var authenticated = await HttpContext.AuthenticateAsync(Scheme);
        var principal = authenticated.Principal;
        if (principal is null) return Error(Errors.InvalidGrant, "授权码或刷新令牌已失效。");
        var current = await ClientAsync(request, principal.GetClaim(Claims.Subject), ct, principal);
        if (current is null) return Error(Errors.InvalidGrant, "原用户、客户端、scope 或资源已变化。");
        if (!await db.Set<McpOAuthAuthorization>().AsNoTracking().AnyAsync(x => x.Id == principal.GetAuthorizationId()
            && x.Status == Statuses.Valid && x.Subject == current.BoundUserId, ct)) return Error(Errors.InvalidGrant, "授权已撤销。");
        // refresh 请求只能缩小原 scope，不能借客户端较宽的新配置扩权。
        if (request.GetScopes().Any(scope => !principal.HasScope(scope))) return Error(Errors.InvalidScope, "不能扩大原授权 scope。");
        if (request.GetScopes().Length > 0) principal.SetScopes(request.GetScopes());
        return SignIn(principal, Scheme);
    }

    private async Task<McpClient?> ClientAsync(OpenIddictRequest request, string? userId, CancellationToken ct, ClaimsPrincipal? original = null)
    {
        var settings = await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(ct);
        var client = await db.McpClients.AsNoTracking().SingleOrDefaultAsync(x => x.ClientId == request.ClientId, ct);
        if (settings is null || !settings.Enabled || client is null || !client.Enabled || client.ExpiresAtUtc <= DateTime.UtcNow
            || userId is not null && userId != client.BoundUserId) return null;
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == client.BoundUserId && x.Enabled, ct);
        if (user is null) return null;
        var scopes = original?.GetScopes() ?? request.GetScopes();
        var configured = McpConfigurationService.Strings(client.ScopesJson);
        if (scopes.Any(scope => scope != Scopes.OfflineAccess && !configured.Contains(scope))
            || scopes.Contains("mcp.write") && user.Role != "admin") return null;
        var resources = request.GetResources();
        var oauthAddress = runtime.OAuthBaseUrl(settings.PublicBaseUrl);
        if (oauthAddress.Length == 0) return null;
        var expected = oauthAddress + "/mcp";
        if (original is null && (resources.Length != 1 || resources[0] != expected)) return null;
        if (original is not null && (!original.GetResources().SequenceEqual(new[] { expected })
            || resources.Length > 0 && !resources.SequenceEqual(new[] { expected }))) return null;
        return client;
    }

    private async Task<ClaimsPrincipal> PrincipalAsync(McpClient client, string[] scopes, CancellationToken ct)
    {
        var user = await db.Users.AsNoTracking().SingleAsync(x => x.Id == client.BoundUserId && x.Enabled, ct);
        var settings = await db.McpSettings.AsNoTracking().SingleAsync(ct);
        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType, Claims.Name, Claims.Role);
        identity.SetClaim(Claims.Subject, user.Id).SetClaim(Claims.Name, user.Username).SetClaim(Claims.Role, user.Role)
            .SetClaim("mcp_client", client.ClientId);
        var principal = new ClaimsPrincipal(identity);
        principal.SetScopes(scopes); principal.SetResources(runtime.OAuthBaseUrl(settings.PublicBaseUrl) + "/mcp"); principal.SetPresenters(client.ClientId);
        var descriptor = new OpenIddictAuthorizationDescriptor { ApplicationId = client.OAuthApplicationId, Subject = user.Id,
            Status = Statuses.Valid, Type = AuthorizationTypes.Permanent, CreationDate = DateTimeOffset.UtcNow, Principal = principal };
        descriptor.Scopes.UnionWith(scopes);
        var authorization = await authorizations.CreateAsync(descriptor, ct);
        principal.SetAuthorizationId(await authorizations.GetIdAsync(authorization, ct));
        foreach (var claim in principal.Claims) claim.SetDestinations(Destinations.AccessToken);
        return principal;
    }
    private ForbidResult Error(string error, string description) => Forbid(new AuthenticationProperties(new Dictionary<string, string?>
    {
        [OpenIddictServerAspNetCoreConstants.Properties.Error] = error,
        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
    }), Scheme);
}
