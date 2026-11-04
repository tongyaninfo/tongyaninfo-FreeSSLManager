using System.Security.Claims;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service;

namespace SslManager.Api.Controllers;

[ApiController, Route("api/auth")]
public sealed class AuthController(IIdentityService identity) : BusinessController
{
    [AllowAnonymous, HttpGet("setup-status")]
    public async Task<IActionResult> SetupStatus(CancellationToken ct) =>
        Ok(ApiResult<SetupStatus>.Ok(new(await identity.IsSetupRequiredAsync(ct))));

    [AllowAnonymous, HttpGet("csrf")]
    public IActionResult Csrf([FromServices] IAntiforgery antiforgery)
    {
        // 前端首次提交及登录后重新获取令牌；密钥不参与此接口。
        var tokens = antiforgery.GetAndStoreTokens(HttpContext);
        return tokens.RequestToken is null
            ? StatusCode(500, ApiResult<CsrfToken>.Fail("INTERNAL_ERROR", "无法创建请求验证令牌。"))
            : Ok(ApiResult<CsrfToken>.Ok(new(tokens.RequestToken)));
    }

    [AllowAnonymous, HttpPost("setup"), EnableRateLimiting("login")]
    public async Task<IActionResult> Setup(SetupInput input, CancellationToken ct)
    {
        var result = await identity.SetupAsync(input, ct);
        if (!result.Success || result.Data is null)
            return Reply(result);
        await SignInAsync(result.Data);
        return Ok(result);
    }

    [AllowAnonymous, HttpPost("login"), EnableRateLimiting("login")]
    public async Task<IActionResult> Login(LoginInput input, CancellationToken ct)
    {
        var result = await identity.LoginAsync(input, ct);
        if (!result.Success || result.Data is null) return StatusCode(401, result);
        await SignInAsync(result.Data);
        return Ok(result);
    }

    [Authorize, HttpGet("current-user")]
    public async Task<IActionResult> CurrentUser(CancellationToken ct)
    {
        var result = await identity.GetCurrentUserAsync(User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "", ct);
        if (!result.Success)
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return StatusCode(401, result);
        }
        return Ok(result);
    }

    [Authorize, HttpPost("change-password")]
    public async Task<IActionResult> ChangePassword(ChangePasswordInput input, CancellationToken ct)
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "";
        var result = await identity.ChangePasswordAsync(userId, input, ct);
        return Reply(result);
    }

    [Authorize, HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Ok(ApiResult<bool>.Ok(true, "已退出登录。"));
    }

    private Task SignInAsync(CurrentUser user)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, user.Id), new Claim(ClaimTypes.Name, user.Username),
            new Claim("display_name", user.Name), new Claim(ClaimTypes.Role, user.Role)
        ], CookieAuthenticationDefaults.AuthenticationScheme));
        return HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal,
            new AuthenticationProperties { IsPersistent = false, AllowRefresh = false });
    }
}
