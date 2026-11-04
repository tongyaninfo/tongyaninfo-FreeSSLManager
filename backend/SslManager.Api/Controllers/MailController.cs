using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SslManager.Api.Common;
using SslManager.Api.Models.Mail;
using SslManager.Api.Service;

namespace SslManager.Api.Controllers;

/// <summary>邮件配置、发送及正文均限管理员，沿用 Cookie、CSRF 和统一业务返回。</summary>
[ApiController, Authorize(Roles = "admin"), Route("api/mail")]
public sealed class MailController(IMailService mail) : BusinessController
{
    [HttpGet("settings")]
    public async Task<IActionResult> Settings(CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store";
        return Reply(await mail.GetSettingsAsync(ct));
    }

    [HttpPut("settings")]
    public async Task<IActionResult> SaveSettings(MailSettingsInput input, CancellationToken ct) =>
        Reply(await mail.SaveSettingsAsync(input, ct));

    [HttpPost("probe")]
    public async Task<IActionResult> Probe(CancellationToken ct) => Reply(await mail.ProbeAsync(ct));

    [HttpPost("send"), RequestSizeLimit(512 * 1024)]
    public async Task<IActionResult> Send(MailSendInput input, CancellationToken ct) =>
        Reply(await mail.SendAsync(input, User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "", ct));

    [HttpGet("messages")]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20,
        [FromQuery] string? search = null, [FromQuery] string? status = null, CancellationToken ct = default)
    {
        Response.Headers.CacheControl = "no-store";
        return Reply(await mail.ListAsync(page, pageSize, search, status, ct));
    }

    [HttpGet("messages/{id}")]
    public async Task<IActionResult> Detail(string id, CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store";
        return Reply(await mail.GetAsync(id, ct));
    }
}
