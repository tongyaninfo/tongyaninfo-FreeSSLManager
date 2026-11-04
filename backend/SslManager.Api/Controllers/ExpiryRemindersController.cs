using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SslManager.Api.Common;
using SslManager.Api.Models.Mail;
using SslManager.Api.Service;

namespace SslManager.Api.Controllers;

/// <summary>管理员维护提醒规则和忽略预警；保存和忽略不会直接调用 SMTP。</summary>
[ApiController, Authorize(Roles = "admin"), Route("api/mail/expiry-reminders")]
public sealed class ExpiryRemindersController(IExpiryReminderService reminders) : BusinessController
{
    [HttpGet("settings")]
    public async Task<IActionResult> Settings(CancellationToken ct)
    {
        DisableCaching();
        return Reply(await reminders.GetSettingsAsync(ct));
    }

    [HttpPut("settings")]
    public async Task<IActionResult> SaveSettings(ExpiryReminderSettingsInput input, CancellationToken ct)
    {
        DisableCaching();
        return Reply(await reminders.SaveSettingsAsync(input, ct));
    }

    [HttpGet("alerts")]
    public async Task<IActionResult> Alerts([FromQuery] int page = 1, [FromQuery] int pageSize = 20,
        [FromQuery] string? status = null, CancellationToken ct = default)
    {
        DisableCaching();
        return Reply(await reminders.ListAsync(page, pageSize, status, ct));
    }

    [HttpPost("alerts/{id}/ignore")]
    public async Task<IActionResult> Ignore(string id, CancellationToken ct)
    {
        DisableCaching();
        return Reply(await reminders.IgnoreAsync(id, ct));
    }

    private void DisableCaching()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
    }
}
