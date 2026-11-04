using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Models.Mail;

namespace SslManager.Api.Service.impl.Mail;

public sealed partial class MailService
{
    internal const string ExpiryReminderActorId = "system:certificate-expiry";

    /// <summary>后台提醒沿用人工发送流水线；已记账的固定请求只能读取原结果，不能再次发送。</summary>
    public async Task<ApiResult<MailMessageDetail>> SendExpiryReminderAsync(ExpiryReminderMailInput input, CancellationToken ct)
    {
        if (!Guid.TryParse(input.RequestId, out var parsedRequestId) || parsedRequestId == Guid.Empty)
            return ApiResult<MailMessageDetail>.Fail("VALIDATION", "提醒发送请求标识无效。");
        var requestId = parsedRequestId.ToString("D");
        await RecoverInterruptedAsync(ct);
        var existing = await db.MailMessages.AsNoTracking().SingleOrDefaultAsync(x => x.RequestId == requestId, ct);
        if (existing is not null)
            return existing.CreatedByUserId == ExpiryReminderActorId
                ? ApiResult<MailMessageDetail>.Ok(ToDetail(existing), "此提醒请求已记录，未重复发送。")
                : ApiResult<MailMessageDetail>.Fail("CONFLICT", "同一请求标识已用于其他邮件。");
        var message = new MailSendInput { RequestId = input.RequestId, To = input.To, Subject = input.Subject, Body = input.Body };
        var error = ValidateMessage(message);
        if (error is not null) return ApiResult<MailMessageDetail>.Fail("VALIDATION", error);
        if (string.IsNullOrWhiteSpace(input.HtmlBody) || input.HtmlBody.Length > 100000)
            return ApiResult<MailMessageDetail>.Fail("VALIDATION", "提醒 HTML 正文须为 1～100000 字。");
        if (input.SettingsUpdatedAtUtc == default || input.AlertIds is null || input.AlertIds.Length is < 1 or > 100
            || input.AlertIds.Any(string.IsNullOrWhiteSpace) || input.AlertIds.Distinct(StringComparer.Ordinal).Count() != input.AlertIds.Length)
            return ApiResult<MailMessageDetail>.Fail("VALIDATION", "提醒配置版本或证书提醒标识无效。");
        return await SendRecordedAsync(message, ExpiryReminderActorId, "证书到期提醒", input.HtmlBody, true,
            token => AuthorizeExpiryReminderAsync(input, requestId, token), ct);
    }

    /// <summary>保存意图前与实际 SMTP 调用前均复核开关、配置版本、忽略/解除状态及本轮证书到期时间。</summary>
    private async Task<string?> AuthorizeExpiryReminderAsync(ExpiryReminderMailInput input, string requestId, CancellationToken ct)
    {
        if (!await db.ExpiryReminderSettings.AsNoTracking().AnyAsync(x => x.Id == "default" && x.Enabled
            && x.UpdatedAtUtc == input.SettingsUpdatedAtUtc, ct))
            return "EXPIRY_REMINDER_CONFIGURATION_CHANGED";

        var validAlerts = await db.CertificateExpiryAlerts.AsNoTracking()
            .Where(x => input.AlertIds.Contains(x.Id) && x.Status == "Active" && x.PendingRequestId == requestId
                && db.Certificates.Any(certificate => certificate.Id == x.CertificateId
                    && certificate.NotAfterUtc == x.NotAfterUtc && certificate.Status != "Revoked"
                    && certificate.Status != "Cancelled" && certificate.Status != "Deleted" && certificate.Status != "NotPresent"
                    && certificate.Status != "Refunded" && certificate.Status != "Removed"))
            .CountAsync(ct);
        return validAlerts == input.AlertIds.Length ? null : "EXPIRY_ALERT_CHANGED";
    }
}
