using SslManager.Api.Models.Mail;

namespace SslManager.Api.Service;

/// <summary>本地 HTML 邮件模板渲染；所有业务字段先转义，模板不可用时明确失败。</summary>
public interface IExpiryReminderTemplateRenderer
{
    Task<ExpiryReminderContent> RenderAsync(IReadOnlyList<ExpiryAlertView> alerts, int daysBeforeExpiry,
        DateTime generatedAtUtc, CancellationToken ct);
}
