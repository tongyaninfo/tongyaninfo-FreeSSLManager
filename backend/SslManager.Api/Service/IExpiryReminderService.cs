using SslManager.Api.Common;
using SslManager.Api.Models.Mail;

namespace SslManager.Api.Service;

/// <summary>到期规则与预警状态独立持久化，保存和忽略均不会直接发送邮件。</summary>
public interface IExpiryReminderService
{
    Task<ApiResult<ExpiryReminderSettingsSummary>> GetSettingsAsync(CancellationToken ct);
    Task<ApiResult<ExpiryReminderSettingsSummary>> SaveSettingsAsync(ExpiryReminderSettingsInput input, CancellationToken ct);
    Task<ApiResult<PageResult<ExpiryAlertView>>> ListAsync(int page, int pageSize, string? status, CancellationToken ct);
    Task<ApiResult<ExpiryAlertView>> IgnoreAsync(string id, CancellationToken ct);
    Task<int> ProcessAsync(CancellationToken ct);
}
