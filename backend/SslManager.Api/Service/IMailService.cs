using SslManager.Api.Common;
using SslManager.Api.Models.Mail;

namespace SslManager.Api.Service;

/// <summary>单套 SMTP 配置与本系统发件记录；没有收件、审批或自动重发。</summary>
public interface IMailService
{
    Task<ApiResult<MailSettingsSummary>> GetSettingsAsync(CancellationToken ct);
    Task<ApiResult<MailSettingsSummary>> SaveSettingsAsync(MailSettingsInput input, CancellationToken ct);
    Task<ApiResult<bool>> ProbeAsync(CancellationToken ct);
    Task<ApiResult<MailMessageDetail>> SendAsync(MailSendInput input, string userId, CancellationToken ct);
    /// <summary>内部到期提醒入口，复用发送前记账与幂等流水线，不提供 HTTP 调用。</summary>
    Task<ApiResult<MailMessageDetail>> SendExpiryReminderAsync(ExpiryReminderMailInput input, CancellationToken ct);
    Task<ApiResult<PageResult<MailMessageSummary>>> ListAsync(int page, int pageSize, string? search, string? status, CancellationToken ct);
    Task<ApiResult<MailMessageDetail>> GetAsync(string id, CancellationToken ct);
    Task<int> RecoverInterruptedAsync(CancellationToken ct);
}
