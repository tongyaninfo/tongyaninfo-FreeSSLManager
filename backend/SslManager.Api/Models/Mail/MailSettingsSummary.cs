namespace SslManager.Api.Models.Mail;

/// <summary>仅返回非敏感 SMTP 参数，密码和密文都不进入 HTTP 响应。</summary>
public sealed record MailSettingsSummary(bool Configured, bool Enabled, string Host, int Port,
    string Security, string Username, string FromAddress, string FromName, bool HasPassword, DateTime? UpdatedAtUtc);
