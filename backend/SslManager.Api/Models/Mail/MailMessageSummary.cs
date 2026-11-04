namespace SslManager.Api.Models.Mail;

/// <summary>发件列表保留当时的发件身份与固定中文结果，不读取服务器自由文本。</summary>
public sealed record MailMessageSummary(string Id, IReadOnlyList<string> To, string FromAddress,
    string Subject, string Status, string Code, string Message, string CreatedByUserId,
    string CreatedByName, DateTime CreatedAtUtc, DateTime? CompletedAtUtc);
