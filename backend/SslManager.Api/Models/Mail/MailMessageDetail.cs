namespace SslManager.Api.Models.Mail;

/// <summary>发件详情仅供已授权用户读取本系统保存的正文与协议标识。</summary>
public sealed record MailMessageDetail(string Id, IReadOnlyList<string> To, string FromAddress,
    string Subject, string Status, string Code, string Message, string CreatedByUserId,
    string CreatedByName, DateTime CreatedAtUtc, DateTime? CompletedAtUtc, string Body, string MessageId);
