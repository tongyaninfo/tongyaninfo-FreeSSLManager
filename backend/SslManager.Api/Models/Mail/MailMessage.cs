using System.ComponentModel.DataAnnotations;

namespace SslManager.Api.Models.Mail;

/// <summary>本系统主动发送的邮件记录；发送结果未知时保留记录，禁止以重试猜测是否送达。</summary>
public sealed class MailMessage
{
    [MaxLength(64)] public string Id { get; set; } = "";
    [MaxLength(64)] public string RequestId { get; set; } = "";
    public string ToJson { get; set; } = "[]";
    [MaxLength(254)] public string FromAddress { get; set; } = "";
    [MaxLength(300)] public string Subject { get; set; } = "";
    public string Body { get; set; } = "";
    [MaxLength(20)] public string Status { get; set; } = "Sending";
    [MaxLength(64)] public string Code { get; set; } = "";
    [MaxLength(500)] public string Message { get; set; } = "";
    [MaxLength(64)] public string CreatedByUserId { get; set; } = "";
    [MaxLength(100)] public string CreatedByName { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
    [MaxLength(254)] public string MessageId { get; set; } = "";
}
