using System.ComponentModel.DataAnnotations;

namespace SslManager.Api.Models.Mail;

/// <summary>全局到期提醒配置；默认关闭，与现有 SMTP 配置分别维护。</summary>
public sealed class ExpiryReminderSettings
{
    [MaxLength(64)] public string Id { get; set; } = "default";
    public bool Enabled { get; set; }
    public int DaysBeforeExpiry { get; set; } = 30;
    public int RepeatIntervalDays { get; set; } = 1;
    public string RecipientsJson { get; set; } = "[]";
    public DateTime UpdatedAtUtc { get; set; }
}

/// <summary>同一证书及到期时间是一轮预警；忽略状态不会因同域名存在其他证书而改变。</summary>
public sealed class CertificateExpiryAlert
{
    [MaxLength(64)] public string Id { get; set; } = "";
    [MaxLength(64)] public string CertificateId { get; set; } = "";
    [MaxLength(100)] public string AccountName { get; set; } = "";
    [MaxLength(253)] public string Domain { get; set; } = "";
    [MaxLength(100)] public string Alias { get; set; } = "";
    public DateTime NotAfterUtc { get; set; }
    [MaxLength(20)] public string Status { get; set; } = "Active";
    public DateTime FirstDetectedAtUtc { get; set; }
    public DateTime? LastAttemptAtUtc { get; set; }
    public DateTime? NextReminderAtUtc { get; set; }
    [MaxLength(20)] public string LastMailStatus { get; set; } = "";
    [MaxLength(500)] public string Message { get; set; } = "";
    public int AttemptSequence { get; set; }
    // 一组邮件共享同一请求键；只有组长保存冻结的收件人与正文快照，避免重启后改变发送内容。
    [MaxLength(64)] public string PendingRequestId { get; set; } = "";
    [MaxLength(64)] public string PendingLeaderId { get; set; } = "";
    public string PendingPayloadJson { get; set; } = "";
    [MaxLength(64)] public string LeaseToken { get; set; } = "";
    public DateTime? LeaseUntilUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
}

public sealed class ExpiryReminderSettingsInput
{
    public bool Enabled { get; set; }
    [Range(1, 365)] public int DaysBeforeExpiry { get; set; } = 30;
    [Range(0, 365)] public int RepeatIntervalDays { get; set; } = 1;
    [MaxLength(50)] public string[] Recipients { get; set; } = [];
}

public sealed record ExpiryReminderSettingsSummary(bool Configured, bool Enabled, int DaysBeforeExpiry,
    int RepeatIntervalDays, IReadOnlyList<string> Recipients, bool SmtpConfigured, bool SmtpEnabled, DateTime? UpdatedAtUtc);

public sealed record ExpiryAlertView(string Id, string CertificateId, string AccountName, string Domain, string Alias,
    DateTime NotAfterUtc, string Status, DateTime FirstDetectedAtUtc, DateTime? LastAttemptAtUtc,
    DateTime? NextReminderAtUtc, string LastMailStatus, string Message);
