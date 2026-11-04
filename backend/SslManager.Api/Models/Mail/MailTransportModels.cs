using System.Text.Json.Serialization;

namespace SslManager.Api.Models.Mail;

/// <summary>解密后的密码只在服务端短暂传给协议适配器，不允许序列化或写入日志。</summary>
public sealed record MailTransportEndpoint(string Host, int Port, string Security, string Username,
    [property: JsonIgnore] string Password, int TimeoutSeconds = 30)
{
    public override string ToString() => "MailTransportEndpoint { 邮件凭据已隐藏 }";
}

/// <summary>UTF-8 邮件；人工邮件仅使用纯文本，系统提醒可追加本轮内存中的 HTML 替代正文。</summary>
public sealed record MailTransportMessage(string MessageId, string FromAddress, string FromName,
    IReadOnlyList<string> To, string Subject, string Body, DateTime CreatedAtUtc, string? HtmlBody = null)
{
    public override string ToString() => "MailTransportMessage { 邮件正文已隐藏 }";
}

/// <summary>仅供后台证书到期提醒调用；HTML 不落入发件表，也不在日志中输出。</summary>
public sealed class ExpiryReminderMailInput
{
    public string RequestId { get; set; } = "";
    public string[] To { get; set; } = [];
    public string Subject { get; set; } = "";
    public string Body { get; set; } = "";
    [JsonIgnore] public string HtmlBody { get; set; } = "";
    public DateTime SettingsUpdatedAtUtc { get; set; }
    public string[] AlertIds { get; set; } = [];
    public override string ToString() => "ExpiryReminderMailInput { 邮件正文已隐藏 }";
}

/// <summary>模板渲染结果；仅纯文本摘要保存到现有发件记录。</summary>
public sealed record ExpiryReminderContent(string Subject, string TextBody, string HtmlBody)
{
    public override string ToString() => "ExpiryReminderContent { 邮件正文已隐藏 }";
}

/// <summary>Accepted 仅表示服务器受理；Unknown 必须人工核验，不能自动重发。</summary>
public sealed record MailTransportResult(string Status, string Code, string Message);

public sealed record MailTransportProbeResult(bool Success, string Code, string Message);
