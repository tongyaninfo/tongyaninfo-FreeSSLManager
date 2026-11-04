using System.ComponentModel.DataAnnotations;

namespace SslManager.Api.Models.Mail;

/// <summary>一份草稿使用固定请求标识，重复提交读取原结果，不再次发送。</summary>
public sealed class MailSendInput
{
    [Required, StringLength(64)] public string RequestId { get; set; } = "";
    [Required, MinLength(1), MaxLength(50)] public string[] To { get; set; } = [];
    [Required, StringLength(300)] public string Subject { get; set; } = "";
    [Required, StringLength(100000)] public string Body { get; set; } = "";
}
