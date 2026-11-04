using System.ComponentModel.DataAnnotations;

namespace SslManager.Api.Models.Mail;

/// <summary>邮件配置输入；更新时不填写密码会保留原密码，响应只返回是否已配置。</summary>
public sealed class MailSettingsInput
{
    public bool Enabled { get; set; } = true;
    [Required, StringLength(253)] public string Host { get; set; } = "";
    [Range(1, 65535)] public int Port { get; set; } = 465;
    [Required, StringLength(30)] public string Security { get; set; } = "SslOnConnect";
    /// <summary>留空时使用发件地址作为 SMTP 登录账号。</summary>
    [StringLength(254)] public string Username { get; set; } = "";
    [Required, StringLength(254)] public string FromAddress { get; set; } = "";
    [StringLength(100)] public string FromName { get; set; } = "";
    [StringLength(4096)] public string Password { get; set; } = "";
}
