using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace SslManager.Api.Models.Mail;

/// <summary>系统唯一的 SMTP 配置；密码仅保存现有 Data Protection 保护后的密文。</summary>
public sealed class MailSettings
{
    [MaxLength(64)] public string Id { get; set; } = "default";
    public bool Enabled { get; set; } = true;
    [MaxLength(253)] public string Host { get; set; } = "";
    public int Port { get; set; } = 465;
    [MaxLength(30)] public string Security { get; set; } = "SslOnConnect";
    [MaxLength(254)] public string Username { get; set; } = "";
    [MaxLength(254)] public string FromAddress { get; set; } = "";
    [MaxLength(100)] public string FromName { get; set; } = "";
    [JsonIgnore] public string ProtectedPassword { get; set; } = "";
    public DateTime UpdatedAtUtc { get; set; }
}
