using System.ComponentModel.DataAnnotations;

namespace SslManager.Api.Models;

/// <summary>云账号配置实体；两类密钥均为 Data Protection 密文，不能直接作为 API 响应。</summary>
public sealed class CloudAccount
{
    [MaxLength(64)] public string Id { get; set; } = "";
    [MaxLength(100)] public string Name { get; set; } = "";
    [MaxLength(30)] public string Provider { get; set; } = "";
    public string ProtectedAccessKeyId { get; set; } = "";
    public string ProtectedAccessKeySecret { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public bool UseForCertificates { get; set; } = true;
    public bool UseForDns { get; set; } = true;
    [MaxLength(100)] public string ContactName { get; set; } = "";
    [MaxLength(254)] public string ContactEmail { get; set; } = "";
    [MaxLength(40)] public string ContactPhone { get; set; } = "";
    /// <summary>阿里云证书申请联系人 ID；只保存 ID，不保存云端联系人密钥等敏感信息。</summary>
    [MaxLength(64)] public string AliyunContactId { get; set; } = "";
    /// <summary>ACME 目录决定正式或测试环境，修改后不会复用另一目录的账号密钥。</summary>
    [MaxLength(300)] public string AcmeDirectoryUrl { get; set; } = "https://acme-v02.api.letsencrypt.org/directory";
    /// <summary>默认使用用户已有账号；Automatic 仅允许管理员显式注册一次。</summary>
    [MaxLength(20)] public string AcmeAccountMode { get; set; } = "Existing";
    [MaxLength(30)] public string AcmeRegistrationStatus { get; set; } = "";
    public DateTime? AcmeRegisteredAtUtc { get; set; }
    public bool AutoSyncEnabled { get; set; }
    public string AutoSyncIntervalUnit { get; set; } = "hour";
    public int AutoSyncIntervalValue { get; set; } = 6;
    public string AutoSyncAtLocalTime { get; set; } = "02:00";
    public DateTime? AutoSyncNextRunAtUtc { get; set; }
    public DateTime? LastAutoSyncAtUtc { get; set; }
    public DateTime? LastTestAtUtc { get; set; }
    public bool? LastTestSuccess { get; set; }
    public string LastTestCode { get; set; } = "";
    public string LastTestMessage { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
}
