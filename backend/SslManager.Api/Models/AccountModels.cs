using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace SslManager.Api.Models;

public sealed class CloudAccountInput
{
    [Required, StringLength(100)] public string Name { get; set; } = "";
    [Required, StringLength(30)] public string Provider { get; set; } = "";
    /// <summary>更新时空字符串保留原值；不能用空白字符覆盖密钥。</summary>
    [StringLength(4096)] public string AccessKeyId { get; set; } = "";
    [StringLength(8192)] public string AccessKeySecret { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public bool UseForCertificates { get; set; } = true;
    public bool UseForDns { get; set; } = true;
    [StringLength(100)] public string ContactName { get; set; } = "";
    [StringLength(254)] public string ContactEmail { get; set; } = "";
    [StringLength(40)] public string ContactPhone { get; set; } = "";
    /// <summary>阿里云 ListContact 返回的联系人 ID。未选择时留空。</summary>
    [StringLength(64)] public string AliyunContactId { get; set; } = "";
    /// <summary>ACME 正式与测试账号隔离；仅允许受支持的 Let's Encrypt 目录。</summary>
    [StringLength(300)] public string AcmeDirectoryUrl { get; set; } = "https://acme-v02.api.letsencrypt.org/directory";
    [StringLength(20)] public string AcmeAccountMode { get; set; } = "Existing";
    public bool AutoSyncEnabled { get; set; }
    [StringLength(20)] public string AutoSyncIntervalUnit { get; set; } = "hour";
    [Range(1, 366)] public int AutoSyncIntervalValue { get; set; } = 6;
    [StringLength(5)] public string AutoSyncAtLocalTime { get; set; } = "02:00";
}

/// <summary>读取阿里云联系人所需的临时请求参数；密钥只用于本次请求，不落库。</summary>
public sealed class CloudContactSyncInput
{
    [StringLength(64)] public string? AccountId { get; set; }
    [Required, StringLength(30)] public string Provider { get; set; } = "Aliyun";
    [StringLength(4096)] public string? AccessKeyId { get; set; }
    [StringLength(8192)] public string? AccessKeySecret { get; set; }
}

/// <summary>只有管理员明确同意 CA 条款后，独立注册操作才允许创建外部账号。</summary>
public sealed record AcmeAccountRegistrationRequest(bool AgreeTerms = false);

/// <summary>管理员列表只返回掩码和是否配置，不暴露密钥密文或明文。</summary>
public sealed record CloudAccountSummary(string Id, string Name, string Provider, string AccessKeyIdMasked,
    bool HasAccessKeySecret, bool Enabled, bool UseForCertificates, bool UseForDns,
    string ContactName, string ContactEmail, string ContactPhone, DateTime CreatedAtUtc, DateTime UpdatedAtUtc,
    bool AutoSyncEnabled = false, string AutoSyncIntervalUnit = "hour", int AutoSyncIntervalValue = 6,
    string AutoSyncAtLocalTime = "02:00", DateTime? AutoSyncNextRunAtUtc = null, DateTime? LastAutoSyncAtUtc = null,
    DateTime? LastTestAtUtc = null, bool? LastTestSuccess = null, string LastTestCode = "", string LastTestMessage = "",
    string AliyunContactId = "", string AcmeDirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory",
    string AcmeAccountMode = "Existing", string AcmeAccountStatus = "", string AccountUrl = "", string PublicKeyThumbprint = "", DateTime? RegisteredAtUtc = null);
public sealed record CloudAccountOption(string Id, string Name, string Provider, bool Enabled,
    bool UseForCertificates, bool UseForDns, string AcmeDirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory");
public sealed record CloudAccountPage(IReadOnlyList<CloudAccountSummary> Items, int Total, int Page, int PageSize);

/// <summary>仅由管理员主动查看接口返回；禁止在日志中记录该对象。</summary>
public sealed record CloudAccountSecrets(string AccessKeyId, string AccessKeySecret)
{
    public override string ToString() => "CloudAccountSecrets { 已隐藏密钥 }";
}

/// <summary>仅供服务端云适配器使用；控制器不得返回该类型或记录其内容。</summary>
public sealed record CloudAccountCredentials(string Id, string Name, string Provider,
    [property: JsonIgnore] string AccessKeyId, [property: JsonIgnore] string AccessKeySecret,
    bool Enabled, bool UseForCertificates, bool UseForDns, string ContactName, string ContactEmail, string ContactPhone,
    string AliyunContactId = "", string AcmeDirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory")
{
    public override string ToString() => $"CloudAccountCredentials {{ Id = {Id}, Provider = {Provider}, 已隐藏密钥 }}";
}
