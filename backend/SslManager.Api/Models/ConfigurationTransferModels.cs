using System.Text.Json;
using SslManager.Api.Models.Mail;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Models;

/// <summary>可移植配置包；凭据由管理员主动导出为明文，不包含业务数据与原密钥环。</summary>
public sealed class ConfigurationPackage
{
    public string Format { get; set; } = "free-ssl-manager.configuration";
    public int Version { get; set; } = 1;
    public DateTime ExportedAtUtc { get; set; }
    public List<CloudAccountConfiguration> CloudAccounts { get; set; } = [];
    public List<DeploymentTargetConfigurationItem> DeploymentTargets { get; set; } = [];
    public List<CertificateScheduleConfiguration> CertificateSchedules { get; set; } = [];
    public MailSettingsInput? MailSettings { get; set; }
    // 可选字段保持旧版配置包兼容；运行中的预警状态与发信历史不参与导入导出。
    public ExpiryReminderSettingsInput? ExpiryReminderSettings { get; set; }
    /// <summary>MCP 只迁移非秘密设置；导入后关闭并清空公开地址，必须在本地重新复核。</summary>
    public McpSettingsInput? McpSettings { get; set; }
    public List<McpClientConfiguration> McpClients { get; set; } = [];
    public override string ToString() => "ConfigurationPackage { 明文配置内容已隐藏 }";
}

/// <summary>客户端只携带可移植配置和停用规则，不携带本地用户、OAuth 身份、秘密或授权。</summary>
public sealed class McpClientConfiguration
{
    public string SourceId { get; set; } = "";
    public McpPortableClientSettings Settings { get; set; } = new();
    /// <summary>AccountIds 和 TargetIds 引用同包配置的 SourceId，导入时统一映射。</summary>
    public List<McpAllowRuleInput> AllowRules { get; set; } = [];
    public override string ToString() => "McpClientConfiguration { 可移植配置内容已隐藏 }";
}

public sealed class McpPortableClientSettings
{
    public string Name { get; set; } = "";
    public string ClientType { get; set; } = "public";
    public string GrantType { get; set; } = "authorization_code";
    public string[] Scopes { get; set; } = [];
    public string[] RedirectUris { get; set; } = [];
    public DateTime? ExpiresAtUtc { get; set; }
}

/// <summary>SourceId 只作为包内引用键，导入时重新映射到目标实例的账号 ID。</summary>
public sealed class CloudAccountConfiguration
{
    public string SourceId { get; set; } = "";
    public CloudAccountInput Settings { get; set; } = new();
    public override string ToString() => "CloudAccountConfiguration { 凭据已隐藏 }";
}

/// <summary>显式携带连接凭据；禁止把整个配置项写入日志或审计。</summary>
public sealed class DeploymentTargetConfigurationItem
{
    public string SourceId { get; set; } = "";
    public DeploymentTargetInput Settings { get; set; } = new();
    public override string ToString() => "DeploymentTargetConfigurationItem { 凭据已隐藏 }";
}

/// <summary>计划中的 AccountId 和 TargetIds 均引用包内 SourceId。</summary>
public sealed class CertificateScheduleConfiguration
{
    public string SourceId { get; set; } = "";
    public CertificateScheduleInput Settings { get; set; } = new();
    /// <summary>区域引用按包内 DNS 账号与稳定平台区域映射，不能将源实例本地主键直接带入。</summary>
    public string? DnsAccountSourceId { get; set; }
    public string? DnsZoneName { get; set; }
    public string? DnsProviderZoneId { get; set; }
    public override string ToString() => "CertificateScheduleConfiguration { 配置内容已隐藏 }";
}

/// <summary>预览与提交使用相同原始 JSON；提交凭证只承诺其摘要，不携带任何明文凭据。</summary>
public sealed class ConfigurationImportRequest
{
    public JsonElement Package { get; set; }
    public string Mode { get; set; } = "CreateOnly";
    public string PreviewToken { get; set; } = "";
    public override string ToString() => "ConfigurationImportRequest { 配置内容及预览凭证已隐藏 }";
}

public sealed record ConfigurationImportItemPreview(string Kind, string SourceId, string Name, string Action);
public sealed record ConfigurationImportIssue(string Path, string Message);
public sealed record ConfigurationImportPreview(string Mode, string PreviewToken, bool CanImport, int Created,
    int Updated, int Conflicts, IReadOnlyList<ConfigurationImportItemPreview> Items,
    IReadOnlyList<ConfigurationImportIssue> Errors);
public sealed record ConfigurationImportResult(int Created, int Updated, DateTime ImportedAtUtc);
