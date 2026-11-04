using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using OpenIddict.EntityFrameworkCore.Models;

namespace SslManager.Api.Models.Mcp;

/// <summary>MCP 单例配置，空白名单拒绝访问，默认关闭。</summary>
public sealed class McpSettings
{
    public string Id { get; set; } = "default";
    public bool Enabled { get; set; }
    public string PublicBaseUrl { get; set; } = "";
    public string SystemName { get; set; } = "Free SSL Manager";
    public string InstanceId { get; set; } = "";
    public string Mode { get; set; } = "ReadOnly";
    public string AllowedCidrsJson { get; set; } = "[]";
    public string AllowedOriginsJson { get; set; } = "[]";
    public string AllowedToolsJson { get; set; } = "[]";
    public int RateLimitPerMinute { get; set; } = 60;
    public int MaxConcurrentCalls { get; set; } = 4;
    public int LogRetentionDays { get; set; } = 90;
    public int ConfigRevision { get; set; } = 1;
    public DateTime UpdatedAtUtc { get; set; }
}

/// <summary>业务客户端关联标准 OAuth Application，不存明文秘密。</summary>
public sealed class McpClient
{
    public string Id { get; set; } = "";
    public string OAuthApplicationId { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string Name { get; set; } = "";
    public string ClientType { get; set; } = "public";
    public string GrantType { get; set; } = "authorization_code";
    public string BoundUserId { get; set; } = "";
    public string ScopesJson { get; set; } = "[]";
    public string RedirectUrisJson { get; set; } = "[]";
    public bool Enabled { get; set; }
    public DateTime? ExpiresAtUtc { get; set; }
    public int ConfigRevision { get; set; } = 1;
    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public DateTime? LastUsedAtUtc { get; set; }
}

/// <summary>客户端的预分配调用凭据；秘密仅保存高熵随机值的摘要，撤销记录保留供审计核对。</summary>
public sealed class McpApiKey
{
    public string Id { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string Name { get; set; } = "";
    public string Prefix { get; set; } = "";
    [JsonIgnore] public string SecretHash { get; set; } = "";
    public bool Enabled { get; set; } = true;
    public DateTime? ExpiresAtUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public DateTime? LastUsedAtUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
    public int ConfigRevision { get; set; } = 1;
}

/// <summary>一条规则内各适用维度取交集，多条规则取并集；全部范围必须明确勾选。</summary>
public sealed class McpAllowRule
{
    public string Id { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string ToolNamesJson { get; set; } = "[]";
    public string AccountIdsJson { get; set; } = "[]";
    public string DomainsJson { get; set; } = "[]";
    public string TargetIdsJson { get; set; } = "[]";
    public string AllowedCidrsJson { get; set; } = "[]";
    public string ScopesJson { get; set; } = "[]";
    public bool AllAccounts { get; set; }
    public bool AllDomains { get; set; }
    public bool AllTargets { get; set; }
    public string ApprovalMode { get; set; } = "Manual";
    public bool Enabled { get; set; } = true;
    public DateTime? ExpiresAtUtc { get; set; }
    public int ConfigRevision { get; set; } = 1;
}

/// <summary>保存调用元数据及有界白名单入出参投影，不保存原始请求响应或任何凭据。</summary>
public sealed class McpInvocationLog
{
    public string Id { get; set; } = "";
    public string TraceId { get; set; } = "";
    public string RequestId { get; set; } = "";
    public string ProtocolVersion { get; set; } = "";
    public string Method { get; set; } = "";
    public string ToolName { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string UserId { get; set; } = "";
    public string AuthorizationId { get; set; } = "";
    public string AuthenticationType { get; set; } = "OAuth";
    public string ApiKeyId { get; set; } = "";
    public string ApiKeyName { get; set; } = "";
    public string ApiKeyPrefix { get; set; } = "";
    public string ContextJson { get; set; } = "{}";
    public string RemoteIp { get; set; } = "";
    public string SourceIp { get; set; } = "";
    public string Status { get; set; } = "Started";
    public string Code { get; set; } = "";
    public string Message { get; set; } = "";
    public string ArgumentsDigest { get; set; } = "";
    public string OperationId { get; set; } = "";
    public string CertificateId { get; set; } = "";
    public string BatchId { get; set; } = "";
    public string TaskId { get; set; } = "";
    public bool IdempotencyReused { get; set; }
    public int PolicyRevision { get; set; }
    public int HttpStatus { get; set; }
    public DateTime StartedAtUtc { get; set; }
    public DateTime? FinishedAtUtc { get; set; }
    public long DurationMilliseconds { get; set; }
    public int OccurrenceCount { get; set; } = 1;
}

/// <summary>不可变业务输入与执行台账；准备人、批准人和有效调用身份分别保留。</summary>
public sealed class McpOperation
{
    public string Id { get; set; } = "";
    public string ClientId { get; set; } = "";
    public string AuthorizationId { get; set; } = "";
    public string AuthenticationType { get; set; } = "OAuth";
    public string ApiKeyId { get; set; } = "";
    public string EffectiveUserId { get; set; } = "";
    public string PreparedBy { get; set; } = "";
    public string ApprovedBy { get; set; } = "";
    public string ToolName { get; set; } = "";
    public string Kind { get; set; } = "";
    public string Status { get; set; } = "Prepared";
    public string IdempotencyKey { get; set; } = "";
    public string ArgumentsJson { get; set; } = "{}";
    public string ArgumentsDigest { get; set; } = "";
    public string ResourceJson { get; set; } = "{}";
    public string SourceIp { get; set; } = "";
    public string ScopesJson { get; set; } = "[]";
    public int PolicyRevision { get; set; }
    public int SettingsRevision { get; set; }
    public int ClientRevision { get; set; }
    public DateTime? ApprovalExpiresAtUtc { get; set; }
    public DateTime? ApprovedAtUtc { get; set; }
    public DateTime? ConsumedAtUtc { get; set; }
    public string CertificateId { get; set; } = "";
    public string CertificateJobId { get; set; } = "";
    public string BatchId { get; set; } = "";
    public string TaskId { get; set; } = "";
    public int PlanRevision { get; set; }
    public string LeaseToken { get; set; } = "";
    public DateTime? LeaseUntilUtc { get; set; }
    public DateTime? NextRunAtUtc { get; set; }
    public int Version { get; set; } = 1;
    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public string Message { get; set; } = "";
    public string Code { get; set; } = "";
}

/// <summary>OAuth 四张框架表使用项目字符串业务 ID，实体 ID 在存储创建边界统一生成。</summary>
public sealed class McpOAuthApplication : OpenIddictEntityFrameworkCoreApplication<string, McpOAuthAuthorization, McpOAuthToken>;
public sealed class McpOAuthAuthorization : OpenIddictEntityFrameworkCoreAuthorization<string, McpOAuthApplication, McpOAuthToken>;
public sealed class McpOAuthScope : OpenIddictEntityFrameworkCoreScope<string>;
public sealed class McpOAuthToken : OpenIddictEntityFrameworkCoreToken<string, McpOAuthApplication, McpOAuthAuthorization>;
