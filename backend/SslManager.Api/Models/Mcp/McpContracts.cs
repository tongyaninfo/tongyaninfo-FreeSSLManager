using System.Text.Json;
using SslManager.Api.Common;

namespace SslManager.Api.Models.Mcp;

public sealed class McpSettingsInput
{
    public bool Enabled { get; set; }
    public string PublicBaseUrl { get; set; } = "";
    public string SystemName { get; set; } = "Free SSL Manager";
    public string Mode { get; set; } = "ReadOnly";
    public string[] AllowedCidrs { get; set; } = [];
    public string[] AllowedOrigins { get; set; } = [];
    public string[] AllowedTools { get; set; } = [];
    public int RateLimitPerMinute { get; set; } = 60;
    public int MaxConcurrentCalls { get; set; } = 4;
    public int LogRetentionDays { get; set; } = 90;
    public int? ConfigRevision { get; set; }
}
public sealed record McpSettingsView(bool Enabled, string PublicBaseUrl, string Mode, string[] AllowedCidrs,
    string[] AllowedOrigins, string[] AllowedTools, int RateLimitPerMinute, int MaxConcurrentCalls, int LogRetentionDays,
    int ConfigRevision, DateTime? UpdatedAtUtc, string SystemName = "Free SSL Manager", string InstanceId = "");
public sealed record McpStatusView(bool Supported, bool Enabled, bool OAuthReady, string State, string Message,
    string McpUrl, string[] ProtocolVersions, string SdkVersion, bool ApiKeyReady = false,
    string SystemName = "Free SSL Manager", string InstanceId = "");
public sealed class McpClientInput
{
    public string Name { get; set; } = "";
    public string ClientType { get; set; } = "public";
    public string GrantType { get; set; } = "authorization_code";
    public string BoundUserId { get; set; } = "";
    public string[] Scopes { get; set; } = [];
    public string[] RedirectUris { get; set; } = [];
    public DateTime? ExpiresAtUtc { get; set; }
    public int? ConfigRevision { get; set; }
}
public sealed record McpClientView(string Id, string ClientId, string Name, string ClientType, string GrantType,
    string BoundUserId, string[] Scopes, string[] RedirectUris, bool Enabled, DateTime? ExpiresAtUtc,
    int ConfigRevision, DateTime CreatedAtUtc, DateTime UpdatedAtUtc, DateTime? LastUsedAtUtc);
public sealed record McpClientCreated(McpClientView Client, string? ClientSecret = null);
public sealed record McpSecretView(string ClientId, string ClientSecret);
public sealed record McpStatusInput(bool Enabled, int? ConfigRevision = null);
public sealed class McpAllowRuleInput
{
    public string[] ToolNames { get; set; } = [];
    public string[] AccountIds { get; set; } = [];
    public string[] Domains { get; set; } = [];
    public string[] TargetIds { get; set; } = [];
    public string[] AllowedCidrs { get; set; } = [];
    public string[] Scopes { get; set; } = [];
    public bool AllAccounts { get; set; }
    public bool AllDomains { get; set; }
    public bool AllTargets { get; set; }
    public string ApprovalMode { get; set; } = "Manual";
    public bool Enabled { get; set; } = true;
    public DateTime? ExpiresAtUtc { get; set; }
}
public sealed record McpAllowRulesInput(IReadOnlyList<McpAllowRuleInput> Rules, int ConfigRevision);
public sealed record McpAllowRulesView(IReadOnlyList<McpAllowRuleInput> Rules, int ConfigRevision);
public sealed record McpToolDescriptor(string Name, string Title, string Description, bool ReadOnly,
    string[] Scopes, string[] ResourceKinds, JsonElement InputSchema, JsonElement? OutputSchema = null);
/// <summary>由已验证凭据构造；客户端不能通过工具参数指定用户、来源或授权身份。</summary>
public sealed record McpCallerContext(string ClientId, string EffectiveUserId, string AuthorizationId,
    string[] Scopes, string SourceIp, string Role = "", string TraceId = "", string RemoteIp = "",
    string AuthenticationType = "OAuth", string ApiKeyId = "");
public sealed record McpResourceScope(string AccountId = "", string Domain = "", string TargetId = "", string ScheduleId = "");
public sealed record McpEffectivePermission(int SettingsRevision, int ClientRevision, int PolicyRevision,
    IReadOnlyList<McpAllowRuleInput> Rules, bool Preauthorized = false);
public sealed record McpApprovalInput(int Version, string Note = "");
/// <summary>审批及工具查询只返回公开业务摘要，隐藏输入快照、内部资源及执行租约。</summary>
public sealed record McpOperationView(string Id, string Kind, string ToolName, string Status, string IdempotencyKey,
    string EffectiveUserId, string PreparedBy, string ApprovedBy, DateTime? ApprovalExpiresAtUtc, DateTime? ApprovedAtUtc,
    DateTime? ConsumedAtUtc, string CertificateId, string CertificateJobId, string BatchId, string TaskId, int PlanRevision,
    int Version, DateTime CreatedAtUtc, DateTime UpdatedAtUtc, string Message, string Code, string SummaryJson = "{}",
    string ClientId = "", string ArgumentsDigest = "", bool CanApprove = false);
public sealed record McpConnectionProfile(string McpUrl, string ClientId, string Transport, string GrantType,
    string[] Scopes, string AuthorizationUrl, string TokenUrl, string SystemName = "Free SSL Manager", string InstanceId = "",
    [property: System.Text.Json.Serialization.JsonPropertyName("oauthMcpUrl")] string OAuthMcpUrl = "");
public sealed record McpInvocationQuery(int Page = 1, int PageSize = 20, string? ClientId = null,
    string? ToolName = null, string? Status = null, string? Code = null, string? SourceIp = null,
    DateTime? FromUtc = null, DateTime? ToUtc = null, string? ApiKeyId = null, string? Method = null,
    string? TraceId = null, int? HttpStatus = null, string? AuthenticationType = null);
