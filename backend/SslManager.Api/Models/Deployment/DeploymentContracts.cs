using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace SslManager.Api.Models;

/// <summary>执行器显式声明版本和能力，目标始终固定到注册的实现。</summary>
public sealed record DeploymentExecutorDescriptor(string Key, string Name, string TargetType, string OperatingSystem,
    string Protocol, string Revision = "1", string SupportedProductVersions = "", bool Available = true,
    string UnavailableReason = "", string[]? AuthenticationModes = null, string[]? MaterialFormats = null,
    bool SupportsRollback = false);

/// <summary>配置中不包含密码、Token、私钥或 PFX 密码。</summary>
public sealed class DeploymentTargetConfiguration
{
    /// <summary>群晖证书的匹配与新增描述；留空使用证书域名，按 ID 更新时保留远端原描述。</summary>
    public string CertificateDescription { get; set; } = "";
    public string[] SiteIds { get; set; } = [];
    public string RemoteCertificateId { get; set; } = "";
    public bool BindSites { get; set; }
    public string OperatingSystem { get; set; } = "";
    public string Shell { get; set; } = "";
    public string OutputDirectory { get; set; } = "";
    /// <summary>Harbor Docker Compose 安装目录；只允许实际绝对路径，不执行安装或重新生成配置。</summary>
    public string HarborInstallDirectory { get; set; } = "";
    /// <summary>仅支持已安装的 docker compose 或 docker-compose，不拼接其他命令。</summary>
    public string HarborComposeCommand { get; set; } = "docker compose";
    /// <summary>只重建此 Harbor HTTPS 代理服务，不停止其他组件。</summary>
    public string HarborProxyService { get; set; } = "proxy";
    /// <summary>来源域名固定绑定；同域名续签证书可以复用文件映射，不固定某次签发的证书 ID。</summary>
    public string SourceDomain { get; set; } = "";
    /// <summary>仅兼容旧配置及历史任务快照；新保存的目标使用 SourceDomain 并清空此字段。</summary>
    public string SourceCertificateId { get; set; } = "";
    public string SourceFormat { get; set; } = "";
    public List<DeploymentFileMapping> Files { get; set; } = [];
    public List<DeploymentCommand> ValidationCommands { get; set; } = [];
    public List<DeploymentCommand> PostCommands { get; set; } = [];
    public string HostKeyFingerprint { get; set; } = "";
    public bool CreateDirectory { get; set; }
    public string VerificationHost { get; set; } = "";
    public int VerificationPort { get; set; } = 443;
    public string VerificationServerName { get; set; } = "";
    public int ConnectionTimeoutSeconds { get; set; } = 30;
    public int OperationTimeoutSeconds { get; set; } = 120;
}
/// <summary>每个源文件可独立选择目录；空目录沿用公共输出目录，源名使用 ZIP 内完整相对路径。</summary>
public sealed record DeploymentFileMapping(string Role, string FileName, string Directory = "", string SourceFileName = "");
public sealed record DeploymentCommand(string Command, string WorkingDirectory = "", int TimeoutSeconds = 120,
    string ExecutionMode = "WaitForExit", string RecoveryCheckCommand = "", bool RetryOnInterruption = false);

public sealed class DeploymentTargetInput
{
    [Required, StringLength(100)] public string Name { get; set; } = "";
    [StringLength(500)] public string Description { get; set; } = "";
    [Required] public string ExecutorKey { get; set; } = "";
    [Required, StringLength(2048)] public string Endpoint { get; set; } = "";
    public int Port { get; set; }
    [StringLength(200)] public string Username { get; set; } = "";
    [StringLength(40)] public string AuthenticationMode { get; set; } = "Password";
    [StringLength(16384)] public string Password { get; set; } = "";
    [StringLength(16384)] public string ApiToken { get; set; } = "";
    [StringLength(65536)] public string PrivateKey { get; set; } = "";
    [StringLength(4096)] public string PrivateKeyPassphrase { get; set; } = "";
    [StringLength(4096)] public string PfxPassword { get; set; } = "";
    public bool Enabled { get; set; } = true;
    [StringLength(256)] public string TlsFingerprint { get; set; } = "";
    public int? ConfigRevision { get; set; }
    public DeploymentTargetConfiguration Configuration { get; set; } = new();
}
public sealed record DeploymentTargetView(string Id, string Name, string Description, string ExecutorKey,
    string ExecutorRevision, string Endpoint, int Port, string Username, string AuthenticationMode, bool Enabled,
    string TlsFingerprint, int ConfigRevision, DeploymentTargetConfiguration Configuration, bool PasswordConfigured,
    bool ApiTokenConfigured, bool PrivateKeyConfigured, bool PfxPasswordConfigured, DateTime? LastTestAtUtc,
    bool? LastTestSuccess, string LastTestMessage, string ProductVersion, DateTime? LastDeploymentAtUtc,
    string LastDeploymentStatus);

/// <summary>只在服务内存及专用加密快照中使用，API 不序列化秘密。</summary>
public sealed class DeploymentCredentials
{
    public string Password { get; set; } = "";
    public string ApiToken { get; set; } = "";
    public string PrivateKey { get; set; } = "";
    public string PrivateKeyPassphrase { get; set; } = "";
    public string PfxPassword { get; set; } = "";
    public override string ToString() => "[Protected deployment credentials]";
}
public sealed class DeploymentTargetContext
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string ExecutorKey { get; init; } = "";
    public string ExecutorRevision { get; init; } = "1";
    public string Endpoint { get; init; } = "";
    public int Port { get; init; }
    public string Username { get; init; } = "";
    public string AuthenticationMode { get; init; } = "Password";
    public string TlsFingerprint { get; init; } = "";
    public int ConfigRevision { get; init; }
    public DeploymentTargetConfiguration Configuration { get; init; } = new();
    [JsonIgnore] public DeploymentCredentials Credentials { get; init; } = new();
}
public sealed record DeploymentConnectionTest(string ProductVersion, string Message, string[]? Capabilities = null);
public sealed record DeploymentDiscovery(IReadOnlyList<DeploymentRemoteCertificate> Certificates,
    IReadOnlyList<DeploymentRemoteSite> Sites, string ProductVersion = "");
public sealed record DeploymentRemoteCertificate(string Id, string Name, string[] Domains, string Fingerprint = "", string[]? RelatedSiteIds = null);
public sealed record DeploymentRemoteSite(string Id, string Name, string[] Domains, string CertificateId = "");

public sealed record CertificateMaterialMetadata(string CertificateId, string Domain, string[] Domains,
    string Fingerprint, string MaterialDigest, DateTime NotBeforeUtc, DateTime NotAfterUtc);
public sealed class CertificateMaterial
{
    public required CertificateMaterialMetadata Metadata { get; init; }
    public string CertificatePem { get; init; } = "";
    public string ChainPem { get; init; } = "";
    public string FullChainPem { get; init; } = "";
    [JsonIgnore] public string PrivateKeyPem { get; init; } = "";
    [JsonIgnore] public IReadOnlyList<CertificateSourcePackage> SourcePackages { get; init; } = [];
    public override string ToString() => $"CertificateMaterial {Metadata.Fingerprint}";
}
public sealed record DeploymentSelection(string TargetId, string RemoteCertificateId = "", string[]? SiteIds = null)
{
    /// <summary>队列复核使用计划已解析的资源，空 ID 表示新增，不再回落目标配置中的旧 ID。</summary>
    [JsonIgnore]
    public bool UseConfiguredRemoteCertificateId { get; init; } = true;
}
public sealed record DeploymentPlanRequest(IReadOnlyList<DeploymentSelection> Targets);
public sealed record DeploymentSubmitRequest(int PlanRevision, string IdempotencyKey);
public sealed record DeploymentTargetPlan(string ResourceKey, string Action, string Summary,
    string PreconditionsJson = "{}", string RemoteResourceId = "", string[]? SiteIds = null,
    string[]? FilePaths = null, string[]? Warnings = null);
public sealed record DeploymentPlanView(string BatchId, int PlanRevision, DateTime ExpiresAtUtc,
    CertificateMaterialMetadata Certificate, IReadOnlyList<DeploymentPlanTargetView> Targets);
public sealed record DeploymentPlanTargetView(string TaskId, string TargetId, string TargetName, string ExecutorKey,
    int ConfigRevision, DeploymentTargetPlan Plan);
public sealed record DeploymentExecutionResult(string Message, string RemoteResourceId = "", string Fingerprint = "",
    string VerificationLevel = "PlatformReadback", bool Skipped = false, string ReceiptJson = "{}");
public sealed record DeploymentInspection(bool MatchesExpected, string Message, string Fingerprint = "",
    string VerificationLevel = "None");
/// <summary>Completed 表示全部动作和证明齐全；Retry 只等待或核对；Blocked 表示需要明确处理冲突。</summary>
public sealed record DeploymentRecoveryResult(string Disposition, string Message, DeploymentExecutionResult? Result = null);
public sealed class DeploymentExecutionContext
{
    public required string TaskId { get; init; }
    public required DeploymentTargetContext Target { get; init; }
    public required CertificateMaterial Material { get; init; }
    public required DeploymentTargetPlan Plan { get; init; }
    public required Func<string, string, CancellationToken, Task> ReportProgressAsync { get; init; }
    /// <summary>恢复沿原任务的检查点继续，私钥和源文件字节仍只保存在加密材料快照。</summary>
    public bool IsRecovery { get; init; }
    public string ReceiptJson { get; init; } = "{}";
    public Func<string, string, CancellationToken, Task>? SaveCheckpointAsync { get; init; }
    /// <summary>MCP 来源任务在每次文件、命令或平台变更前复核当前授权；普通 Web 任务为空。</summary>
    public Func<CancellationToken, Task>? BeforeExternalMutationAsync { get; init; }
}
public sealed record DeploymentInspectionContext(DeploymentTargetContext Target, DeploymentTargetPlan Plan,
    CertificateMaterialMetadata Material, string ReceiptJson = "{}");
public sealed record DeploymentRollbackContext(DeploymentTargetContext Target, string SourceTaskId, string ReceiptJson);
public sealed record DeploymentRollbackResult(string Message);
public sealed record DeploymentStatusRequest(bool Enabled);
public sealed record DeploymentResolveRequest(string Note);

public sealed record DeploymentTaskView(string Id, string BatchId, string TargetId, string TargetName,
    string ExecutorKey, string Status, string Phase, string Message, string Code, string VerificationLevel,
    string Fingerprint, string RemoteResourceId, bool CancelRequested, DateTime CreatedAtUtc,
    DateTime? StartedAtUtc, DateTime? FinishedAtUtc, IReadOnlyList<DeploymentStepView>? Steps = null, string SourceTaskId = "");
public sealed record DeploymentStepView(string Id, string Phase, string Status, string Message, DateTime CreatedAtUtc);
public sealed record DeploymentBatchView(string Id, string CertificateId, string CertificateDomain,
    string Fingerprint, string Status, int PlanRevision, DateTime CreatedAtUtc, DateTime ExpiresAtUtc,
    IReadOnlyList<DeploymentTaskView> Tasks, string OperationType = "Deploy");
