using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
namespace SslManager.Api.Models;

/// <summary>部署目标只保存目标配置，私密字段始终密文。</summary>
public sealed class DeploymentTarget
{
    [MaxLength(64)] public string Id { get; set; } = "";
    [MaxLength(100)] public string Name { get; set; } = "";
    [MaxLength(500)] public string Description { get; set; } = "";
    [MaxLength(100)] public string ExecutorKey { get; set; } = "";
    [MaxLength(40)] public string ExecutorRevision { get; set; } = "1";
    [MaxLength(2048)] public string Endpoint { get; set; } = "";
    public int Port { get; set; }
    [MaxLength(200)] public string Username { get; set; } = "";
    public string AuthenticationMode { get; set; } = "Password";
    public bool Enabled { get; set; } = true;
    public string TlsFingerprint { get; set; } = "";
    public string ConfigurationJson { get; set; } = "{}";
    [JsonIgnore] public string ProtectedCredentials { get; set; } = "";
    public int ConfigRevision { get; set; } = 1;
    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public DateTime? LastTestAtUtc { get; set; }
    public bool? LastTestSuccess { get; set; }
    public string LastTestMessage { get; set; } = "";
    public string ProductVersion { get; set; } = "";
    public DateTime? LastDeploymentAtUtc { get; set; }
    public string LastDeploymentStatus { get; set; } = "";
}
public sealed class DeploymentBatch
{
    public string Id { get; set; } = "";
    public string CertificateId { get; set; } = "";
    public string CertificateDomain { get; set; } = "";
    public string Fingerprint { get; set; } = "";
    public string MaterialDigest { get; set; } = "";
    public string MaterialSnapshotId { get; set; } = "";
    public string CreatedBy { get; set; } = "";
    public string Status { get; set; } = "Draft";
    public string OperationType { get; set; } = "Deploy";
    public string IdempotencyKey { get; set; } = "";
    public int PlanRevision { get; set; } = 1;
    public DateTime CreatedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? SubmittedAtUtc { get; set; }
}
public sealed class DeploymentTask
{
    public string Id { get; set; } = "";
    public string BatchId { get; set; } = "";
    public string SourceTaskId { get; set; } = "";
    public string TargetId { get; set; } = "";
    public string TargetName { get; set; } = "";
    public string ExecutorKey { get; set; } = "";
    public string ExecutorRevision { get; set; } = "1";
    public int ConfigRevision { get; set; }
    public string Status { get; set; } = "Draft";
    public string Phase { get; set; } = "Plan";
    public string Message { get; set; } = "";
    public string Code { get; set; } = "";
    public string ResourceKey { get; set; } = "";
    public string TargetSnapshotJson { get; set; } = "{}";
    [JsonIgnore] public string ProtectedCredentials { get; set; } = "";
    public string PlanJson { get; set; } = "{}";
    public string MaterialSnapshotId { get; set; } = "";
    public string Fingerprint { get; set; } = "";
    public string VerificationLevel { get; set; } = "None";
    public string RemoteResourceId { get; set; } = "";
    public string ReceiptJson { get; set; } = "{}";
    public string LeaseId { get; set; } = "";
    public DateTime? LeaseUntilUtc { get; set; }
    public bool CancelRequested { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? StartedAtUtc { get; set; }
    public DateTime? FinishedAtUtc { get; set; }
}
public sealed class DeploymentTaskStep
{
    public string Id { get; set; } = "";
    public string TaskId { get; set; } = "";
    public string Phase { get; set; } = "";
    public string Status { get; set; } = "";
    public string Message { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }
}
public sealed class DeploymentBinding
{
    public string Id { get; set; } = "";
    public string TargetId { get; set; } = "";
    public string ResourceKey { get; set; } = "";
    public string RemoteResourceId { get; set; } = "";
    public string CertificateId { get; set; } = "";
    public string Fingerprint { get; set; } = "";
    public string MaterialDigest { get; set; } = "";
    public string LastTaskId { get; set; } = "";
    public DateTime UpdatedAtUtc { get; set; }
}
public sealed class DeploymentMaterialSnapshot
{
    public string Id { get; set; } = "";
    public string CertificateId { get; set; } = "";
    public string MetadataJson { get; set; } = "{}";
    [JsonIgnore] public string ProtectedPayload { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
}
