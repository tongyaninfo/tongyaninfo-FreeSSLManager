using System.ComponentModel.DataAnnotations;

namespace SslManager.Api.Models;

/// <summary>周期计划绑定账号、域名和明确选择的目标，不绑定某一次证书签发。</summary>
public sealed class CertificateSchedule
{
    public string Id { get; set; } = "";
    public string Name { get; set; } = "";
    public string AccountId { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Alias { get; set; } = "";
    public string ValidationMode { get; set; } = "ManagedDns";
    /// <summary>固定 DNS 托管区域；历史空值继续使用原同账号匹配规则。</summary>
    public string? DnsZoneId { get; set; }
    public bool AutoCleanup { get; set; } = true;
    public bool RevokeOldCertificates { get; set; } = true;
    public string TargetIdsJson { get; set; } = "[]";
    public int IntervalValue { get; set; } = 1;
    public string IntervalUnit { get; set; } = "month";
    public DateTime FirstRunAtUtc { get; set; }
    public DateTime NextRunAtUtc { get; set; }
    public bool Enabled { get; set; } = true;
    public int ConfigRevision { get; set; } = 1;
    public string CreatedByUserId { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
}

/// <summary>运行快照记录每一个有副作用的阶段，重启只恢复已有申请和部署。</summary>
public sealed class CertificateScheduleRun
{
    public string Id { get; set; } = "";
    public string ScheduleId { get; set; } = "";
    public string TriggerKey { get; set; } = "";
    public string ConfigSnapshotJson { get; set; } = "{}";
    public string CertificateId { get; set; } = "";
    public string TargetsJson { get; set; } = "[]";
    public string OldCertificatesJson { get; set; } = "[]";
    public string Status { get; set; } = "Pending";
    public string Message { get; set; } = "";
    public string Code { get; set; } = "";
    public string CleanupStatus { get; set; } = "Pending";
    public DateTime ScheduledForUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? StartedAtUtc { get; set; }
    public DateTime? FinishedAtUtc { get; set; }
    public DateTime NextCheckAtUtc { get; set; }
    public DateTime? LeaseUntilUtc { get; set; }
    public string LeaseToken { get; set; } = "";
    public bool Active { get; set; } = true;
}

/// <summary>启用时即授权按本配置自动申请、部署和可选的旧证书清理。</summary>
public class CertificateScheduleInput
{
    [Required, StringLength(100)] public string Name { get; set; } = "";
    [Required] public string AccountId { get; set; } = "";
    [Required, StringLength(253)] public string Domain { get; set; } = "";
    [StringLength(100)] public string Alias { get; set; } = "";
    public string ValidationMode { get; set; } = "ManagedDns";
    public string? DnsZoneId { get; set; }
    public bool AutoCleanup { get; set; } = true;
    public bool RevokeOldCertificates { get; set; } = true;
    public string[] TargetIds { get; set; } = [];
    [Range(1, 1200)] public int IntervalValue { get; set; } = 1;
    public string IntervalUnit { get; set; } = "month";
    public DateTime FirstRunAtUtc { get; set; }
    public bool Enabled { get; set; } = true;
    public int? ConfigRevision { get; set; }
}

public sealed class CertificateScheduleView : CertificateScheduleInput
{
    public string Id { get; set; } = "";
    public string AccountName { get; set; } = "";
    public DateTime NextRunAtUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
    public CertificateScheduleRunView? LatestRun { get; set; }
}

/// <summary>对外仅返回业务进度，不返回内部租约、云凭据或私钥。</summary>
public sealed class CertificateScheduleRunView
{
    public string Id { get; set; } = "";
    public string ScheduleId { get; set; } = "";
    public string CertificateId { get; set; } = "";
    public string Status { get; set; } = "";
    public string Code { get; set; } = "";
    public string Message { get; set; } = "";
    public string CleanupStatus { get; set; } = "";
    /// <summary>仅返回申请验证 DNS 的汇总状态，不暴露台账和验证值。</summary>
    public string ApplicationCleanupStatus { get; set; } = "NotRequested";
    public DateTime ScheduledForUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime? StartedAtUtc { get; set; }
    public DateTime? FinishedAtUtc { get; set; }
    public DateTime NextCheckAtUtc { get; set; }
    public bool Active { get; set; }
    public IReadOnlyList<ScheduleTargetProgress> Targets { get; set; } = [];
    public IReadOnlyList<ScheduleCertificateCleanup> OldCertificates { get; set; } = [];
}

public sealed class ScheduleTargetProgress
{
    public string TargetId { get; set; } = "";
    public string TargetName { get; set; } = "";
    /// <summary>申请前固定目标修订；历史值 0 需要核对配置更新时间后补齐，不能静默采用新命令。</summary>
    public int ConfigRevision { get; set; }
    public string BatchId { get; set; } = "";
    public string Status { get; set; } = "Pending";
    public string Code { get; set; } = "";
    public string Message { get; set; } = "";
}

public sealed class ScheduleCertificateCleanup
{
    public string CertificateId { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Status { get; set; } = "Pending";
    public string Code { get; set; } = "";
    public string Message { get; set; } = "";
    /// <summary>吊销专用 DNS 台账随运行 JSON 持久化，证书删除后仍可完成最后清理；API 视图不包含验证值。</summary>
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public List<ScheduleRevocationDnsRecord>? RevocationValidation { get; set; }
    /// <summary>删除旧证书前固定申请验证台账，删除证书行后仍可继续清理。</summary>
    [System.Text.Json.Serialization.JsonIgnore(Condition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull)]
    public ScheduleApplicationDnsCleanup? ApplicationCleanup { get; set; }
}

/// <summary>仅序列化到现有运行 JSON 的内部恢复快照，不增加数据库列或公开输入字段。</summary>
internal sealed class CertificateScheduleRunSnapshot : CertificateScheduleInput
{
    public int RecoveryVersion { get; set; } = 1;
    public int RecoveryAttempts { get; set; }
    public ScheduleApplicationDnsCleanup? ApplicationCleanup { get; set; }
    public string ApplicationCleanupStatus { get; set; } = "NotRequested";
}
