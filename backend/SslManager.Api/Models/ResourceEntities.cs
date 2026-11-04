using System.ComponentModel.DataAnnotations.Schema;

namespace SslManager.Api.Models;

/// <summary>云端 DNS 托管区域快照，不代表域名注册商资产。</summary>
public sealed class ManagedDomain
{
    public string Id { get; set; } = "";
    public string AccountId { get; set; } = "";
    public string Provider { get; set; } = "";
    public string ZoneId { get; set; } = "";
    public string Name { get; set; } = "";
    public string Status { get; set; } = "";
    public DateTime SyncedAtUtc { get; set; }
}

/// <summary>证书与订单 ID 分开保存，保留平台原始状态及产品类型。</summary>
public sealed class ManagedCertificate
{
    public string Id { get; set; } = "";
    public string AccountId { get; set; } = "";
    public string Provider { get; set; } = "";
    public string CertificateId { get; set; } = "";
    public string OrderId { get; set; } = "";
    public string InstanceId { get; set; } = "";
    public string ApiVersion { get; set; } = "V1";
    public string Domain { get; set; } = "";
    public string Alias { get; set; } = "";
    public string ProductCode { get; set; } = "";
    /// <summary>本地 ACME 材料与测试环境的能力必须在服务端核验。</summary>
    public bool HasPrivateKey { get; set; } = true;
    public bool IsStaging { get; set; }
    [NotMapped] public bool CanDownload => Status == "Issued" && HasPrivateKey;
    [NotMapped] public bool CanDeploy => CanDownload && !IsStaging;
    [NotMapped] public bool CanRevoke => Status is "Issued" or "Expired";
    [NotMapped] public bool CanCancel => (Status is "PendingValidation" or "Processing") && (Provider is "TencentCloud" or "Aliyun");
    [NotMapped] public bool CanDelete => Status is "Expired" or "Revoked" or "Cancelled";
    [NotMapped] public string[] DownloadFormats => Provider == "TencentCloud"
        ? ["nginx", "apache", "iis", "tomcat"] : ["nginx", "apache", "iis", "pem", "pfx"];
    public bool? IsFree { get; set; }
    public string Status { get; set; } = "Unknown";
    public string RawStatus { get; set; } = "";
    public DateTime? NotBeforeUtc { get; set; }
    public DateTime? NotAfterUtc { get; set; }
    public string ValidationMode { get; set; } = "ManualDns";
    public bool AutoCleanup { get; set; }
    public string? DnsZoneId { get; set; }
    public string CleanupStatus { get; set; } = "NotRequested";
    public DateTime SyncedAtUtc { get; set; }
}

/// <summary>仅本系统创建的临时记录具备自动删除资格。</summary>
public sealed class ValidationRecord
{
    public string Id { get; set; } = "";
    public string CertificateId { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Name { get; set; } = "";
    public string Type { get; set; } = "TXT";
    public string Value { get; set; } = "";
    public string? DnsZoneId { get; set; }
    public string? RecordId { get; set; }
    public bool CreatedBySystem { get; set; }
    public bool IsPersistent { get; set; }
    public string Status { get; set; } = "Pending";
    public string Message { get; set; } = "";
}

/// <summary>申请任务先记账再提交；结果未知时不重新创建云订单。</summary>
public sealed class CertificateJob
{
    public string Id { get; set; } = "";
    public string CertificateId { get; set; } = "";
    public string Kind { get; set; } = "Apply";
    public string Status { get; set; } = "Pending";
    public string Message { get; set; } = "";
    public int Attempts { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime NextRunAtUtc { get; set; }
    public DateTime? LeaseUntilUtc { get; set; }
    public string RequestId { get; set; } = "";
}

/// <summary>审计日志只记录操作摘要，不记录密钥、私钥或完整云响应。</summary>
public sealed class AuditLog
{
    public string Id { get; set; } = "";
    public string UserId { get; set; } = "";
    public string Username { get; set; } = "";
    public string Action { get; set; } = "";
    public string ResourceId { get; set; } = "";
    public bool Success { get; set; }
    public string Code { get; set; } = "";
    public string Message { get; set; } = "";
    public DateTime CreatedAtUtc { get; set; }
}
