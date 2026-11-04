namespace SslManager.Api.Models;

/// <summary>仅保存在计划运行 JSON 内的吊销验证记录台账，不与证书申请记录混用，也不新增数据库字段。</summary>
public sealed class ScheduleRevocationDnsRecord
{
    public string Domain { get; set; } = "";
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public string Value { get; set; } = "";
    public string ZoneId { get; set; } = "";
    public string ZoneName { get; set; } = "";
    public string AccountId { get; set; } = "";
    public string RecordId { get; set; } = "";
    public bool CreatedBySystem { get; set; }
    public bool IsPersistent { get; set; }
    public string Status { get; set; } = "Pending";
    public string Code { get; set; } = "";
    public string Message { get; set; } = "";
}

/// <summary>申请验证清理的固定快照，仅写入运行 JSON；证书和验证行删除后仍可继续核对。</summary>
public sealed class ScheduleApplicationDnsCleanup
{
    public string CertificateId { get; set; } = "";
    public string AccountId { get; set; } = "";
    public string Domain { get; set; } = "";
    public string Provider { get; set; } = "";
    public string ValidationMode { get; set; } = "";
    public bool Enabled { get; set; }
    public string Status { get; set; } = "Pending";
    public List<ScheduleApplicationDnsRecord> Records { get; set; } = [];
}

/// <summary>申请验证与吊销验证采用不同类型，不能互相认领 DNS 删除权。</summary>
public sealed class ScheduleApplicationDnsRecord
{
    public string ValidationRecordId { get; set; } = "";
    public string Name { get; set; } = "";
    public string Type { get; set; } = "";
    public string Value { get; set; } = "";
    public string ZoneId { get; set; } = "";
    public string ZoneName { get; set; } = "";
    public string AccountId { get; set; } = "";
    public string RecordId { get; set; } = "";
    public bool CreatedBySystem { get; set; }
    public bool IsPersistent { get; set; }
    public string Status { get; set; } = "Pending";
    public string Code { get; set; } = "";
    public string Message { get; set; } = "";
}
