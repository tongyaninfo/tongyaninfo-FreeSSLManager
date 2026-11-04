namespace SslManager.Api.Models;

/// <summary>云端资源标识必须携带版本，防止把订单、实例、证书 ID 混用。</summary>
public sealed record CloudCertificateReference(string CertificateId = "", string OrderId = "", string InstanceId = "", string ApiVersion = "V1");
public sealed record CloudConnectionTest(string Provider, string RequestId, string Message);
/// <summary>阿里云证书申请联系人；同步接口只返回申请所需的公开字段。</summary>
public sealed record AliyunContact(string Id, string Name, string Mobile, bool MobileVerified,
    string Email, bool EmailVerified);
/// <summary>阿里云 CAS V2 已领取的测试证书实例；只返回尚未绑定证书的免费实例。</summary>
public sealed record AliyunCertificateInstanceOption(string InstanceId, string Name, string Domain,
    string Status, string Spec);
public sealed record CloudCertificate(
    CloudCertificateReference Reference, string Domain, string Alias, string Status, string RawStatus,
    bool? IsFree, string ProductCode, DateTimeOffset? NotBeforeUtc, DateTimeOffset? NotAfterUtc,
    string ValidationMode, string RequestId, bool HasPrivateKey = true, bool IsStaging = false);
public sealed record DnsChallenge(string Domain, string Name, string Type, string Value, bool IsPersistent = false, bool IsRelative = false);
/// <summary>申请与吊销的验证值独立传递，避免拿申请记录执行吊销验证或清理。</summary>
public sealed record CloudCertificateDetail(CloudCertificate Certificate, IReadOnlyList<DnsChallenge> Challenges,
    string? FailureReason = null, IReadOnlyList<DnsChallenge>? RevocationChallenges = null);
public sealed record CloudCertificateApplyRequest(string Domain, string ValidationMode = "ManualDns", bool AutoCleanup = true,
    string? InstanceId = null, string ApiVersion = "V2", string Alias = "", string LocalCertificateId = "");
/// <summary>云端异步操作结果；TaskId 仅在平台返回异步任务时填写。</summary>
public sealed record CloudOperation(string RequestId, string State, IReadOnlyList<DnsChallenge>? Challenges = null, string TaskId = "");
/// <summary>证书下载只在内存中传递，禁止记录内容、私钥和临时下载地址。</summary>
public sealed record CertificateDownload(byte[] Content, string ContentType, string FileName, string RequestId);
public sealed record DnsZone(string Id, string Name, string Status, IReadOnlyList<string> NameServers, string RequestId);
public sealed record DnsRecord(string Id, string Zone, string Name, string Type, string Value, int Ttl,
    string Status, string Line, string RequestId, int? Mx = null, bool Proxied = false);
public sealed record DnsRecordRequest(string Name, string Type, string Value, int Ttl = 600, string Line = "default", int? Mx = null);
