using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace SslManager.Api.Models;

/// <summary>长期签发台账，私钥与 CSR 仅以 DataProtection 密文保存；不属于短期部署快照。</summary>
public sealed class CertificateIssuanceState
{
    [Key, MaxLength(64)] public string Id { get; set; } = "";
    [MaxLength(64)] public string AccountId { get; set; } = "";
    [MaxLength(30)] public string Provider { get; set; } = "";
    [MaxLength(254)] public string Domain { get; set; } = "";
    [MaxLength(40)] public string Stage { get; set; } = "Prepared";
    public string RemoteCertificateId { get; set; } = "";
    public string AcmeAccountUrl { get; set; } = "";
    [MaxLength(64)] public string AccountKeyThumbprint { get; set; } = "";
    public string OrderUrl { get; set; } = "";
    public string FinalizeUrl { get; set; } = "";
    public string CertificateUrl { get; set; } = "";
    public string AuthorizationsJson { get; set; } = "[]";
    public bool IsStaging { get; set; }
    [JsonIgnore] public string ProtectedPayload { get; set; } = "";
    [ConcurrencyCheck] public long Revision { get; set; }
    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
}

/// <summary>仅在服务进程内传递，不得作为 HTTP 返回对象或日志参数。</summary>
public sealed record CertificateIssuancePayload(
    [property: JsonIgnore] string PrivateKeyPem,
    [property: JsonIgnore] string CsrPem,
    [property: JsonIgnore] string CertificatePem = "",
    [property: JsonIgnore] string ChainPem = "",
    string Stage = "Prepared", string RemoteCertificateId = "")
{
    public override string ToString() => "CertificateIssuancePayload { 私钥、CSR与证书材料已隐藏 }";
}

/// <summary>此载荷专用于密文序列化；与对外不可序列化的材料 DTO 分开。</summary>
internal sealed record ProtectedIssuancePayload(string PrivateKeyPem, string CsrPem, string CertificatePem = "", string ChainPem = "")
{
    public override string ToString() => "ProtectedIssuancePayload { 已隐藏 }";
}

public sealed record AcmeAuthorizationState(string AuthorizationUrl, string ChallengeUrl, string Token, string Domain, string Status, bool NotificationSubmitted = false);
