namespace SslManager.Api.Models;

public sealed record SyncRequest(string AccountId);
public sealed record RecordStatusRequest(bool Enabled);
public sealed record CertificateApplyRequest(string AccountId, string Domain, string Alias = "",
    string ValidationMode = "NativeAutoDns", bool AutoCleanup = true, string? DnsZoneId = null,
    string? InstanceId = null, string ApiVersion = "V2");
public sealed record RevokeRequest(string Reason = "");
public sealed record BatchDeleteRequest(IReadOnlyCollection<string>? Ids);
