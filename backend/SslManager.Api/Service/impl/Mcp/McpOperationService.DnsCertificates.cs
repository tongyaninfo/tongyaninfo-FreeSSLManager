using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Mcp;

public sealed partial class McpOperationService
{
    private async Task<ApiResult<BusinessSnapshot>> BuildBusinessSnapshotAsync(McpCallerContext caller, string tool, JsonElement input, CancellationToken ct)
    {
        if (tool is "ssl_dns_records_create" or "ssl_dns_records_update" or "ssl_dns_records_delete" or "ssl_dns_records_status")
            return await BuildDnsBusinessSnapshotAsync(caller, tool, input, ct);
        if (tool is "ssl_certificates_revoke" or "ssl_certificates_cancel" or "ssl_certificates_delete" or "ssl_certificates_cleanup_retry")
            return await BuildCertificateBusinessSnapshotAsync(caller, tool, input, ct);
        if (tool is "ssl_domains_sync" or "ssl_certificates_sync")
        {
            var accountId = BusinessText(input, "accountId");
            var account = await db.CloudAccounts.AsNoTracking().SingleOrDefaultAsync(x => x.Id == accountId && x.Enabled, ct);
            if (account is null || (tool == "ssl_domains_sync" ? !account.UseForDns : !account.UseForCertificates)) return BusinessSnapshotDenied();
            return ApiResult<BusinessSnapshot>.Ok(new([new(accountId)], BusinessAccountHash(account), accountId,
                JsonSerializer.Serialize(new { accountId, action = tool, allDomains = true }, Json), AllDomainsRequired: true));
        }
        return await BuildManagementSnapshotAsync(caller, tool, input, ct);
    }

    private async Task<ApiResult<BusinessSnapshot>> BuildDnsBusinessSnapshotAsync(McpCallerContext caller, string tool, JsonElement input, CancellationToken ct)
    {
        if (businessDomains is null) return BusinessSnapshotDenied("MCP_SERVICE_UNAVAILABLE");
        var zoneId = BusinessText(input, "zoneId"); var recordId = BusinessText(input, "recordId");
        var zone = await db.Domains.AsNoTracking().SingleOrDefaultAsync(x => x.Id == zoneId && x.Status != "NotPresent", ct);
        if (zone is null) return BusinessSnapshotDenied();
        var account = await db.CloudAccounts.AsNoTracking().SingleOrDefaultAsync(x => x.Id == zone.AccountId && x.Enabled && x.UseForDns, ct);
        if (account is null) return BusinessSnapshotDenied();
        var initial = await authorization.AuthorizeAsync(caller, tool, new(zone.AccountId), false, ct);
        if (!initial.Success) return BusinessSnapshotDenied(initial.Code);
        DnsRecord? original = null;
        if (tool != "ssl_dns_records_create")
        {
            if (recordId.Length == 0) return BusinessSnapshotDenied("INVALID_ARGUMENTS");
            var records = await businessDomains.ListRecordsAsync(zoneId, ct);
            if (!records.Success || records.Data is null || records.Data.Count > 10000) return BusinessSnapshotDenied("DNS_READ_FAILED");
            original = records.Data.SingleOrDefault(x => x.Id == recordId);
            if (original is null || NormalizeDomain(original.Zone) != NormalizeDomain(zone.Name)) return BusinessSnapshotDenied();
        }
        var oldName = original is null ? "" : BusinessDnsName(original.Name, zone.Name);
        var hasRequest = tool is "ssl_dns_records_create" or "ssl_dns_records_update";
        var request = hasRequest ? BusinessDnsRequest(input) : null;
        if (hasRequest && (request is null || !DomainManagementService.Validate(request).Success || request.Type == "MX" && request.Mx is not (>= 0 and <= 65535)))
            return BusinessSnapshotDenied("INVALID_RECORD");
        var newName = request is null ? "" : BusinessDnsName(request.Name, zone.Name);
        if (oldName.Length == 0 && original is not null || newName.Length == 0 && hasRequest) return BusinessSnapshotDenied("INVALID_RECORD_NAME");
        if (tool == "ssl_dns_records_status" && (!input.TryGetProperty("enabled", out var enabled) || enabled.ValueKind is not (JsonValueKind.True or JsonValueKind.False)))
            return BusinessSnapshotDenied("INVALID_ARGUMENTS");
        if (tool == "ssl_dns_records_status" && account.Provider == "Cloudflare") return BusinessSnapshotDenied("DNS_STATUS_UNSUPPORTED");
        if (hasRequest && account.Provider == "Cloudflare" && request!.Type is "CAA" or "SRV") return BusinessSnapshotDenied("DNS_STRUCTURED_RECORD_UNSUPPORTED");
        var names = new[] { oldName, newName }.Where(x => x.Length > 0).Distinct(StringComparer.Ordinal).ToArray();
        var scopes = names.Select(name => new McpResourceScope(zone.AccountId, name)).ToArray();
        foreach (var scope in scopes)
            if (!(await authorization.AuthorizeAsync(caller, tool, scope, false, ct)).Success) return BusinessSnapshotDenied("FORBIDDEN");
        var sourceDigest = original is null ? "" : BusinessRecordHash(original);
        var digest = BusinessHash(new { zone.Id, zone.AccountId, zone.ZoneId, zone.Provider, zone.Name, zone.Status,
            account = BusinessAccountHash(account), sourceDigest, newName });
        var summary = JsonSerializer.Serialize(new { zoneId, recordId, accountId = zone.AccountId, zone = zone.Name,
            originalName = oldName, name = newName.Length > 0 ? newName : oldName, type = request?.Type ?? original?.Type,
            ttl = request?.Ttl ?? original?.Ttl, line = request?.Line ?? original?.Line, mx = request?.Mx ?? original?.Mx,
            enabled = input.TryGetProperty("enabled", out var value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False ? (bool?)value.GetBoolean() : null,
            action = tool }, Json);
        return ApiResult<BusinessSnapshot>.Ok(new(scopes, digest, zoneId + "/" + recordId, summary, SourceRecordDigest: sourceDigest));
    }

    private async Task<ApiResult<BusinessSnapshot>> BuildCertificateBusinessSnapshotAsync(McpCallerContext caller, string tool, JsonElement input, CancellationToken ct)
    {
        var id = BusinessText(input, "certificateId");
        var certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        if (certificate is null) return BusinessSnapshotDenied();
        if (tool == "ssl_certificates_revoke" && !certificate.CanRevoke
            || tool == "ssl_certificates_cancel" && !certificate.CanCancel
            || tool == "ssl_certificates_delete" && (!certificate.CanDelete || certificate.Status == "Expired" && (certificate.NotAfterUtc is null || certificate.NotAfterUtc > DateTime.UtcNow))
            || tool == "ssl_certificates_cleanup_retry" && (certificate.Status != "Issued" || !certificate.AutoCleanup))
            return BusinessSnapshotDenied("INVALID_STATE");
        if (tool == "ssl_certificates_revoke" && BusinessText(input, "reason", "unspecified") is not
            ("unspecified" or "keyCompromise" or "caCompromise" or "affiliationChanged" or "superseded" or "cessationOfOperation"))
            return BusinessSnapshotDenied("INVALID_ARGUMENTS");
        var account = await db.CloudAccounts.AsNoTracking().SingleOrDefaultAsync(x => x.Id == certificate.AccountId && x.Enabled && x.UseForCertificates, ct);
        if (account is null) return BusinessSnapshotDenied();
        var domains = certificate.Domain.Split([',', ';', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(NormalizeDomain).Distinct(StringComparer.Ordinal).ToArray();
        if (domains.Length == 0 || domains.Any(name => !CertificateManagementService.IsValidDomain(name.StartsWith("*.", StringComparison.Ordinal) ? name[2..] : name)))
            return BusinessSnapshotDenied("INVALID_DOMAIN");
        var resources = domains.Select(domain => new McpResourceScope(certificate.AccountId, domain)).ToList();
        object? dnsSnapshot = null;
        if (certificate.DnsZoneId is { Length: > 0 } dnsId)
        {
            var zone = await db.Domains.AsNoTracking().SingleOrDefaultAsync(x => x.Id == dnsId && x.Status != "NotPresent", ct);
            if (zone is null || domains.Any(domain => !CertificateManagementService.BelongsTo(domain.TrimStart('*', '.'), zone.Name))) return BusinessSnapshotDenied("DNS_ZONE_MISMATCH");
            var dnsAccount = await db.CloudAccounts.AsNoTracking().SingleOrDefaultAsync(x => x.Id == zone.AccountId && x.Enabled && x.UseForDns, ct);
            if (dnsAccount is null) return BusinessSnapshotDenied();
            resources.AddRange(domains.Select(domain => new McpResourceScope(zone.AccountId, domain)));
            dnsSnapshot = new { zone.Id, zone.AccountId, zone.ZoneId, zone.Name, zone.Provider, account = BusinessAccountHash(dnsAccount) };
        }
        foreach (var resource in resources)
            if (!(await authorization.AuthorizeAsync(caller, tool, resource, false, ct)).Success) return BusinessSnapshotDenied("FORBIDDEN");
        var fingerprint = BusinessHash(new { certificate.Id, certificate.AccountId, certificate.Provider, certificate.Domain, certificate.CertificateId,
            certificate.OrderId, certificate.InstanceId, certificate.ApiVersion, certificate.Status, certificate.NotAfterUtc,
            certificate.ValidationMode, certificate.AutoCleanup, certificate.DnsZoneId, certificate.CleanupStatus,
            account = BusinessAccountHash(account), dnsSnapshot });
        var summary = JsonSerializer.Serialize(new { certificateId = id, accountId = certificate.AccountId, domains, provider = certificate.Provider,
            status = certificate.Status, action = tool, reason = tool == "ssl_certificates_revoke" ? BusinessText(input, "reason", "unspecified") : null }, Json);
        return ApiResult<BusinessSnapshot>.Ok(new(resources.Distinct().ToArray(), fingerprint, id, summary, id,
            BindingDigest: await CertificateManagementService.McpCertificateBindingHashAsync(db, certificate, ct)));
    }

    private async Task<BusinessExecution> ExecuteBusinessCoreAsync(McpOperation operation, string tool, JsonElement input, CancellationToken ct)
    {
        if (tool is "ssl_dns_records_create" or "ssl_dns_records_update" or "ssl_dns_records_delete" or "ssl_dns_records_status")
            return await ExecuteDnsBusinessAsync(operation, tool, input, ct);
        if (tool is "ssl_certificates_revoke" or "ssl_certificates_cancel" or "ssl_certificates_delete" or "ssl_certificates_cleanup_retry")
        {
            var result = await certificates.InvokeMaintenanceForMcpAsync(tool, BusinessText(input, "certificateId"), BusinessText(input, "reason", "unspecified"), operation.Id,
                async token =>
                {
                    var current = await BuildCertificateBusinessSnapshotAsync(Caller(operation), tool, input, token);
                    var expected = JsonSerializer.Deserialize<BusinessArguments>(operation.ArgumentsJson, Json)!;
                    return current.Success && current.Data?.ResourceDigest == expected.ResourceDigest ? await RecheckBusinessAuthorizationAsync(operation, token)
                        : ApiResult<bool>.Fail("MCP_RESOURCE_CHANGED", "原证书资源或配置变化，未提交维护操作。");
                }, ct);
            return new(result.Success, result.Code, result.Status, result.PublicResult);
        }
        if (tool is "ssl_domains_sync" or "ssl_certificates_sync")
        {
            var result = tool == "ssl_domains_sync" && businessDomains is not null
                ? await businessDomains.SyncForMcpAsync(BusinessText(input, "accountId"), token => RecheckBusinessAuthorizationAsync(operation, token), ct)
                : await certificates.SyncForMcpAsync(BusinessText(input, "accountId"), operation.Id, ct);
            return result.Success ? new(true, "OK", PublicResult: new { count = result.Data })
                : new(false, "SYNC_FAILED", "Failed");
        }
        return await ExecuteManagementBusinessAsync(operation, tool, input, ct);
    }

    private async Task<BusinessExecution> ExecuteDnsBusinessAsync(McpOperation operation, string tool, JsonElement input, CancellationToken ct)
    {
        if (businessDomains is null) return new(false, "MCP_SERVICE_UNAVAILABLE", "Blocked");
        var envelope = JsonSerializer.Deserialize<BusinessArguments>(operation.ArgumentsJson, Json)!;
        using var exactRecordBoundary = McpCloudMutationGuard.Enter(async token =>
        {
            // 云适配器内部也可能先读再写；实际HTTP mutation发送前再次核对精确记录，防止期间更名或换值。
            var fresh = await BuildDnsBusinessSnapshotAsync(Caller(operation), tool, input, token);
            if (!fresh.Success || fresh.Data?.ResourceDigest != envelope.ResourceDigest)
                throw new McpExecutionDeniedException(fresh.Success ? "MCP_RESOURCE_CHANGED" : fresh.Code, "原 DNS 记录或资源范围已经变化，未发送写入。");
        }, operation.Id);
        async Task<ApiResult<bool>> Guard(DomainManagementService.DnsContext context, DnsRecord? original, CancellationToken token)
        {
            if ((original is null ? "" : BusinessRecordHash(original)) != envelope.SourceRecordDigest)
                return ApiResult<bool>.Fail("MCP_RESOURCE_CHANGED", "原解析记录已变化，未写入。");
            var snapshot = await BuildDnsBusinessSnapshotAsync(Caller(operation), tool, input, token);
            if (!snapshot.Success || snapshot.Data?.ResourceDigest != envelope.ResourceDigest)
                return ApiResult<bool>.Fail(snapshot.Success ? "MCP_RESOURCE_CHANGED" : snapshot.Code, "原解析或账号配置已变化，未写入。");
            return await RecheckBusinessAuthorizationAsync(operation, token);
        }
        var zoneId = BusinessText(input, "zoneId"); var recordId = BusinessText(input, "recordId");
        if (tool is "ssl_dns_records_create" or "ssl_dns_records_update")
        {
            var zone = await db.Domains.AsNoTracking().SingleAsync(x => x.Id == zoneId, ct);
            var request = BusinessDnsRequest(input)!;
            var absolute = BusinessDnsName(request.Name, zone.Name);
            if (absolute.Length == 0) return new(false, "MCP_RESOURCE_CHANGED", "Blocked");
            // 腾讯/阿里接口的主机字段要求相对名称；统一相对后再交适配器，确保实际写入与授权的完整域名一致。
            var relative = absolute == NormalizeDomain(zone.Name) ? "@" : absolute[..^(NormalizeDomain(zone.Name).Length + 1)];
            request = request with { Name = relative };
            var result = await businessDomains.SaveRecordForMcpAsync(zoneId, tool == "ssl_dns_records_create" ? null : recordId, request, Guard, ct);
            if (!result.Success || result.Data is null) return DnsFailure(result.Code);
            return new(true, "OK", PublicResult: new { zoneId, recordId = result.Data.Id, name = BusinessDnsName(result.Data.Name, result.Data.Zone), type = result.Data.Type, ttl = result.Data.Ttl });
        }
        var changed = await businessDomains.ChangeRecordForMcpAsync(zoneId, recordId, tool == "ssl_dns_records_status" ? input.GetProperty("enabled").GetBoolean() : null, Guard, ct);
        return changed.Success ? new(true, "OK", PublicResult: new { zoneId, recordId }) : DnsFailure(changed.Code);
    }
    private static BusinessExecution DnsFailure(string code) => code is "FORBIDDEN" or "API_KEY_REVOKED" or "AUTHORIZATION_REVOKED" or "MCP_DISABLED" or "MCP_RESOURCE_CHANGED"
        ? new(false, code, "Blocked") : BusinessOutcomeUnknown(code) ? new(false, "RESULT_UNKNOWN", "Unknown") : new(false, "DNS_WRITE_FAILED", "Failed");
    private static bool BusinessOutcomeUnknown(string code) => new[] { "UNKNOWN", "TRANSPORT", "TIMEOUT", "HTTP", "NETWORK", "SOCKET", "CONNECTION" }
        .Any(word => code.Contains(word, StringComparison.OrdinalIgnoreCase));
    private static string BusinessAccountHash(CloudAccount account) => BusinessHash(new { account.Id, account.Provider, account.Enabled,
        account.UseForCertificates, account.UseForDns, account.ProtectedAccessKeyId, account.ProtectedAccessKeySecret,
        account.AcmeDirectoryUrl, account.AcmeAccountMode, account.AcmeRegistrationStatus, account.AliyunContactId, account.UpdatedAtUtc });
    private static string BusinessRecordHash(DnsRecord record) => BusinessHash(new { record.Id, record.Zone, record.Name, record.Type,
        record.Value, record.Ttl, record.Status, record.Line, record.Mx, record.Proxied });
    private static DnsRecordRequest? BusinessDnsRequest(JsonElement input)
    {
        var name = BusinessText(input, "name"); var value = BusinessText(input, "value"); var line = BusinessText(input, "line", "default");
        if (name.Length is < 1 or > 253 || value.Length is < 1 or > 4096 || line.Length > 100 || name.Any(char.IsControl) || value.Any(char.IsControl) || line.Any(char.IsControl)) return null;
        return new(name, BusinessText(input, "type"), value, BusinessNumber(input, "ttl", 600), line,
            input.TryGetProperty("mx", out var mx) ? mx.GetInt32() : null);
    }
    private static string BusinessDnsName(string name, string zone)
    {
        var explicitlyAbsolute = name.EndsWith(".", StringComparison.Ordinal);
        name = NormalizeDomain(name); zone = NormalizeDomain(zone);
        if (explicitlyAbsolute && name != zone && !name.EndsWith("." + zone, StringComparison.Ordinal)) return "";
        var absolute = name == "@" ? zone : name == zone || name.EndsWith("." + zone, StringComparison.Ordinal) ? name : name + "." + zone;
        return absolute.Length <= 253 && absolute.Split('.').All(label => label.Length is > 0 and <= 63
            && (label == "*" || Regex.IsMatch(label, "^[a-z0-9_][a-z0-9_-]*$", RegexOptions.CultureInvariant)))
            && CertificateManagementService.BelongsTo(absolute, zone) ? absolute : "";
    }
}
