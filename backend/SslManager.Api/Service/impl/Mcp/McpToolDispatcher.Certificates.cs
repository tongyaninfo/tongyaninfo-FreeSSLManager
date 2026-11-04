using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Mcp;

public sealed partial class McpToolDispatcher
{
    private Task<ApiResult<object>> AccountsAsync(McpEffectivePermission permission, JsonElement input, CancellationToken ct)
    {
        var query = db.CloudAccounts.AsNoTracking().Where(McpQueryFilters.Build<CloudAccount>(permission.Rules, account: x => x.Id));
        var provider = Text(input, "provider");
        if (provider.Length > 0) query = query.Where(x => x.Provider == provider);
        return PageAsync(query.OrderBy(x => x.Name).ThenBy(x => x.Id).Select(x => new
        {
            x.Id, x.Name, x.Provider, x.Enabled, x.UseForCertificates, x.UseForDns,
            // 只公开 CA 环境和注册状态，不公开账号 URL、联系信息或加密凭据。
            AcmeEnvironment = x.Provider == "Acme"
                ? x.AcmeDirectoryUrl == AcmeProtocolClient.StagingDirectory ? "Staging" : "Production" : "",
            AcmeRegistrationStatus = x.Provider == "Acme" ? x.AcmeRegistrationStatus : "",
            AcmeReady = x.Provider == "Acme" && (x.AcmeRegistrationStatus == "Provided" || x.AcmeRegistrationStatus == "Registered")
                && x.ProtectedAccessKeyId != "" && x.ProtectedAccessKeySecret != ""
        }), input, ct);
    }

    private Task<ApiResult<object>> DomainsAsync(McpEffectivePermission permission, JsonElement input, CancellationToken ct)
    {
        var query = db.Domains.AsNoTracking().Where(x => x.Status != "NotPresent")
            .Where(McpQueryFilters.Build<ManagedDomain>(permission.Rules, x => x.AccountId, x => x.Name));
        var account = Text(input, "accountId"); var search = Text(input, "search");
        if (account.Length > 0) query = query.Where(x => x.AccountId == account);
        if (search.Length > 0) query = query.Where(x => x.Name.Contains(search));
        return PageAsync(query.OrderBy(x => x.Name).ThenBy(x => x.Id).Select(x => new
        { x.Id, x.AccountId, x.Provider, x.Name, x.Status, x.SyncedAtUtc }), input, ct);
    }

    private IQueryable<ManagedCertificate> AllowedCertificates(McpEffectivePermission permission) => db.Certificates.AsNoTracking()
        .Where(McpQueryFilters.Build<ManagedCertificate>(permission.Rules, x => x.AccountId, x => x.Domain));

    private Task<ApiResult<object>> CertificatesAsync(McpEffectivePermission permission, JsonElement input, CancellationToken ct)
    {
        var query = AllowedCertificates(permission);
        var account = Text(input, "accountId"); var domain = Text(input, "domain"); var status = Text(input, "status");
        if (account.Length > 0) query = query.Where(x => x.AccountId == account);
        if (domain.Length > 0) { domain = McpQueryFilters.NormalizeDomain(domain); query = query.Where(x => x.Domain == domain); }
        if (status.Length > 0) query = query.Where(x => x.Status == status);
        return PageAsync(query.OrderByDescending(x => x.NotAfterUtc.HasValue).ThenByDescending(x => x.NotAfterUtc).ThenBy(x => x.Id)
            .Select(x => new { x.Id, x.AccountId, x.Provider, x.Domain, x.Alias, x.IsFree, x.Status,
                x.NotBeforeUtc, x.NotAfterUtc, x.CleanupStatus, x.SyncedAtUtc, x.IsStaging, x.HasPrivateKey,
                CanDeploy = x.Status == "Issued" && x.HasPrivateKey && !x.IsStaging }), input, ct);
    }

    private async Task<ApiResult<object>> CertificateAsync(McpEffectivePermission permission, string id, CancellationToken ct)
    {
        var certificate = await AllowedCertificates(permission).Where(x => x.Id == id).Select(x => new
        { x.Id, x.AccountId, x.Provider, x.Domain, x.Alias, x.Status, x.IsFree, x.NotBeforeUtc, x.NotAfterUtc,
            x.ValidationMode, x.AutoCleanup, x.CleanupStatus, x.SyncedAtUtc, x.IsStaging, x.HasPrivateKey,
            CanDeploy = x.Status == "Issued" && x.HasPrivateKey && !x.IsStaging }).SingleOrDefaultAsync(ct);
        if (certificate is null) return Missing();
        var jobs = await db.CertificateJobs.AsNoTracking().Where(x => x.CertificateId == id).OrderByDescending(x => x.CreatedAtUtc)
            .Take(20).Select(x => new { x.Id, x.Kind, x.Status, x.Attempts, x.CreatedAtUtc, x.NextRunAtUtc }).ToArrayAsync(ct);
        // 验证挑战只返回阶段与类型，避免把内部台账、恢复内容和原始云响应交给模型。
        var validations = await db.ValidationRecords.AsNoTracking().Where(x => x.CertificateId == id)
            .Select(x => new { x.Type, x.Status, x.IsPersistent }).ToArrayAsync(ct);
        return ApiResult<object>.Ok(new { certificate, jobs, validations });
    }

    private async Task<ApiResult<object>> DnsRecordsAsync(McpCallerContext caller, McpEffectivePermission permission, JsonElement input, CancellationToken ct)
    {
        var zoneId = Text(input, "zoneId");
        var zone = await db.Domains.AsNoTracking().SingleOrDefaultAsync(x => x.Id == zoneId && x.Status != "NotPresent", ct);
        if (zone is null) return Missing();
        var rules = permission.Rules.Where(rule => (rule.AllAccounts || rule.AccountIds.Contains(zone.AccountId)) && CoversZone(rule, zone.Name)).ToArray();
        if (rules.Length == 0) return Missing();
        // 只读取已保存且相交的托管域；实际记录仍按完整主机名逐条限制，子域授权不能读整个父域。
        var records = await domains.ListRecordsAsync(zone.Id, ct);
        if (!records.Success || records.Data is null) return Fail(records.Code, records.Message);
        if (records.Data.Count > 10000) return Fail("DNS_RECORD_LIMIT", "托管域记录过多，请通过管理页面查询。");
        // 云端读取可能耗时，返回之前重新检查撤销，不能沿用过期的请求权限快照。
        var current = await authorization.AuthorizeAsync(caller, "ssl_dns_records_list", null, false, ct);
        if (!current.Success || current.Data is null) return Fail(current.Code, current.Message);
        rules = current.Data.Rules.Where(rule => rule.AllAccounts || rule.AccountIds.Contains(zone.AccountId)).ToArray();
        var type = Text(input, "type"); var name = Text(input, "name");
        var filtered = records.Data.Where(record =>
        {
            var hostname = AbsoluteRecordName(record.Name, zone.Name);
            return hostname.Length > 0 && rules.Any(rule => McpQueryFilters.DomainMatches(hostname, rule));
        });
        if (type.Length > 0) filtered = filtered.Where(record => record.Type.Equals(type, StringComparison.OrdinalIgnoreCase));
        if (name.Length > 0) filtered = filtered.Where(record => AbsoluteRecordName(record.Name, zone.Name) == AbsoluteRecordName(name, zone.Name));
        var page = Number(input, "page", 1); var size = Number(input, "pageSize", 20);
        var rows = filtered.OrderBy(record => record.Name, StringComparer.Ordinal).ThenBy(record => record.Type, StringComparer.Ordinal).ToArray();
        return ApiResult<object>.Ok(new { items = rows.Skip((page - 1) * size).Take(size).Select(record => new
        { record.Id, record.Name, record.Type, record.Value, record.Ttl, record.Status, record.Line, record.Mx }), total = rows.Length, page, pageSize = size });
    }

    private async Task<ApiResult<object>> CertificateValidationsAsync(McpCallerContext caller, string id, CancellationToken ct)
    {
        if (certificateService is null) return Fail("MCP_SERVICE_UNAVAILABLE", "证书验证查询服务不可用。");
        var certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        if (certificate is null) return Missing();
        var scopes = certificate.Domain.Split([',', ';', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(domain => new McpResourceScope(certificate.AccountId, McpQueryFilters.NormalizeDomain(domain))).ToArray();
        if (scopes.Length == 0) return Missing();
        foreach (var scope in scopes)
            if (!(await authorization.AuthorizeAsync(caller, "ssl_certificates_validations_get", scope, false, ct)).Success) return Missing();
        var result = await certificateService.ReadValidationsForMcpAsync(id, ct);
        if (!result.Success || result.Data is null) return Fail("CERTIFICATE_VALIDATION_QUERY_FAILED", "验证资料查询未完成，请在 Web 核对原证书。");
        foreach (var scope in scopes)
            if (!(await authorization.AuthorizeAsync(caller, "ssl_certificates_validations_get", scope, false, ct)).Success) return Missing();
        var allowedDomains = scopes.Select(scope => scope.Domain.TrimStart('*', '.')).ToHashSet(StringComparer.Ordinal);
        var safe = result.Data.Where(challenge => allowedDomains.Contains(McpQueryFilters.NormalizeDomain(challenge.Domain).TrimStart('*', '.'))
            && challenge.Name.Length <= 253 && challenge.Value.Length <= 4096 && !challenge.Name.Any(char.IsControl)
            && challenge.Type is "TXT" or "CNAME" or "FILE" or "File" or "HTTP").ToArray();
        return ApiResult<object>.Ok(new { certificateId = id, items = safe });
    }

    private static string AbsoluteRecordName(string name, string zone)
    {
        var explicitlyAbsolute = name.EndsWith(".", StringComparison.Ordinal);
        name = McpQueryFilters.NormalizeDomain(name); zone = McpQueryFilters.NormalizeDomain(zone);
        if (name is "" or "@") return zone;
        if (name == zone || name.EndsWith("." + zone, StringComparison.Ordinal)) return name;
        // 供应商返回的绝对名称不得被重新拼接成区内记录，以免改变授权判定对象。
        return explicitlyAbsolute ? "" : name + "." + zone;
    }
    private static bool CoversZone(McpAllowRuleInput rule, string zone)
    {
        zone = McpQueryFilters.NormalizeDomain(zone);
        return rule.AllDomains || rule.Domains.Any(raw =>
        {
            var domain = McpQueryFilters.NormalizeDomain(raw).TrimStart('*', '.');
            return domain == zone || domain.EndsWith("." + zone, StringComparison.Ordinal) || McpQueryFilters.DomainMatches(zone, rule);
        });
    }

    private Task<ApiResult<object>> AlertsAsync(McpEffectivePermission permission, JsonElement input, CancellationToken ct)
    {
        var certificates = AllowedCertificates(permission);
        var query = db.CertificateExpiryAlerts.AsNoTracking().Where(alert => certificates.Any(certificate => certificate.Id == alert.CertificateId));
        var domain = Text(input, "domain"); var status = Text(input, "status");
        if (domain.Length > 0) query = query.Where(x => x.Domain == domain);
        if (status.Length > 0) query = query.Where(x => x.Status == status);
        return PageAsync(query.OrderBy(x => x.NotAfterUtc).ThenBy(x => x.Id).Select(x => new
        { x.Id, x.CertificateId, x.Domain, x.NotAfterUtc, x.Status, x.FirstDetectedAtUtc, x.LastAttemptAtUtc,
            x.NextReminderAtUtc, x.LastMailStatus }), input, ct);
    }
}
