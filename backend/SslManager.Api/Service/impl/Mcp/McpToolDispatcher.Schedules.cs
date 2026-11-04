using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Mcp;

public sealed partial class McpToolDispatcher
{
    private async Task<IQueryable<CertificateSchedule>> AllowedSchedulesAsync(McpEffectivePermission permission, CancellationToken ct)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var rule in permission.Rules)
        {
            var targets = (await AllowedTargetIdsAsync(rule, ct)).ToHashSet(StringComparer.Ordinal);
            var candidates = await db.CertificateSchedules.AsNoTracking()
                .Where(McpQueryFilters.Build<CertificateSchedule>([rule], x => x.AccountId, x => x.Domain))
                .Select(x => new { x.Id, x.TargetIdsJson, x.DnsZoneId, x.Domain }).ToArrayAsync(ct);
            foreach (var candidate in candidates)
            {
                try
                {
                    var selected = JsonSerializer.Deserialize<string[]>(candidate.TargetIdsJson);
                    if (selected is null || !selected.All(targets.Contains)) continue;
                    // 跨账号 DNS 也是计划关联资源，须与证书及目标被同一条完整规则授权。
                    if (!string.IsNullOrEmpty(candidate.DnsZoneId))
                    {
                        var zone = await db.Domains.AsNoTracking().SingleOrDefaultAsync(x => x.Id == candidate.DnsZoneId && x.Status != "NotPresent", ct);
                        if (zone is null || !(rule.AllAccounts || rule.AccountIds.Contains(zone.AccountId))
                            || !McpQueryFilters.DomainMatches(candidate.Domain, rule)) continue;
                    }
                    ids.Add(candidate.Id);
                }
                catch (JsonException) { /* 不公开无法确认资源关联的计划。 */ }
            }
        }
        var allowed = ids.ToArray();
        return db.CertificateSchedules.AsNoTracking().Where(x => allowed.Contains(x.Id));
    }

    private async Task<ApiResult<object>> SchedulesAsync(McpEffectivePermission permission, JsonElement input, CancellationToken ct)
    {
        var query = await AllowedSchedulesAsync(permission, ct);
        var account = Text(input, "accountId"); var domain = Text(input, "domain");
        if (account.Length > 0) query = query.Where(x => x.AccountId == account);
        if (domain.Length > 0) query = query.Where(x => x.Domain == domain);
        return await PageAsync(query.OrderBy(x => x.Name).ThenBy(x => x.Id).Select(x => new
        { x.Id, x.Name, x.AccountId, x.Domain, x.Enabled, x.IntervalValue, x.IntervalUnit, x.NextRunAtUtc, x.ConfigRevision, x.DnsZoneId }), input, ct);
    }

    private async Task<ApiResult<object>> ScheduleAsync(McpEffectivePermission permission, string id, CancellationToken ct)
    {
        var query = await AllowedSchedulesAsync(permission, ct);
        var row = await query.Where(x => x.Id == id).Select(x => new
        { x.Id, x.Name, x.AccountId, x.Domain, x.Enabled, x.IntervalValue, x.IntervalUnit, x.FirstRunAtUtc,
            x.NextRunAtUtc, x.ValidationMode, x.AutoCleanup, x.RevokeOldCertificates, x.ConfigRevision, x.CreatedAtUtc,
            x.UpdatedAtUtc, x.TargetIdsJson, x.DnsZoneId }).SingleOrDefaultAsync(ct);
        return row is null ? Missing() : ApiResult<object>.Ok(new
        { row.Id, row.Name, row.AccountId, row.Domain, row.Enabled, row.IntervalValue, row.IntervalUnit,
            row.FirstRunAtUtc, row.NextRunAtUtc, row.ValidationMode, row.AutoCleanup, row.RevokeOldCertificates,
            row.ConfigRevision, row.CreatedAtUtc, row.UpdatedAtUtc, row.DnsZoneId, targetIds = JsonSerializer.Deserialize<string[]>(row.TargetIdsJson) });
    }

    private async Task<ApiResult<object>> ScheduleRunsAsync(McpEffectivePermission permission, JsonElement input, CancellationToken ct)
    {
        var id = Text(input, "scheduleId");
        var schedules = await AllowedSchedulesAsync(permission, ct);
        if (!await schedules.AnyAsync(x => x.Id == id, ct)) return Missing();
        var certificates = AllowedCertificates(permission);
        var query = db.CertificateScheduleRuns.AsNoTracking().Where(x => x.ScheduleId == id &&
            (x.CertificateId == "" || certificates.Any(certificate => certificate.Id == x.CertificateId)));
        return await PageAsync(query.OrderByDescending(x => x.CreatedAtUtc).ThenBy(x => x.Id).Select(x => new
        { x.Id, x.ScheduleId, x.CertificateId, x.Status, x.Code, x.CleanupStatus, x.ScheduledForUtc,
            x.CreatedAtUtc, x.StartedAtUtc, x.FinishedAtUtc, x.NextCheckAtUtc, x.Active }), input, ct);
    }
}
