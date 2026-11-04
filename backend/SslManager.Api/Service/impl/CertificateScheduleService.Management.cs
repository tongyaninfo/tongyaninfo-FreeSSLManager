using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

public sealed partial class CertificateScheduleService
{
    public async Task<ApiResult<PageResult<CertificateScheduleView>>> ListAsync(int page, int pageSize, string? search, CancellationToken ct)
    {
        page = Math.Max(1, page); pageSize = Math.Clamp(pageSize, 1, 200);
        var query = db.CertificateSchedules.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var term = search.Trim();
            query = query.Where(x => x.Name.Contains(term) || x.Domain.Contains(term));
        }
        var total = await query.CountAsync(ct);
        var rows = await query.OrderByDescending(x => x.CreatedAtUtc).ThenBy(x => x.Id)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        var views = new List<CertificateScheduleView>();
        foreach (var row in rows) views.Add(await ToScheduleViewAsync(row, ct));
        return ApiResult<PageResult<CertificateScheduleView>>.Ok(new(views, total, page, pageSize));
    }

    public async Task<ApiResult<CertificateScheduleView>> GetAsync(string id, CancellationToken ct)
    {
        var row = await db.CertificateSchedules.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        return row is null ? ApiResult<CertificateScheduleView>.Fail("NOT_FOUND", "计划任务不存在")
            : ApiResult<CertificateScheduleView>.Ok(await ToScheduleViewAsync(row, ct));
    }

    public async Task<ApiResult<CertificateScheduleView>> SaveAsync(string? id, CertificateScheduleInput input, string userId, CancellationToken ct)
    {
        var validation = await ValidateInputAsync(input, ct);
        if (validation is not null) return ApiResult<CertificateScheduleView>.Fail("VALIDATION", validation);
        var row = id is null ? null : await db.CertificateSchedules.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (id is not null && row is null) return ApiResult<CertificateScheduleView>.Fail("NOT_FOUND", "计划任务不存在");
        if (row is not null && input.ConfigRevision != row.ConfigRevision)
            return ApiResult<CertificateScheduleView>.Fail("CONFLICT", "计划配置已变化，请刷新后重新编辑");
        if (input.Enabled && await db.CertificateSchedules.AnyAsync(x => x.Id != id && x.Enabled &&
                x.AccountId == input.AccountId && x.Domain == input.Domain, ct))
            return ApiResult<CertificateScheduleView>.Fail("CONFLICT", "同账号同域名已有启用的申请计划");
        // 已启动轮次保留快照；禁止在其运行时更换账号/域名，避免误解本轮处理的资产范围。
        if (row is not null && (row.AccountId != input.AccountId || row.Domain != input.Domain) &&
            await db.CertificateScheduleRuns.AnyAsync(x => x.ScheduleId == row.Id && x.Active, ct))
            return ApiResult<CertificateScheduleView>.Fail("CONFLICT", "当前轮次尚未结束，暂不能更换账号或域名");
        var now = DateTime.UtcNow;
        var first = CertificateScheduleTiming.EnsureUtc(input.FirstRunAtUtc);
        var timingChanged = row is null || row.FirstRunAtUtc != first || row.IntervalValue != input.IntervalValue || row.IntervalUnit != input.IntervalUnit;
        var reenabled = row is not null && !row.Enabled && input.Enabled;
        if (row is null)
        {
            row = new CertificateSchedule { Id = ids.NewId(), CreatedByUserId = userId, CreatedAtUtc = now };
            db.CertificateSchedules.Add(row);
        }
        else row.ConfigRevision++;
        row.Name = input.Name; row.AccountId = input.AccountId; row.Domain = input.Domain; row.Alias = input.Alias;
        row.ValidationMode = input.ValidationMode; row.AutoCleanup = input.AutoCleanup;
        row.DnsZoneId = input.DnsZoneId;
        row.RevokeOldCertificates = input.RevokeOldCertificates;
        row.TargetIdsJson = JsonSerializer.Serialize(input.TargetIds, Json);
        row.IntervalValue = input.IntervalValue; row.IntervalUnit = input.IntervalUnit;
        row.FirstRunAtUtc = first; row.Enabled = input.Enabled; row.UpdatedAtUtc = now;
        // 新建允许指定刚错过的执行点补跑一轮；修改周期和重新启用跳到原锚点的未来点。
        if (id is null) row.NextRunAtUtc = first;
        else if (timingChanged || reenabled)
            row.NextRunAtUtc = CertificateScheduleTiming.NextAfter(first, input.IntervalValue, input.IntervalUnit, now);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateConcurrencyException)
        { return ApiResult<CertificateScheduleView>.Fail("CONFLICT", "计划配置已被其他操作修改，请刷新后重试"); }
        catch (DbUpdateException exception) when (exception.InnerException is SqliteException { SqliteErrorCode: 19 })
        { return ApiResult<CertificateScheduleView>.Fail("CONFLICT", "同账号同域名已有启用的申请计划"); }
        return ApiResult<CertificateScheduleView>.Ok(await ToScheduleViewAsync(row, ct), "计划任务已保存");
    }

    public async Task<ApiResult<CertificateScheduleView>> SetEnabledAsync(string id, bool enabled, CancellationToken ct)
    {
        var row = await db.CertificateSchedules.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return ApiResult<CertificateScheduleView>.Fail("NOT_FOUND", "计划任务不存在");
        if (row.Enabled == enabled) return ApiResult<CertificateScheduleView>.Ok(await ToScheduleViewAsync(row, ct));
        if (enabled)
        {
            var input = ToScheduleInput(row);
            var validation = await ValidateInputAsync(input, ct);
            if (validation is not null) return ApiResult<CertificateScheduleView>.Fail("VALIDATION", validation);
            if (await db.CertificateSchedules.AnyAsync(x => x.Id != id && x.Enabled && x.AccountId == row.AccountId && x.Domain == row.Domain, ct))
                return ApiResult<CertificateScheduleView>.Fail("CONFLICT", "同账号同域名已有启用的申请计划");
            row.NextRunAtUtc = CertificateScheduleTiming.NextAfter(row.FirstRunAtUtc, row.IntervalValue, row.IntervalUnit, DateTime.UtcNow);
        }
        row.Enabled = enabled; row.ConfigRevision++; row.UpdatedAtUtc = DateTime.UtcNow;
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateConcurrencyException)
        { return ApiResult<CertificateScheduleView>.Fail("CONFLICT", "计划配置已变化，请刷新后重试"); }
        catch (DbUpdateException exception) when (exception.InnerException is SqliteException { SqliteErrorCode: 19 })
        { return ApiResult<CertificateScheduleView>.Fail("CONFLICT", "同账号同域名已有启用的申请计划"); }
        return ApiResult<CertificateScheduleView>.Ok(await ToScheduleViewAsync(row, ct), enabled ? "计划已启用" : "计划已停用，已提交的操作继续核对");
    }

    public async Task<ApiResult<PageResult<CertificateScheduleRunView>>> ListRunsAsync(string id, int page, int pageSize, CancellationToken ct)
    {
        if (!await db.CertificateSchedules.AnyAsync(x => x.Id == id, ct))
            return ApiResult<PageResult<CertificateScheduleRunView>>.Fail("NOT_FOUND", "计划任务不存在");
        page = Math.Max(1, page); pageSize = Math.Clamp(pageSize, 1, 200);
        var query = db.CertificateScheduleRuns.AsNoTracking().Where(x => x.ScheduleId == id);
        var total = await query.CountAsync(ct);
        var rows = await query.OrderByDescending(x => x.CreatedAtUtc).ThenBy(x => x.Id)
            .Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return ApiResult<PageResult<CertificateScheduleRunView>>.Ok(new(rows.Select(ToRunView).ToArray(), total, page, pageSize));
    }

    /// <summary>保存和实际开始前均检查自动 DNS 及明确目标，不在配置阶段调用云写入。</summary>
    internal async Task<string?> ValidateInputAsync(CertificateScheduleInput input, CancellationToken ct)
    {
        var structural = ValidateStructure(input);
        if (structural is not null) return structural;
        return await ValidateDependenciesAsync(input, ct);
    }

    /// <summary>导入只保存禁用计划，复用格式校验；启用和执行仍必须检查本地资产及目标。</summary>
    internal static string? ValidateStructure(CertificateScheduleInput input)
    {
        input.Name = input.Name?.Trim() ?? "";
        input.AccountId = input.AccountId?.Trim() ?? "";
        input.Domain = DeploymentSourceBinding.NormalizeDomain(input.Domain ?? "");
        input.Alias = input.Alias?.Trim() ?? "";
        if (input.Name.Length is < 1 or > 100 || input.Alias.Length > 100) return "任务名称和备注均不能超过 100 字，任务名称不能为空";
        if (!CertificateManagementService.IsValidDomain(input.Domain)) return "请输入有效的单个域名，不能使用 IP、泛域名或 URL";
        if (input.ValidationMode is not ("ManagedDns" or "NativeAutoDns")) return "无人值守计划仅支持自动 DNS 验证";
        if (input.IntervalValue is < 1 or > 1200 || input.IntervalUnit is not ("hour" or "day" or "month"))
            return "周期必须为每 1～1200 小时、天或月";
        if (input.FirstRunAtUtc == default || input.FirstRunAtUtc.Year < 2000 || input.FirstRunAtUtc.Year > 9000)
            return "请设置有效的首次执行时间";
        try { _ = CertificateScheduleTiming.NextAfter(input.FirstRunAtUtc, input.IntervalValue, input.IntervalUnit, DateTime.UtcNow); }
        catch (ArgumentOutOfRangeException) { return "首次执行时间或周期超出允许范围"; }
        if (input.TargetIds is not { Length: > 0 and <= 20 } || input.TargetIds.Any(string.IsNullOrWhiteSpace) || input.TargetIds.Distinct().Count() != input.TargetIds.Length)
            return "请选择 1～20 个不同的部署目标";
        return null;
    }

    private async Task<string?> ValidateDependenciesAsync(CertificateScheduleInput input, CancellationToken ct)
    {
        var account = await db.CloudAccounts.AsNoTracking().SingleOrDefaultAsync(x => x.Id == input.AccountId, ct);
        if (account is null || !account.Enabled || !account.UseForCertificates) return "证书账号不存在、已停用或未启用证书管理";
        if (account.Provider is not ("TencentCloud" or "Aliyun" or "Acme")) return "当前云账号不支持自动申请计划";
        if (account.Provider == "Acme" && account.AcmeDirectoryUrl.Contains("staging", StringComparison.Ordinal)) return "ACME 测试环境证书不能用于自动部署计划";
        if (account.Provider == "Acme" && input.ValidationMode != "ManagedDns") return "ACME 周期计划须使用系统自动 DNS 验证";
        {
            // null 保留历史同账号匹配；导入后的空字符串要求管理员重新绑定本地 DNS 区域。
            if (input.DnsZoneId == "") return "导入的 DNS 区域尚未映射，请同步域名并重新选择 DNS 托管区域";
            var dnsAccountId = input.AccountId;
            if (input.DnsZoneId is not null && input.ValidationMode == "ManagedDns")
            {
                var zone = await db.Domains.AsNoTracking().SingleOrDefaultAsync(x => x.Id == input.DnsZoneId && x.Status != "NotPresent", ct);
                if (zone is null || !CertificateManagementService.BelongsTo(input.Domain, zone.Name)) return "所选 DNS 托管区域不存在或不覆盖计划域名";
                dnsAccountId = zone.AccountId;
            }
            var dnsAccount = await db.CloudAccounts.AsNoTracking().SingleOrDefaultAsync(x => x.Id == dnsAccountId, ct);
            if (dnsAccount is null || !dnsAccount.Enabled || !dnsAccount.UseForDns) return "DNS 账号不存在、已停用或未启用 DNS 管理";
            var zones = await db.Domains.AsNoTracking().Where(x => x.AccountId == dnsAccountId && x.Status != "NotPresent")
                .Select(x => x.Name).ToListAsync(ct);
            if (!zones.Any(zone => CertificateManagementService.BelongsTo(input.Domain, DeploymentSourceBinding.NormalizeDomain(zone))))
                return "请先同步所选 DNS 账号的托管域，确保覆盖计划域名";
        }
        var selected = await db.DeploymentTargets.AsNoTracking().Where(x => input.TargetIds.Contains(x.Id)).ToListAsync(ct);
        if (selected.Count != input.TargetIds.Length || selected.Any(x => !x.Enabled)) return "部分部署目标不存在或已停用，请重新选择";
        foreach (var target in selected)
        {
            if (target.ExecutorKey is not ("linux.files.ssh.v1" or "synology.dsm.7.x" or "safeline.ce.9.x" or "harbor.compose.ssh.v1"))
                return "当前计划仅支持群晖、雷池、Linux 文件和 Harbor 部署目标";
            DeploymentTargetConfiguration? config;
            try { config = JsonSerializer.Deserialize<DeploymentTargetConfiguration>(target.ConfigurationJson, Json); }
            catch (JsonException) { return "部署目标配置无法读取，请重新保存目标"; }
            if (config is null) return "部署目标配置无法读取，请重新保存目标";
            // 文件目标与 Harbor 都固定业务域名，续签计划不能把其他域名的证书部署过去。
            if (target.ExecutorKey is ("linux.files.ssh.v1" or "harbor.compose.ssh.v1") &&
                DeploymentSourceBinding.NormalizeDomain(config.SourceDomain) != input.Domain)
                return "Linux 或 Harbor 部署目标必须绑定本计划的域名，请先保存目标的绑定域名";
        }
        return null;
    }

    internal static CertificateScheduleInput ToScheduleInput(CertificateSchedule row) => new()
    {
        Name = row.Name, AccountId = row.AccountId, Domain = row.Domain, Alias = row.Alias,
        ValidationMode = row.ValidationMode, AutoCleanup = row.AutoCleanup, RevokeOldCertificates = row.RevokeOldCertificates,
        DnsZoneId = row.DnsZoneId,
        TargetIds = JsonSerializer.Deserialize<string[]>(row.TargetIdsJson, Json) ?? [],
        IntervalValue = row.IntervalValue, IntervalUnit = row.IntervalUnit,
        FirstRunAtUtc = CertificateScheduleTiming.EnsureUtc(row.FirstRunAtUtc), Enabled = row.Enabled, ConfigRevision = row.ConfigRevision
    };

    private async Task<CertificateScheduleView> ToScheduleViewAsync(CertificateSchedule row, CancellationToken ct)
    {
        var latest = await db.CertificateScheduleRuns.AsNoTracking().Where(x => x.ScheduleId == row.Id)
            .OrderByDescending(x => x.CreatedAtUtc).ThenByDescending(x => x.Id).FirstOrDefaultAsync(ct);
        return new()
        {
            Id = row.Id, Name = row.Name, AccountId = row.AccountId,
            AccountName = await db.CloudAccounts.Where(x => x.Id == row.AccountId).Select(x => x.Name).FirstOrDefaultAsync(ct) ?? "已移除账号",
            Domain = row.Domain, Alias = row.Alias, ValidationMode = row.ValidationMode, AutoCleanup = row.AutoCleanup,
            DnsZoneId = row.DnsZoneId,
            RevokeOldCertificates = row.RevokeOldCertificates, TargetIds = JsonSerializer.Deserialize<string[]>(row.TargetIdsJson, Json) ?? [],
            IntervalValue = row.IntervalValue, IntervalUnit = row.IntervalUnit, Enabled = row.Enabled, ConfigRevision = row.ConfigRevision,
            FirstRunAtUtc = CertificateScheduleTiming.EnsureUtc(row.FirstRunAtUtc), NextRunAtUtc = CertificateScheduleTiming.EnsureUtc(row.NextRunAtUtc),
            CreatedAtUtc = CertificateScheduleTiming.EnsureUtc(row.CreatedAtUtc), UpdatedAtUtc = CertificateScheduleTiming.EnsureUtc(row.UpdatedAtUtc),
            LatestRun = latest is null ? null : ToRunView(latest)
        };
    }

    internal static CertificateScheduleRunView ToRunView(CertificateScheduleRun row) => new()
    {
        Id = row.Id, ScheduleId = row.ScheduleId, CertificateId = row.CertificateId,
        Status = row.Status, Code = row.Code, Message = row.Message, CleanupStatus = row.CleanupStatus, Active = row.Active,
        ApplicationCleanupStatus = Read<CertificateScheduleRunSnapshot>(row.ConfigSnapshotJson)?.ApplicationCleanupStatus ?? "NotRequested",
        ScheduledForUtc = CertificateScheduleTiming.EnsureUtc(row.ScheduledForUtc), CreatedAtUtc = CertificateScheduleTiming.EnsureUtc(row.CreatedAtUtc),
        StartedAtUtc = row.StartedAtUtc.HasValue ? CertificateScheduleTiming.EnsureUtc(row.StartedAtUtc.Value) : null,
        FinishedAtUtc = row.FinishedAtUtc.HasValue ? CertificateScheduleTiming.EnsureUtc(row.FinishedAtUtc.Value) : null,
        NextCheckAtUtc = CertificateScheduleTiming.EnsureUtc(row.NextCheckAtUtc),
        Targets = JsonSerializer.Deserialize<List<ScheduleTargetProgress>>(row.TargetsJson, Json) ?? [],
        // DNS 验证值和精确云端记录 ID 只用于后台恢复，运行列表只暴露脱敏业务进度。
        OldCertificates = (JsonSerializer.Deserialize<List<ScheduleCertificateCleanup>>(row.OldCertificatesJson, Json) ?? [])
            .Select(item => new ScheduleCertificateCleanup { CertificateId = item.CertificateId, Domain = item.Domain,
                Status = item.Status, Code = item.Code, Message = item.Message }).ToArray()
    };
}
