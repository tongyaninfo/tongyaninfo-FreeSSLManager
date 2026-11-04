using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>吊销验证使用独立持久台账；只创建明确挑战，不覆盖已有记录，未知创建不取得删除权。</summary>
public sealed class CertificateRevocationDnsService(AppDbContext db, DomainManagementService domains)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public async Task<ApiResult<bool>> EnsureAsync(CertificateScheduleRun run, ScheduleCertificateCleanup item,
        CertificateScheduleInput config, IReadOnlyList<DnsChallenge> challenges, Func<CancellationToken, Task> saveProgress, CancellationToken ct)
    {
        if (!ValidConfiguration(item, config)) return Fail("REVOCATION_DNS_UNSUPPORTED", "吊销验证仅支持本计划域名的自动 DNS 配置。");
        if (challenges is not { Count: > 0 and <= 32 }) return Fail("REVOCATION_DNS_CHALLENGE_INVALID", "吊销验证缺少完整 DNS 挑战或数量超限。");
        var validated = new List<ScheduleRevocationDnsRecord>();
        foreach (var challenge in challenges)
        {
            var record = ValidateChallenge(config.Domain, challenge);
            if (record is null) return Fail("REVOCATION_DNS_CHALLENGE_INVALID", "吊销验证必须明确提供属于本计划域名的完整 TXT 或 CNAME 记录，不能猜测类型或位置。");
            validated.Add(record);
        }
        item.RevocationValidation ??= [];
        var current = new List<ScheduleRevocationDnsRecord>();
        foreach (var candidate in validated)
        {
            var record = item.RevocationValidation.FirstOrDefault(record => SameChallenge(record, candidate));
            if (record is null) { record = candidate; item.RevocationValidation.Add(record); }
            record.IsPersistent |= candidate.IsPersistent;
            if (!current.Contains(record)) current.Add(record);
        }
        foreach (var record in current)
        {
            var resolved = string.IsNullOrEmpty(record.ZoneId)
                ? await ResolveNewZoneAsync(config, record.Name, ct) : await ResolveStoredZoneAsync(config, record, ct);
            if (!resolved.Success || resolved.Data is null) return Fail(resolved.Code, resolved.Message);
            var context = resolved.Data;
            record.ZoneId = context.Domain.Id; record.ZoneName = Normalize(context.Domain.Name); record.AccountId = context.Account.Id;
            var listing = await context.Provider.ListRecordsAsync(context.Account, context.Domain.Name, ct);
            if (!listing.Success || listing.Data is null) return Waiting("正在等待 DNS 平台完整返回吊销验证记录。");
            var atName = listing.Data.Where(value => AbsoluteName(value.Name, record.ZoneName) == record.Name).ToArray();
            if ((record.Type == "CNAME" && atName.Any(value => !SameRecord(value, record))) ||
                (record.Type == "TXT" && atName.Any(value => value.Type.Equals("CNAME", StringComparison.OrdinalIgnoreCase))))
                return Fail("REVOCATION_DNS_CONFLICT", "吊销验证位置已有冲突的 CNAME 或其他记录，未覆盖任何 DNS。");
            var matches = atName.Where(value => SameRecord(value, record)).ToArray();
            if (matches.Length > 1) return Fail("REVOCATION_DNS_AMBIGUOUS", "存在多条相同吊销验证记录，不能随意选取记录 ID。");
            if (matches.Length == 1)
            {
                var matching = matches[0];
                if (!EnabledRecord(matching))
                {
                    record.RecordId = matching.Id; record.CreatedBySystem = false; record.Status = "Changed";
                    record.Code = "DNS_RECORD_NOT_ENABLED"; record.Message = "相同吊销验证记录未确认启用，未修改现有记录状态。";
                    await saveProgress(ct);
                    return Fail("REVOCATION_DNS_NOT_ENABLED", record.Message);
                }
                // 只有创建回执明确确认的同一记录 ID 保持所有权；崩溃和未知创建后看到同值也只复用。
                var owned = record.CreatedBySystem && record.Status == "Created" && record.RecordId == matching.Id;
                record.RecordId = matching.Id; record.CreatedBySystem = owned;
                record.Status = owned ? "Created" : "Reused"; record.Code = "";
                record.Message = owned ? "本轮创建的吊销验证记录已就绪。" : "复用已有吊销验证记录，后续不会自动删除。";
                await saveProgress(ct);
                continue;
            }
            if (record.Status is "Creating" or "CreationUnknown")
                return Waiting("已有创建意图结果尚未确认，只读核对，未重复创建。");
            if (record.Status != "Pending")
                return Fail("REVOCATION_DNS_RECORD_CHANGED", "已有吊销验证记录已消失或被修改，未重新创建或覆盖。");
            if (!await EnabledAsync(run, ct)) return Fail("SCHEDULE_DISABLED", "计划已停用，未创建吊销验证记录。");
            record.Status = "Creating"; record.Message = "DNS 创建意图已持久化，准备提交吊销验证记录。";
            await saveProgress(ct);
            if (!await EnabledAsync(run, ct)) return Fail("SCHEDULE_DISABLED", "计划已停用，未创建吊销验证记录。");
            ApiResult<DnsRecord> created;
            try
            {
                created = await context.Provider.CreateRecordAsync(context.Account, context.Domain.Name,
                    new(CertificateManagementService.RelativeName(record.Name, record.ZoneName), record.Type, record.Value), ct);
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                record.Status = "CreationUnknown"; record.CreatedBySystem = false; record.Code = "DNS_CREATION_UNKNOWN";
                record.Message = "DNS 创建结果未知，后续只查询同一挑战，不重复创建或认领删除权。";
                await saveProgress(ct);
                return Waiting(record.Message);
            }
            if (!created.Success || created.Data is null || string.IsNullOrWhiteSpace(created.Data.Id) || !SameRecord(created.Data, record) || !EnabledRecord(created.Data))
            {
                record.Status = !created.Success && !Uncertain(created.Code) ? "Pending" : "CreationUnknown";
                record.CreatedBySystem = false; record.Code = "DNS_CREATION_UNCONFIRMED";
                record.Message = "DNS 创建未取得完整确定回执，后续只读核对且不认领删除权。";
                await saveProgress(ct);
                return !created.Success && !Uncertain(created.Code) && !Retryable(created.Code)
                    ? Fail("REVOCATION_DNS_CREATE_FAILED", "DNS 平台拒绝吊销验证记录创建，请核对 DNS 账号权限及记录限制。") : Waiting(record.Message);
            }
            record.RecordId = created.Data.Id; record.CreatedBySystem = true; record.Status = "Created";
            record.Code = ""; record.Message = "本轮吊销验证记录已创建，等待证书平台验证。";
            await saveProgress(ct);
        }
        return ApiResult<bool>.Ok(true, "本轮明确提供的吊销验证记录已就绪。");
    }

    public async Task<ApiResult<bool>> CleanupAsync(CertificateScheduleRun run, ScheduleCertificateCleanup item,
        CertificateScheduleInput config, Func<CancellationToken, Task> saveProgress, CancellationToken ct)
    {
        if (!ValidConfiguration(item, config)) return Fail("REVOCATION_DNS_SCOPE_INVALID", "吊销验证清理范围与本计划域名不一致。");
        if (item.RevocationValidation is not { Count: > 0 }) return ApiResult<bool>.Ok(true, "没有本轮吊销验证记录需要清理。");
        var preserved = false;
        foreach (var record in item.RevocationValidation)
        {
            if (!ValidSnapshot(config, record)) return Fail("REVOCATION_DNS_SCOPE_INVALID", "吊销验证台账的域名、记录位置或类型不符合本计划范围，未执行删除。");
            if (record.Status == "Deleted") continue;
            if (!record.CreatedBySystem || record.IsPersistent || record.Status is "Changed" or "Protected" or "Preserved")
            {
                preserved = true;
                record.Status = record.Status == "Changed" ? "Changed" : "Preserved";
                record.Message = record.IsPersistent ? "持久验证记录按原标记保留。" : "记录不具备本轮明确创建的删除权，已安全保留。";
                await saveProgress(ct);
                continue;
            }
            var resolved = await ResolveStoredZoneAsync(config, record, ct);
            if (!resolved.Success || resolved.Data is null) return Fail(resolved.Code, resolved.Message);
            var context = resolved.Data;
            var listing = await context.Provider.ListRecordsAsync(context.Account, context.Domain.Name, ct);
            if (!listing.Success || listing.Data is null) return Waiting("等待 DNS 平台返回完整快照后再核对清理。");
            var matchingId = listing.Data.Where(value => value.Id == record.RecordId).ToArray();
            if (matchingId.Length == 0)
            { record.Status = "Deleted"; record.Code = ""; record.Message = "已确认本轮记录不存在。"; await saveProgress(ct); continue; }
            if (matchingId.Length != 1 || !SameRecord(matchingId[0], record) || !EnabledRecord(matchingId[0]))
            {
                record.Status = "Changed"; record.Code = "DNS_RECORD_CHANGED"; record.CreatedBySystem = false;
                record.Message = "原记录 ID 的名称、类型、值或启用状态已变化，已保留现场。";
                preserved = true; await saveProgress(ct); continue;
            }
            if (await ReferencedAsync(run, item, record, ct))
            {
                record.Status = "Protected"; record.Code = "DNS_RECORD_IN_USE";
                record.Message = "仍有其他验证记录或活跃轮次引用此 DNS，已保留。";
                preserved = true; await saveProgress(ct); continue;
            }
            // 原请求响应丢失后，只有完整读回仍证明精确 ID、内容、所有权和引用不变，才安全重试该 ID。
            if (record.Status is not ("Created" or "Deleting" or "DeletionUnknown") || string.IsNullOrWhiteSpace(record.RecordId))
                return Fail("REVOCATION_DNS_OWNERSHIP_UNCONFIRMED", "本轮 DNS 创建回执不完整，未执行删除。");
            if (!await EnabledAsync(run, ct)) return Fail("SCHEDULE_DISABLED", "计划已停用，未提交吊销验证 DNS 清理。");
            record.Status = "Deleting"; record.Message = "精确 DNS 删除意图已持久化。";
            await saveProgress(ct);
            // 保存等待期间可能出现新的使用者；在云调用前再次检查共享引用与停用状态。
            if (await ReferencedAsync(run, item, record, ct))
            {
                record.Status = "Protected"; record.Code = "DNS_RECORD_IN_USE"; record.Message = "清理前发现其他引用，已保留。";
                preserved = true; await saveProgress(ct); continue;
            }
            if (!await EnabledAsync(run, ct)) return Fail("SCHEDULE_DISABLED", "计划已停用，未提交吊销验证 DNS 清理。");
            var fresh = await context.Provider.ListRecordsAsync(context.Account, context.Domain.Name, ct);
            if (!fresh.Success || fresh.Data is null)
            {
                // 此执行者明确尚未调用删除；回滚到已创建状态，下轮仅重试读前置条件。
                record.Status = "Created"; record.Message = "DNS 前置查询暂不可用，本次尚未发送删除。";
                await saveProgress(ct); return Waiting(record.Message);
            }
            var finalIdentity = fresh.Data.Where(value => value.Id == record.RecordId).ToArray();
            if (finalIdentity.Length == 0)
            { record.Status = "Deleted"; record.Message = "清理前已确认原记录不存在。"; await saveProgress(ct); continue; }
            if (finalIdentity.Length != 1 || !SameRecord(finalIdentity[0], record) || !EnabledRecord(finalIdentity[0]))
            {
                record.Status = "Changed"; record.CreatedBySystem = false; record.Code = "DNS_RECORD_CHANGED";
                record.Message = "删除意图保存期间 DNS 记录发生变化，未执行删除，已保留现场。";
                preserved = true; await saveProgress(ct); continue;
            }
            if (await ReferencedAsync(run, item, record, ct))
            {
                record.Status = "Protected"; record.Code = "DNS_RECORD_IN_USE"; record.Message = "最终读回后发现其他引用，已保留。";
                preserved = true; await saveProgress(ct); continue;
            }
            if (!await EnabledAsync(run, ct)) return Fail("SCHEDULE_DISABLED", "计划已停用，未提交吊销验证 DNS 清理。");
            // 重新进入调用方的租约栅栏，不能在前置读取期间失去执行权后仍发出删除。
            await saveProgress(ct);
            ApiResult<CloudOperation> deleted;
            try { deleted = await context.Provider.DeleteRecordAsync(context.Account, context.Domain.Name, record.RecordId, ct); }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                record.Status = "DeletionUnknown"; record.Code = "DNS_DELETION_UNKNOWN";
                record.Message = "DNS 删除响应中断，后续只读确认记录是否消失。";
                await saveProgress(ct); return Waiting(record.Message);
            }
            record.Status = deleted.Success ? "Deleting" : Uncertain(deleted.Code) ? "DeletionUnknown" : "Created";
            record.Code = deleted.Success ? "" : "DNS_DELETION_UNCONFIRMED";
            record.Message = "DNS 删除已尝试，等待读回确认；只有精确身份和所有权仍匹配时才安全重试同一 ID。";
            await saveProgress(ct);
            return !deleted.Success && !Uncertain(deleted.Code) && !Retryable(deleted.Code)
                ? Fail("REVOCATION_DNS_DELETE_FAILED", "DNS 平台拒绝清理，请核对权限后重新核对已有结果。") : Waiting(record.Message);
        }
        return ApiResult<bool>.Ok(true, preserved ? "本轮拥有的临时 DNS 已处理，复用、持久、共享或已变化记录已安全保留。" : "本轮吊销验证临时 DNS 已全部清理。");
    }

    private async Task<ApiResult<DomainManagementService.DnsContext>> ResolveNewZoneAsync(CertificateScheduleInput config, string name, CancellationToken ct)
    {
        var candidates = await db.Domains.AsNoTracking().Where(zone => zone.Status != "NotPresent")
            .Join(db.CloudAccounts.AsNoTracking().Where(account => account.Enabled && account.UseForDns), zone => zone.AccountId,
                account => account.Id, (zone, account) => zone).ToListAsync(ct);
        candidates = candidates.Where(zone => CertificateManagementService.BelongsTo(name, Normalize(zone.Name))).ToList();
        var preferred = candidates.Where(zone => zone.AccountId == config.AccountId).ToArray();
        var pool = preferred.Length > 0 ? preferred : candidates.ToArray();
        if (pool.Length == 0) return ZoneFail("REVOCATION_DNS_ZONE_MISSING", "没有已启用 DNS 账号管理此吊销验证域名，请同步托管域。");
        var longest = pool.Max(zone => Normalize(zone.Name).Length);
        var selected = pool.Where(zone => Normalize(zone.Name).Length == longest).ToArray();
        if (selected.Length != 1) return ZoneFail("REVOCATION_DNS_ZONE_AMBIGUOUS", "存在同级 DNS 托管区域或多个可用账号，无法安全自动选择。");
        var resolved = await domains.ResolveAsync(selected[0].Id, ct);
        return resolved.Success ? resolved : ZoneFail("REVOCATION_DNS_ZONE_UNAVAILABLE", "已选 DNS 账号或托管区域当前不可用。");
    }

    private async Task<ApiResult<DomainManagementService.DnsContext>> ResolveStoredZoneAsync(CertificateScheduleInput config,
        ScheduleRevocationDnsRecord record, CancellationToken ct)
    {
        if (!ValidSnapshot(config, record) || string.IsNullOrEmpty(record.ZoneId) || string.IsNullOrEmpty(record.RecordId) && record.Status != "Pending" && record.Status != "Creating" && record.Status != "CreationUnknown")
            return ZoneFail("REVOCATION_DNS_SCOPE_INVALID", "吊销验证 DNS 台账的身份或区域信息不完整。");
        var zone = await db.Domains.AsNoTracking().SingleOrDefaultAsync(zone => zone.Id == record.ZoneId, ct);
        if (zone is null || zone.AccountId != record.AccountId || Normalize(zone.Name) != Normalize(record.ZoneName) ||
            !CertificateManagementService.BelongsTo(record.Name, Normalize(zone.Name)))
            return ZoneFail("REVOCATION_DNS_ZONE_CHANGED", "原 DNS 托管区域已变化，未向其他区域发送操作。");
        var context = await domains.ResolveAsync(zone.Id, ct);
        return context.Success ? context : ZoneFail("REVOCATION_DNS_ZONE_UNAVAILABLE", "原 DNS 账号或托管区域当前不可用。");
    }

    private async Task<bool> ReferencedAsync(CertificateScheduleRun run, ScheduleCertificateCleanup item, ScheduleRevocationDnsRecord record, CancellationToken ct)
    {
        var references = await db.ValidationRecords.AsNoTracking().Where(value => value.Status != "Deleted").ToListAsync(ct);
        if (references.Any(value =>
            (value.DnsZoneId is null || value.DnsZoneId == record.ZoneId) &&
            (value.RecordId == record.RecordId || Normalize(value.Type) == Normalize(record.Type) &&
                AbsoluteName(value.Name, record.ZoneName) == record.Name && SameValue(value.Value, record.Value, record.Type))))
            return true;
        var runs = await db.CertificateScheduleRuns.AsNoTracking().Where(other => other.Active)
            .Select(other => new { other.Id, other.OldCertificatesJson, other.ConfigSnapshotJson }).ToListAsync(ct);
        foreach (var other in runs)
        {
            List<ScheduleCertificateCleanup>? old;
            try { old = JsonSerializer.Deserialize<List<ScheduleCertificateCleanup>>(other.OldCertificatesJson, Json); }
            catch (JsonException) { return true; }
            // 申请验证行可能随旧证书被删除，仍须检查运行 JSON 中独立保存的申请清理台账。
            if (ApplicationConfigReferences(other.ConfigSnapshotJson, record)) return true;
            foreach (var cleanup in old ?? [])
            {
                if (cleanup.Status is not ("Deleted" or "Skipped") && ApplicationReferences(cleanup.ApplicationCleanup, record)) return true;
                if (other.Id == run.Id && cleanup.CertificateId == item.CertificateId || cleanup.Status is "Deleted" or "Skipped") continue;
                if (cleanup.RevocationValidation?.Any(value => value.Status != "Deleted" && value.AccountId == record.AccountId &&
                    Normalize(value.ZoneName) == Normalize(record.ZoneName) && (value.RecordId == record.RecordId || SameChallenge(value, record))) == true)
                    return true;
            }
        }
        return false;
    }

    private static bool ApplicationReferences(ScheduleApplicationDnsCleanup? application, ScheduleRevocationDnsRecord record) =>
        application?.Records.Any(value => value.Status != "Deleted" && value.ZoneId == record.ZoneId &&
            (value.RecordId == record.RecordId || value.Name == record.Name && value.Type == record.Type && value.Value == record.Value)) == true;

    private static bool ApplicationConfigReferences(string json, ScheduleRevocationDnsRecord record)
    {
        try
        {
            using var config = JsonDocument.Parse(json);
            return config.RootElement.ValueKind != JsonValueKind.Object ||
                config.RootElement.TryGetProperty("applicationCleanup", out var application) && application.ValueKind == JsonValueKind.Object &&
                ApplicationReferences(application.Deserialize<ScheduleApplicationDnsCleanup>(Json), record);
        }
        catch (JsonException) { return true; }
    }

    private Task<bool> EnabledAsync(CertificateScheduleRun run, CancellationToken ct) => db.CertificateSchedules.AsNoTracking()
        .AnyAsync(schedule => schedule.Id == run.ScheduleId && schedule.Enabled && run.Active, ct);

    private static bool ValidConfiguration(ScheduleCertificateCleanup item, CertificateScheduleInput config) =>
        config.ValidationMode is "ManagedDns" or "NativeAutoDns" && CertificateManagementService.IsValidDomain(Normalize(config.Domain)) &&
        Normalize(item.Domain) == Normalize(config.Domain);
    private static ScheduleRevocationDnsRecord? ValidateChallenge(string domain, DnsChallenge challenge)
    {
        var name = Normalize(challenge.Name); var type = challenge.Type?.Trim().ToUpperInvariant() ?? "";
        var authorizationDomain = Normalize(challenge.Domain);
        if (challenge.IsRelative || type is not ("TXT" or "CNAME") || !ValidName(name) ||
            !CertificateManagementService.BelongsTo(name, Normalize(domain)) ||
            // 云端可用托管根域表示验证授权域；完整记录名仍必须位于本计划的严格业务域名内。
            !string.IsNullOrEmpty(challenge.Domain) && (!CertificateManagementService.IsValidDomain(authorizationDomain) ||
                !CertificateManagementService.BelongsTo(Normalize(domain), authorizationDomain)) ||
            string.IsNullOrWhiteSpace(challenge.Value) || challenge.Value.Length > 4096 || challenge.Value.Any(char.IsControl)) return null;
        return new() { Domain = Normalize(domain), Name = name, Type = type, Value = challenge.Value, IsPersistent = challenge.IsPersistent };
    }
    private static bool ValidSnapshot(CertificateScheduleInput config, ScheduleRevocationDnsRecord record) =>
        Normalize(record.Domain) == Normalize(config.Domain) && record.Name == Normalize(record.Name) &&
        ValidName(record.Name) && CertificateManagementService.BelongsTo(record.Name, Normalize(config.Domain)) &&
        record.Type is "TXT" or "CNAME" && !string.IsNullOrWhiteSpace(record.Value) && record.Value.Length <= 4096 && !record.Value.Any(char.IsControl);
    private static bool ValidName(string name) => name.Length is > 0 and <= 253 && name.Contains('.') &&
        name.Split('.').All(label => label.Length is > 0 and <= 63 && Regex.IsMatch(label, "^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$"));
    private static bool SameRecord(DnsRecord value, ScheduleRevocationDnsRecord expected) =>
        AbsoluteName(value.Name, expected.ZoneName) == expected.Name && value.Type.Equals(expected.Type, StringComparison.OrdinalIgnoreCase) &&
        SameValue(value.Value, expected.Value, expected.Type);
    private static bool EnabledRecord(DnsRecord value) => value.Status.Equals("Enabled", StringComparison.OrdinalIgnoreCase);
    private static bool SameChallenge(ScheduleRevocationDnsRecord first, ScheduleRevocationDnsRecord second) =>
        Normalize(first.Name) == Normalize(second.Name) && first.Type.Equals(second.Type, StringComparison.OrdinalIgnoreCase) && SameValue(first.Value, second.Value, first.Type);
    private static bool SameValue(string first, string second, string type) => type.Equals("CNAME", StringComparison.OrdinalIgnoreCase)
        ? Normalize(first) == Normalize(second) : first.Equals(second, StringComparison.Ordinal);
    private static string AbsoluteName(string name, string zone)
    {
        var value = Normalize(name); var root = Normalize(zone);
        return value == "@" ? root : value == root || value.EndsWith("." + root, StringComparison.Ordinal) ? value : value + "." + root;
    }
    private static string Normalize(string? value) => DeploymentSourceBinding.NormalizeDomain(value);
    private static bool Uncertain(string code) => new[] { "UNKNOWN", "TRANSPORT", "TIMEOUT", "NETWORK", "SOCKET", "CONNECTION", "SYSTEM", "HTTP" }
        .Any(value => code.Contains(value, StringComparison.OrdinalIgnoreCase));
    private static bool Retryable(string code) => new[] { "THROTTL", "LIMIT", "BUSY", "TEMPORAR", "UNAVAILABLE", "SERVICEERROR" }
        .Any(value => code.Contains(value, StringComparison.OrdinalIgnoreCase));
    private static ApiResult<bool> Waiting(string message) => ApiResult<bool>.Ok(false, message);
    private static ApiResult<bool> Fail(string code, string message) => ApiResult<bool>.Fail(code, message);
    private static ApiResult<DomainManagementService.DnsContext> ZoneFail(string code, string message) => ApiResult<DomainManagementService.DnsContext>.Fail(code, message);
}
