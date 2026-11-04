using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Mcp;

public sealed partial class McpOperationService
{
    private Task<ApiResult<BusinessSnapshot>> BuildManagementSnapshotAsync(McpCallerContext caller, string tool, JsonElement input, CancellationToken ct) =>
        tool.StartsWith("ssl_schedules_", StringComparison.Ordinal) || tool.StartsWith("ssl_schedule_runs_", StringComparison.Ordinal)
            ? BuildScheduleManagementSnapshotAsync(caller, tool, input, ct) : BuildAdministrationSnapshotAsync(caller, tool, input, ct);

    private Task<BusinessExecution> ExecuteManagementBusinessAsync(McpOperation operation, string tool, JsonElement input, CancellationToken ct) =>
        tool.StartsWith("ssl_schedules_", StringComparison.Ordinal) || tool.StartsWith("ssl_schedule_runs_", StringComparison.Ordinal)
            ? ExecuteScheduleManagementAsync(operation, tool, input, ct) : ExecuteAdministrationBusinessAsync(operation, tool, input, ct);

    private async Task<ApiResult<BusinessSnapshot>> BuildScheduleManagementSnapshotAsync(McpCallerContext caller, string tool, JsonElement input, CancellationToken ct)
    {
        if (businessSchedules is not CertificateScheduleService concrete) return BusinessSnapshotDenied("MCP_SERVICE_UNAVAILABLE");
        CertificateSchedule? existing = null; CertificateScheduleRun? run = null; CertificateScheduleInput? settings = null;
        var id = BusinessText(input, "scheduleId");
        if (tool is "ssl_schedule_runs_resume" or "ssl_schedule_runs_resolve")
        {
            run = await db.CertificateScheduleRuns.AsNoTracking().SingleOrDefaultAsync(x => x.Id == BusinessText(input, "runId"), ct);
            if (run is null) return BusinessSnapshotDenied();
            id = run.ScheduleId;
            if (!run.Active || run.Status != "NeedsAttention" || run.LeaseUntilUtc > DateTime.UtcNow) return BusinessSnapshotDenied("CONFLICT");
            // 恢复会继续原有写入，不能借另一把 Key 接管旧调用方留下的任务。
            var sourceId = McpScheduleOrigin.ReadOperationId(run.ConfigSnapshotJson);
            if (tool == "ssl_schedule_runs_resume" && sourceId.Length > 0)
            {
                var source = await db.McpOperations.AsNoTracking().SingleOrDefaultAsync(x => x.Id == sourceId, ct);
                if (source is null || !SameCaller(source, caller)) return BusinessSnapshotDenied("FORBIDDEN");
            }
        }
        if (tool != "ssl_schedules_create")
        {
            existing = await db.CertificateSchedules.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
            if (existing is null) return BusinessSnapshotDenied();
        }
        if (tool is "ssl_schedules_create" or "ssl_schedules_update")
        {
            try { settings = input.GetProperty("schedule").Deserialize<CertificateScheduleInput>(Json); }
            catch (JsonException) { return BusinessSnapshotDenied("VALIDATION"); }
            if (settings is null || await concrete.ValidateInputAsync(settings, ct) is not null) return BusinessSnapshotDenied("VALIDATION");
            if (existing is not null && settings.ConfigRevision != existing.ConfigRevision) return BusinessSnapshotDenied("CONFLICT");
        }
        else if (existing is not null) settings = ScheduleInput(existing);
        if (settings is null) return BusinessSnapshotDenied("VALIDATION");
        var resources = await ScheduleManagementResourcesAsync(settings, id, ct);
        if (resources is null) return BusinessSnapshotDenied();
        if (existing is not null && tool == "ssl_schedules_update")
        {
            var oldResources = await ScheduleManagementResourcesAsync(ScheduleInput(existing), id, ct);
            if (oldResources is null) return BusinessSnapshotDenied();
            resources = resources.Concat(oldResources).Distinct().ToArray();
        }
        var targetIds = resources.Where(x => x.TargetId.Length > 0).Select(x => x.TargetId).Distinct().ToArray();
        var accountIds = resources.Where(x => x.AccountId.Length > 0).Select(x => x.AccountId).Distinct().ToArray();
        var targetsSnapshot = await db.DeploymentTargets.AsNoTracking().Where(x => targetIds.Contains(x.Id))
            .OrderBy(x => x.Id).Select(x => new { x.Id, x.Enabled, x.ConfigRevision }).ToArrayAsync(ct);
        var accountsSnapshot = await db.CloudAccounts.AsNoTracking().Where(x => accountIds.Contains(x.Id))
            .OrderBy(x => x.Id).Select(x => new { x.Id, x.Enabled, x.UpdatedAtUtc, x.ProtectedAccessKeyId, x.ProtectedAccessKeySecret }).ToArrayAsync(ct);
        var digest = BusinessHash(new { original = existing is null ? null : ScheduleInput(existing), targetsSnapshot, accountsSnapshot,
            run = run is null ? null : new { run.Id, run.Status, run.Active, run.LeaseToken, run.CertificateId, run.ConfigSnapshotJson, run.TargetsJson } });
        var summary = JsonSerializer.Serialize(new { scheduleId = id, runId = run?.Id, accountId = settings.AccountId, domain = settings.Domain,
            targetIds = settings.TargetIds, dnsZoneId = settings.DnsZoneId, intervalValue = settings.IntervalValue,
            intervalUnit = settings.IntervalUnit, enabled = settings.Enabled, revokeOldCertificates = settings.RevokeOldCertificates,
            impact = "启用计划将按此范围自动申请、部署及可选清理旧证书，后台逐写入边界继续核对原调用授权。" }, Json);
        return ApiResult<BusinessSnapshot>.Ok(new(resources, digest, run?.Id ?? id, summary));
    }

    private async Task<McpResourceScope[]?> ScheduleManagementResourcesAsync(CertificateScheduleInput input, string id, CancellationToken ct)
    {
        var resources = input.TargetIds.Select(target => new McpResourceScope(input.AccountId, NormalizeDomain(input.Domain), target, id)).ToList();
        if (resources.Count == 0) resources.Add(new(input.AccountId, NormalizeDomain(input.Domain), ScheduleId: id));
        if (!string.IsNullOrWhiteSpace(input.DnsZoneId))
        {
            var zone = await db.Domains.AsNoTracking().SingleOrDefaultAsync(x => x.Id == input.DnsZoneId && x.Status != "NotPresent", ct);
            if (zone is null || !CertificateManagementService.BelongsTo(input.Domain, zone.Name)) return null;
            resources.Add(new(zone.AccountId, NormalizeDomain(input.Domain), ScheduleId: id));
        }
        return resources.ToArray();
    }

    private async Task<BusinessExecution> ExecuteScheduleManagementAsync(McpOperation operation, string tool, JsonElement input, CancellationToken ct)
    {
        if (businessSchedules is null) return new(false, "MCP_SERVICE_UNAVAILABLE", "Failed");
        var id = BusinessText(input, "scheduleId");
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        ApiResult<CertificateScheduleView>? saved = null; ApiResult<CertificateScheduleRunView>? result = null;
        if (tool is "ssl_schedules_create" or "ssl_schedules_update")
        {
            var settings = input.GetProperty("schedule").Deserialize<CertificateScheduleInput>(Json)!;
            saved = await businessSchedules.SaveAsync(tool == "ssl_schedules_create" ? null : id, settings, operation.EffectiveUserId, ct);
        }
        else if (tool == "ssl_schedules_status") saved = await businessSchedules.SetEnabledAsync(id, input.GetProperty("enabled").GetBoolean(), ct);
        else if (tool == "ssl_schedules_run") result = await businessSchedules.RunNowAsync(id, ct);
        else if (tool == "ssl_schedule_runs_resume") result = await businessSchedules.ResumeRunAsync(BusinessText(input, "runId"), ct);
        else if (tool == "ssl_schedule_runs_resolve") result = await businessSchedules.ResolveRunAsync(BusinessText(input, "runId"), BusinessText(input, "note"), ct);
        else return new(false, "TOOL_NOT_FOUND", "Failed");
        if (saved is { Success: false }) return new(false, saved.Code, "Failed");
        if (result is { Success: false }) return new(false, result.Code, "Failed");
        if (saved?.Data is { } schedule)
        {
            // 与计划配置同事务绑定来源，Worker 不会看见已启用却缺少来源约束的中间状态。
            var resources = await ScheduleManagementResourcesAsync(schedule, schedule.Id, ct) ?? [];
            var snapshot = ReadResources(operation);
            operation.ResourceJson = JsonSerializer.Serialize(snapshot with { Resources = resources,
                SummaryJson = JsonSerializer.Serialize(new { request = JsonSerializer.Deserialize<JsonElement>(snapshot.SummaryJson), sourceConfigRevision = schedule.ConfigRevision }, Json) }, Json);
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            return new(true, "OK", PublicResult: new { scheduleId = schedule.Id, configRevision = schedule.ConfigRevision, schedule.Enabled });
        }
        if (result?.Data is { } run)
        {
            if (tool == "ssl_schedules_run")
            {
                var row = await db.CertificateScheduleRuns.SingleAsync(x => x.Id == run.Id, ct);
                row.ConfigSnapshotJson = McpScheduleOrigin.WriteOperationId(row.ConfigSnapshotJson, operation.Id);
                row.Status = "Pending"; row.Code = ""; row.Message = "本轮由已批准的 MCP 操作请求，执行时继续核对原调用授权。";
                await db.SaveChangesAsync(ct);
            }
            await transaction.CommitAsync(ct);
            return new(true, "OK", PublicResult: new { runId = run.Id, run.ScheduleId, run.CertificateId, run.Status, run.Active });
        }
        return new(false, "SYSTEM_ERROR", "Failed");
    }

    private static CertificateScheduleInput ScheduleInput(CertificateSchedule row) => CertificateScheduleService.ToScheduleInput(row);
}
