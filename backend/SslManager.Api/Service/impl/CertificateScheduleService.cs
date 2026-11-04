using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>按持久化阶段推进一轮申请、部署和旧证书清理；未知写入只核对，不自动重放。</summary>
public sealed partial class CertificateScheduleService : ICertificateScheduleService
{
    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly AppDbContext db;
    private readonly CertificateManagementService certificates;
    private readonly ICloudAccountStore accounts;
    private readonly ICloudProviderResolver providers;
    private readonly IDeploymentService deployments;
    private readonly IDeploymentTargetService targets;
    private readonly IIdGenerator ids;
    private readonly ILogger<CertificateScheduleService> logger;
    private readonly IServiceScopeFactory? scopes;
    private readonly CertificateRevocationDnsService revocationDns;

    public CertificateScheduleService(AppDbContext db, CertificateManagementService certificates, ICloudAccountStore accounts,
        ICloudProviderResolver providers, IDeploymentService deployments, IDeploymentTargetService targets, IIdGenerator ids,
        ILogger<CertificateScheduleService>? logger = null, IServiceScopeFactory? scopes = null,
        CertificateRevocationDnsService? revocationDns = null)
    {
        this.db = db; this.certificates = certificates; this.accounts = accounts; this.providers = providers;
        this.deployments = deployments; this.targets = targets; this.ids = ids;
        this.logger = logger ?? NullLogger<CertificateScheduleService>.Instance; this.scopes = scopes;
        this.revocationDns = revocationDns ?? new(db, new DomainManagementService(db, accounts, providers, ids));
    }

    public async Task<ApiResult<CertificateScheduleRunView>> RunNowAsync(string id, CancellationToken ct)
    {
        var schedule = await db.CertificateSchedules.AsNoTracking().SingleOrDefaultAsync(item => item.Id == id, ct);
        if (schedule is null) return ApiResult<CertificateScheduleRunView>.Fail("NOT_FOUND", "计划任务不存在。");
        if (!schedule.Enabled) return ApiResult<CertificateScheduleRunView>.Fail("SCHEDULE_DISABLED", "请先启用计划，再立即执行。");
        if (await db.CertificateScheduleRuns.AnyAsync(item => item.ScheduleId == id && item.Active, ct))
            return ApiResult<CertificateScheduleRunView>.Fail("RUN_ACTIVE", "本计划已有未结束或待核对轮次。");
        var run = CreateRun(schedule, "manual:" + ids.NewId(), DateTime.UtcNow);
        db.CertificateScheduleRuns.Add(run);
        Audit(run, "ScheduleRunRequested", "MANUAL", "已请求立即执行，周期锚点保持不变。");
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException) { db.ChangeTracker.Clear(); return ApiResult<CertificateScheduleRunView>.Fail("RUN_ACTIVE", "另一请求已创建本轮任务，请刷新。"); }
        return ApiResult<CertificateScheduleRunView>.Ok(ToRunView(run), "本轮已排队，后台将按已授权配置申请和部署。");
    }

    public async Task<ApiResult<CertificateScheduleRunView>> ResumeRunAsync(string runId, CancellationToken ct)
    {
        var run = await db.CertificateScheduleRuns.SingleOrDefaultAsync(item => item.Id == runId, ct);
        if (run is null) return ApiResult<CertificateScheduleRunView>.Fail("NOT_FOUND", "运行记录不存在。");
        if (!run.Active || run.Status != "NeedsAttention" || run.LeaseUntilUtc > DateTime.UtcNow)
            return ApiResult<CertificateScheduleRunView>.Fail("CONFLICT", "仅空闲的待核对轮次可以重新核对。");
        if (string.IsNullOrEmpty(run.CertificateId))
            return ApiResult<CertificateScheduleRunView>.Fail("MANUAL_RESOLUTION_REQUIRED", "本轮没有可核对的申请记录，请确认云端结果后结束本轮；不会重新申请。");
        var progress = Read<List<ScheduleTargetProgress>>(run.TargetsJson) ?? [];
        run.Status = progress.Count > 0 && progress.All(TargetSucceeded) ? "CleaningOldCertificates"
            : progress.Any(item => item.BatchId.Length > 0 || item.Status != "Pending") ? "Deploying" : "WaitingForIssuance";
        run.NextCheckAtUtc = DateTime.UtcNow;
        run.Code = "RECHECK_REQUESTED"; run.Message = "重新核对本轮已有证书、部署和清理结果，不重发未知操作。";
        run.LeaseToken = ids.NewId();
        Audit(run, "ScheduleRunRecheck", run.Code, run.Message);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateConcurrencyException) { return ApiResult<CertificateScheduleRunView>.Fail("CONFLICT", "运行状态已变化，请刷新。"); }
        return ApiResult<CertificateScheduleRunView>.Ok(ToRunView(run));
    }

    public async Task<ApiResult<CertificateScheduleRunView>> ResolveRunAsync(string runId, string note, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(note) || note.Length > 1000)
            return ApiResult<CertificateScheduleRunView>.Fail("VALIDATION", "请填写 1 至 1000 字的人工核对说明。");
        var run = await db.CertificateScheduleRuns.SingleOrDefaultAsync(item => item.Id == runId, ct);
        if (run is null) return ApiResult<CertificateScheduleRunView>.Fail("NOT_FOUND", "运行记录不存在。");
        if (!run.Active || run.Status != "NeedsAttention" || run.LeaseUntilUtc > DateTime.UtcNow)
            return ApiResult<CertificateScheduleRunView>.Fail("CONFLICT", "只能结束空闲的待核对轮次。");
        run.Status = "Resolved"; run.Active = false; run.FinishedAtUtc = DateTime.UtcNow;
        run.Code = "MANUALLY_RESOLVED"; run.Message = "管理员核对后结束本轮：" + note.Trim();
        run.LeaseToken = ids.NewId(); run.LeaseUntilUtc = null;
        Audit(run, "ScheduleRunResolved", run.Code, run.Message);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        try { await AdvanceScheduleAfterRunAsync(run.ScheduleId, ct); await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct); }
        catch (DbUpdateConcurrencyException) { return ApiResult<CertificateScheduleRunView>.Fail("CONFLICT", "运行状态已变化，请刷新。"); }
        return ApiResult<CertificateScheduleRunView>.Ok(ToRunView(run), "已结束本轮；已有证书及部署批次保留，不重放未知动作。");
    }

    public async Task<bool> ProcessNextAsync(CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        // 仅恢复旧版因额外吊销验证暂停的已授权轮次；后续仍验证当前部署状态，绝不重新申请或重发吊销。
        await db.CertificateScheduleRuns.Where(item => item.Active && item.Status == "NeedsAttention" &&
                item.Code == "ADDITIONAL_REVOKE_VALIDATION" && item.CertificateId != "" &&
                (item.LeaseUntilUtc == null || item.LeaseUntilUtc <= now) &&
                db.CertificateSchedules.Any(schedule => schedule.Id == item.ScheduleId && schedule.Enabled &&
                    (schedule.ValidationMode == "ManagedDns" || schedule.ValidationMode == "NativeAutoDns")))
            .ExecuteUpdateAsync(update => update.SetProperty(item => item.Status, "CleaningOldCertificates")
                .SetProperty(item => item.CleanupStatus, "Running").SetProperty(item => item.Code, "REVOKE_DNS_RESUMED")
                .SetProperty(item => item.Message, "正在恢复本轮已有吊销验证，不重新申请、部署或提交吊销。")
                .SetProperty(item => item.NextCheckAtUtc, now).SetProperty(item => item.LeaseToken, ""), ct);
        await EnqueueDueAsync(now, ct);
        var candidate = await db.CertificateScheduleRuns.AsNoTracking().Where(item => item.Active &&
            (item.Status != "NeedsAttention" || AutomaticRecoveryCodes.Contains(item.Code)) &&
            item.NextCheckAtUtc <= now && (item.LeaseUntilUtc == null || item.LeaseUntilUtc <= now))
            .OrderBy(item => item.NextCheckAtUtc).ThenBy(item => item.CreatedAtUtc).Select(item => item.Id).FirstOrDefaultAsync(ct);
        if (candidate is null) return false;
        var token = ids.NewId();
        var claimed = await db.CertificateScheduleRuns.Where(item => item.Id == candidate && item.Active &&
                (item.Status != "NeedsAttention" || AutomaticRecoveryCodes.Contains(item.Code)) &&
                item.NextCheckAtUtc <= now && (item.LeaseUntilUtc == null || item.LeaseUntilUtc <= now))
            .ExecuteUpdateAsync(update => update.SetProperty(item => item.LeaseToken, token)
                .SetProperty(item => item.LeaseUntilUtc, now.AddMinutes(5)), ct);
        if (claimed != 1) return true;
        db.ChangeTracker.Clear();
        var run = await db.CertificateScheduleRuns.SingleAsync(item => item.Id == candidate, ct);
        using var operation = CancellationTokenSource.CreateLinkedTokenSource(ct);
        operation.CancelAfter(TimeSpan.FromMinutes(4));
        using var heartbeatStop = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var heartbeat = HeartbeatAsync(run.Id, token, operation, heartbeatStop.Token);
        try
        {
            run.StartedAtUtc ??= now;
            if (run.Status == "NeedsAttention")
            {
                run.Status = RecoveryStage(run);
                if (run.Status == "CleaningOldCertificates") run.CleanupStatus = "Running";
                run.Message = "正在自动核对并继续原轮次，不重新申请证书。";
                Audit(run, "ScheduleRunAutoRecovery", "AUTO_RECOVERING", run.Message);
                await SaveRunAsync(run, token, operation.Token);
            }
            await AdvanceAsync(run, token, operation.Token);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (DbUpdateConcurrencyException) { /* 租约已被接管，旧执行者不写回状态。 */ }
        catch (Exception exception)
        {
            logger.LogWarning("周期任务推进中断，运行={RunId}，异常类型={ExceptionType}", run.Id, exception.GetType().Name);
            db.ChangeTracker.Clear();
            var current = await db.CertificateScheduleRuns.SingleOrDefaultAsync(item => item.Id == candidate && item.Active && item.LeaseToken == token, CancellationToken.None);
            if (current is not null)
                await RetryRunAsync(current, token, "SCHEDULE_STEP_INTERRUPTED", "本轮操作中断，后台将从已保存阶段核对并继续；不重发未知操作。", CancellationToken.None);
        }
        finally
        {
            heartbeatStop.Cancel();
            try { await heartbeat; } catch (OperationCanceledException) { }
            await db.CertificateScheduleRuns.Where(item => item.Id == candidate && item.LeaseToken == token)
                .ExecuteUpdateAsync(update => update.SetProperty(item => item.LeaseUntilUtc, (DateTime?)null)
                    .SetProperty(item => item.LeaseToken, ""), CancellationToken.None);
        }
        return true;
    }

    private async Task EnqueueDueAsync(DateTime now, CancellationToken ct)
    {
        var schedule = await db.CertificateSchedules.AsNoTracking().Where(item => item.Enabled && item.NextRunAtUtc <= now &&
            !db.CertificateScheduleRuns.Any(run => run.ScheduleId == item.Id && run.Active))
            .OrderBy(item => item.NextRunAtUtc).FirstOrDefaultAsync(ct);
        if (schedule is null) return;
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var due = schedule.NextRunAtUtc;
        var next = CertificateScheduleTiming.NextAfter(schedule.FirstRunAtUtc, schedule.IntervalValue, schedule.IntervalUnit, now);
        var changed = await db.CertificateSchedules.Where(item => item.Id == schedule.Id && item.Enabled && item.ConfigRevision == schedule.ConfigRevision &&
                item.NextRunAtUtc == due && !db.CertificateScheduleRuns.Any(run => run.ScheduleId == item.Id && run.Active))
            .ExecuteUpdateAsync(update => update.SetProperty(item => item.NextRunAtUtc, next), ct);
        if (changed != 1) return;
        var run = CreateRun(schedule, "scheduled:" + due.Ticks, due);
        db.CertificateScheduleRuns.Add(run);
        Audit(run, "ScheduleRunRequested", "SCHEDULED", "周期已到，已保存本轮执行记录；停机错过多个周期只补一轮。");
        try { await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct); }
        catch (DbUpdateException) { await transaction.RollbackAsync(ct); db.ChangeTracker.Clear(); }
    }

    private CertificateScheduleRun CreateRun(CertificateSchedule schedule, string trigger, DateTime scheduledFor)
    {
        var input = ToScheduleInput(schedule);
        return new()
        {
            Id = ids.NewId(), ScheduleId = schedule.Id, TriggerKey = trigger, ConfigSnapshotJson = JsonSerializer.Serialize(input, Json),
            TargetsJson = JsonSerializer.Serialize(input.TargetIds.Select(id => new ScheduleTargetProgress { TargetId = id }).ToArray(), Json),
            ScheduledForUtc = scheduledFor, CreatedAtUtc = DateTime.UtcNow, NextCheckAtUtc = DateTime.UtcNow,
            CleanupStatus = input.RevokeOldCertificates ? "Pending" : "Disabled"
        };
    }

    private async Task AdvanceAsync(CertificateScheduleRun run, string token, CancellationToken ct)
    {
        await FenceAsync(run, token, ct);
        var input = Read<CertificateScheduleRunSnapshot>(run.ConfigSnapshotJson) ?? throw new InvalidOperationException("周期配置快照缺失。");
        if (input.RecoveryVersion != 1)
        { await AttentionAsync(run, token, "RECOVERY_VERSION_UNSUPPORTED", "本轮恢复快照版本不受当前程序支持，保留原记录等待处理。", ct); return; }
        if (run.Status is "Pending" or "Applying") { await ApplyAsync(run, input, token, ct); return; }
        if (run.Status == "WaitingForIssuance") { await WaitForIssuanceAsync(run, input, token, ct); return; }
        if (run.Status == "Deploying") { await DeployAsync(run, input, token, ct); return; }
        if (run.Status == "CleaningOldCertificates") { await CleanupAsync(run, input, token, ct); return; }
        await AttentionAsync(run, token, "UNKNOWN_STAGE", "本轮阶段无法识别，请人工核对。", ct);
    }

    private async Task ApplyAsync(CertificateScheduleRun run, CertificateScheduleInput input, string token, CancellationToken ct)
    {
        if (!await EnabledAsync(run.ScheduleId, ct)) { await FinishAsync(run, token, "Cancelled", "SCHEDULE_DISABLED", "计划已停用，未提交申请。", ct); return; }
        if (!string.IsNullOrEmpty(run.CertificateId))
        {
            run.Status = "WaitingForIssuance"; await SaveRunAsync(run, token, ct); return;
        }
        var validation = await ValidateInputAsync(input, ct);
        if (validation is not null) { await AttentionAsync(run, token, "CONFIGURATION_INVALID", validation, ct); return; }
        if (run.Status == "Pending")
        {
            var targetSnapshots = await db.DeploymentTargets.AsNoTracking().Where(target => input.TargetIds.Contains(target.Id))
                .ToDictionaryAsync(target => target.Id, target => new { target.Name, target.ConfigRevision }, ct);
            var targetProgress = Read<List<ScheduleTargetProgress>>(run.TargetsJson) ?? [];
            foreach (var target in targetProgress)
            {
                target.TargetName = targetSnapshots.TryGetValue(target.TargetId, out var original) ? original.Name : target.TargetId;
                target.ConfigRevision = original?.ConfigRevision ?? 0;
            }
            run.TargetsJson = JsonSerializer.Serialize(targetProgress, Json);
            var old = await db.Certificates.AsNoTracking().Where(item => item.AccountId == input.AccountId &&
                !item.IsStaging &&
                (item.Status == "Issued" || item.Status == "Expired" || item.Status == "Revoked"))
                .Select(item => new { item.Id, item.Domain }).ToListAsync(ct);
            run.OldCertificatesJson = JsonSerializer.Serialize(old.Where(item =>
                DeploymentSourceBinding.NormalizeDomain(item.Domain) == input.Domain)
                .Select(item => new ScheduleCertificateCleanup { CertificateId = item.Id, Domain = input.Domain }).ToArray(), Json);
            run.Status = "Applying"; run.Message = "已固定申请前的旧证书候选集合，准备提交本轮申请。";
            await SaveRunAsync(run, token, ct);
        }
        var account = await accounts.GetCredentialsAsync(input.AccountId, ct);
        if (!account.Success || account.Data is null) { await FailureOrRetryAsync(run, token, account.Code, "证书账号暂不可用，请检查账号状态。", ct); return; }
        IReadOnlyList<string>? freeInstances = null;
        if (account.Data.Provider == "Aliyun")
        {
            var provider = providers.ResolveCertificate(account.Data.Provider);
            if (!provider.Success || provider.Data is null) { await AttentionAsync(run, token, "PROVIDER_UNAVAILABLE", "证书平台不可用。", ct); return; }
            var options = await provider.Data.ListAliyunInstancesAsync(account.Data, ct);
            if (!options.Success)
            { await FailureOrRetryAsync(run, token, options.Code, "暂时无法查询原账号的免费测试实例，未购买或提交申请。", ct); return; }
            if (options.Data is null || options.Data.Count == 0)
            { await AttentionAsync(run, token, "FREE_INSTANCE_UNAVAILABLE", "没有可用的已领取免费测试实例；未购买或提交申请。", ct); return; }
            freeInstances = options.Data.Select(item => item.InstanceId).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        }
        await FenceAsync(run, token, ct);
        var result = await certificates.ApplyForScheduleAsync(new(input.AccountId, input.Domain, input.Alias,
            input.ValidationMode, input.AutoCleanup, input.DnsZoneId), run.Id, token, freeInstances, ct);
        await db.Entry(run).ReloadAsync(ct);
        if (!result.Success)
        {
            var local = string.IsNullOrEmpty(run.CertificateId) ? null : await db.Certificates.AsNoTracking().SingleOrDefaultAsync(item => item.Id == run.CertificateId, ct);
            if (local?.Status == "Failed") await FinishAsync(run, token, "Failed", SafeCode(result.Code), "本轮申请已明确失败，未执行部署。", ct);
            else await AttentionAsync(run, token, SafeCode(result.Code), "本轮申请未能确认成功，请核对申请记录和云端状态；不会重复申请。", ct);
            return;
        }
        run.Status = "WaitingForIssuance"; run.Code = ""; run.Message = "申请已提交，持续等待同一张证书签发。";
        await SaveRunAsync(run, token, ct, 30);
    }

    private async Task WaitForIssuanceAsync(CertificateScheduleRun run, CertificateScheduleInput input, string token, CancellationToken ct)
    {
        var certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(item => item.Id == run.CertificateId, ct);
        if (certificate is null) { await AttentionAsync(run, token, "CERTIFICATE_MISSING", "本轮关联证书已不存在，不能用另一张证书代替。", ct); return; }
        if (certificate.AccountId != input.AccountId || DeploymentSourceBinding.NormalizeDomain(certificate.Domain) != input.Domain)
        { await AttentionAsync(run, token, "CERTIFICATE_IDENTITY_CHANGED", "本轮证书账号或域名不匹配，已阻止部署。", ct); return; }
        if (certificate.Status is "Submitting" or "SubmissionUnknown")
        {
            var refreshed = await certificates.RefreshForScheduleAsync(certificate.Id, ct);
            if (!refreshed.Success)
            {
                // 没有云端标识的未知提交不能用新订单代替；已有标识则持续只读查询同一申请。
                if (certificate.CertificateId.Length > 0 || certificate.OrderId.Length > 0 || certificate.InstanceId.Length > 0)
                    await RetryRunAsync(run, token, "SUBMISSION_RECHECK", "本轮申请暂未确认，将继续查询同一云端申请，不创建新订单。", ct);
                else await AttentionAsync(run, token, "SUBMISSION_UNKNOWN", "本轮申请缺少可查询的云端标识，请核对云端并同步；不会创建新订单。", ct);
                return;
            }
            certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(item => item.Id == run.CertificateId, ct);
        }
        if (certificate?.Status == "Issued")
        {
            if (!await EnabledAsync(run.ScheduleId, ct)) { await FinishAsync(run, token, "Cancelled", "SCHEDULE_DISABLED", "证书已签发，计划已停用，未提交自动部署。", ct); return; }
            run.Status = "Deploying"; run.Message = "本轮证书已签发，开始逐个目标部署；DNS 清理不阻塞部署。";
            Audit(run, "ScheduleCertificateIssued", "ISSUED", run.Message);
            await SaveRunAsync(run, token, ct); return;
        }
        if (certificate?.Status is "Failed" or "Expired" or "Revoked" or "Cancelled")
        { await FinishAsync(run, token, "Failed", "APPLICATION_FAILED", "本轮申请进入失败或不可部署终态，未执行部署。", ct); return; }
        run.Message = "正在持续检查本轮申请，尚未签发；不会重复申请。";
        await SaveRunAsync(run, token, ct, 30);
    }

    private async Task DeployAsync(CertificateScheduleRun run, CertificateScheduleInput input, string token, CancellationToken ct)
    {
        var progress = Read<List<ScheduleTargetProgress>>(run.TargetsJson) ?? [];
        if (!ProgressMatches(input, progress)) { await AttentionAsync(run, token, "TARGET_SNAPSHOT_INVALID", "本轮目标快照不完整，已阻止自动部署。", ct); return; }
        // 远端预检的临时失败没有产生批次，可在原轮次按原目标重新预检。
        foreach (var target in progress.Where(item => item.BatchId.Length == 0 && item.Status == "Failed" && RetryableFailure(item.Code)))
            target.Status = "Pending";
        // 先独立推进尚未提交的目标，某目标预检失败不会阻塞其余目标。
        var pending = progress.FirstOrDefault(item => item.Status == "Pending" && item.BatchId.Length == 0);
        if (pending is not null)
        {
            if (!await EnabledAsync(run.ScheduleId, ct))
            {
                foreach (var item in progress.Where(item => item.BatchId.Length == 0 && item.Status == "Pending"))
                { item.Status = "Cancelled"; item.Code = "SCHEDULE_DISABLED"; item.Message = "计划已停用，未提交此目标。"; }
            }
            else
            {
                if (pending.ConfigRevision == 0)
                {
                    // 历史轮次没有修订号时，只有配置更新时间早于本轮开始才可补齐证据。
                    var original = await db.DeploymentTargets.AsNoTracking().SingleOrDefaultAsync(target => target.Id == pending.TargetId, ct);
                    if (original is null || original.UpdatedAtUtc > (run.StartedAtUtc ?? run.CreatedAtUtc))
                    {
                        pending.Status = "NeedsAttention"; pending.Code = "TARGET_REVISION_UNCONFIRMED";
                        pending.Message = "历史轮次缺少原目标配置修订，且目标配置已变化，需核对原部署范围。";
                        run.TargetsJson = JsonSerializer.Serialize(progress, Json);
                        await AttentionAsync(run, token, pending.Code, pending.Message, ct); return;
                    }
                    pending.ConfigRevision = original.ConfigRevision;
                    run.TargetsJson = JsonSerializer.Serialize(progress, Json);
                    await SaveRunAsync(run, token, ct);
                }
                await FenceAsync(run, token, ct);
                var result = await deployments.PlanForScheduleAsync(run.CertificateId, new([new(pending.TargetId)]),
                    ServiceUser(run), run.Id, token, ct);
                await db.Entry(run).ReloadAsync(ct);
                progress = Read<List<ScheduleTargetProgress>>(run.TargetsJson) ?? [];
                pending = progress.Single(item => item.TargetId == pending.TargetId);
                if (!result.Success)
                {
                    pending.Status = RetryableFailure(result.Code) ? "Pending" : "Failed";
                    pending.Code = SafeCode(result.Code); pending.Message = result.Message;
                }
                else if (pending.BatchId != result.Data?.BatchId)
                { await AttentionAsync(run, token, "BATCH_LINK_MISSING", "部署服务未原子保存本轮批次关联，已阻止提交。", ct); return; }
                run.TargetsJson = JsonSerializer.Serialize(progress, Json);
                await SaveRunAsync(run, token, ct, !result.Success && RetryableFailure(result.Code) ? 30 : 1); return;
            }
        }
        foreach (var target in progress.Where(item => item.BatchId.Length > 0 && !TargetSucceeded(item) &&
                     item.Status != "Cancelled" && (item.Status != "Failed" || RetryableFailure(item.Code))))
        {
            // 入口只处理原批次；过期材料/草稿重建、远端恢复由部署服务在资源锁内完成。
            var result = await EnabledAsync(run.ScheduleId, ct)
                ? await deployments.RecoverForScheduleAsync(target.BatchId, run.Id, token, ct)
                : await deployments.GetAsync(target.BatchId, ct);
            if (!result.Success || result.Data is null)
            { target.Status = "NeedsAttention"; target.Code = SafeCode(result.Code); target.Message = "已有批次恢复核对未完成：" + result.Message; continue; }
            var batch = result.Data;
            target.TargetName = batch.Tasks.FirstOrDefault()?.TargetName ?? target.TargetName;
            if (batch.CertificateId != run.CertificateId || batch.Tasks.Count == 0 || batch.Tasks.Any(item => item.TargetId != target.TargetId))
            { target.Status = "NeedsAttention"; target.Code = "BATCH_IDENTITY_CHANGED"; target.Message = "已有批次与本轮证书或目标不匹配。"; continue; }
            if (batch.Status == "Draft")
            {
                if (!await EnabledAsync(run.ScheduleId, ct)) { target.Status = "Cancelled"; target.Code = "SCHEDULE_DISABLED"; target.Message = "计划已停用，草稿未提交。"; continue; }
                target.Status = "Submitting"; target.Message = "正在提交已关联的部署批次。";
                run.TargetsJson = JsonSerializer.Serialize(progress, Json);
                await SaveRunAsync(run, token, ct);
                await FenceAsync(run, token, ct);
                var submitted = await deployments.SubmitAsync(batch.Id, new(batch.PlanRevision, run.Id + ":" + target.TargetId), ServiceUser(run), ct);
                target.Status = submitted.Success ? "Queued" : "NeedsAttention";
                target.Code = submitted.Success ? "" : SafeCode(submitted.Code);
                target.Message = submitted.Success ? "已提交后台部署。" : "部署提交结果需要核对，保留同一批次和幂等键。";
                Audit(run, "ScheduleDeploymentSubmit", submitted.Success ? "QUEUED" : "NEEDS_ATTENTION", "目标：" + target.TargetId);
                run.TargetsJson = JsonSerializer.Serialize(progress, Json);
                await SaveRunAsync(run, token, ct); return;
            }
            if (batch.Status == "Succeeded" && batch.Tasks.All(TaskVerified))
            { target.Status = batch.Tasks.All(item => item.Status == "Skipped") ? "Skipped" : "Succeeded"; target.Code = "OK"; target.Message = "目标部署已完成并核对。"; }
            else if (batch.Status is "Queued" or "Running") { target.Status = batch.Status; target.Message = "等待已有部署批次执行及核对。"; }
            else if (batch.Status == "NeedsAttention" || batch.Status == "Succeeded")
            { target.Status = "NeedsAttention"; target.Code = batch.Tasks.FirstOrDefault(item => item.Status == "NeedsAttention")?.Code ?? "DEPLOYMENT_UNCONFIRMED"; target.Message = "后台正在核对已有部署，未确认前保留旧证书。"; }
            else
            {
                target.Code = batch.Tasks.FirstOrDefault(item => item.Status == "Failed")?.Code ?? "DEPLOYMENT_FAILED";
                target.Status = RetryableFailure(target.Code) ? "NeedsAttention" : "Failed";
                target.Message = "已有部署批次未成功，保留原批次及旧证书。";
            }
        }
        run.TargetsJson = JsonSerializer.Serialize(progress, Json);
        if (progress.Any(item => item.Status is "Pending" or "Draft" or "Submitting" or "Queued" or "Running"))
        { run.Message = "已签发，正在独立推进各目标部署。"; await SaveRunAsync(run, token, ct, 15); return; }
        if (progress.Any(item => item.Status == "NeedsAttention"))
        { await AttentionAsync(run, token, "DEPLOYMENT_NEEDS_ATTENTION", "至少一个目标结果待核对，保留全部旧证书。", ct); return; }
        if (!progress.All(TargetSucceeded))
        {
            run.CleanupStatus = "NotStarted";
            await FinishAsync(run, token, progress.Any(TargetSucceeded) ? "PartialFailed" : "Failed", "DEPLOYMENT_FAILED", "部分或全部目标未成功，未吊销或删除旧证书。", ct); return;
        }
        run.Status = "CleaningOldCertificates"; run.Message = "全部选定目标已核对成功，准备处理本轮旧证书快照。";
        await SaveRunAsync(run, token, ct);
    }

    private async Task CleanupAsync(CertificateScheduleRun run, CertificateScheduleInput input, string token, CancellationToken ct)
    {
        var old = Read<List<ScheduleCertificateCleanup>>(run.OldCertificatesJson) ?? [];
        var item = old.FirstOrDefault(item => item.Status is not ("Deleted" or "Skipped"));
        if (item is not null && (item.CertificateId == run.CertificateId || item.Domain != input.Domain))
        { await AttentionAsync(run, token, "CLEANUP_SCOPE_CHANGED", "旧证书快照身份不匹配，禁止清理。", ct); return; }
        // 停用后保留清理台账和活跃轮次，避免已创建的吊销 DNS 因轮次被取消而成为孤立记录。
        if (!await EnabledAsync(run.ScheduleId, ct))
        { run.Message = "计划已停用，保留当前清理进度，启用后继续；未写入 DNS 或删除证书。"; await SaveCleanupAsync(30); return; }
        if (item?.Status == "DnsCleaning") { await CompleteDnsCleanupAsync(); return; }
        var bindingRecheck = await RecoverMissingBindingsAsync(run, token, ct);
        if (!await AllDeploymentsVerifiedAsync(run, input, ct))
        {
            if (bindingRecheck) await RetryRunAsync(run, token, "DEPLOYMENT_BINDING_RECHECK", "历史部署绑定暂未核对完成，后台将继续查询原目标；未清理旧证书。", ct);
            else await AttentionAsync(run, token, "DEPLOYMENT_NOT_VERIFIED", "尚未确认所有选定目标使用本轮证书，禁止旧证书清理。", ct);
            return;
        }
        // 申请验证清理不阻塞签发后的部署，但属于本轮完成条件；进度进入既有 JSON。
        if (!await AdvanceNewApplicationCleanupAsync()) return;
        if (!input.RevokeOldCertificates)
        { run.CleanupStatus = "Disabled"; await FinishAsync(run, token, "Succeeded", "OK", "全部目标部署成功，按配置保留旧证书。", ct); return; }
        if (item is null)
        {
            run.CleanupStatus = old.Any(item => item.Status == "Skipped" || item.ApplicationCleanup?.Status == "CompletedWithSkips" ||
                item.RevocationValidation?.Any(record => record.Status is "Preserved" or "Changed" or "Protected") == true)
                ? "CompletedWithSkips" : "Completed";
            await FinishAsync(run, token, "Succeeded", "OK", "全部目标已更新，旧证书清理已完成；受保护资源如有则保留。", ct); return;
        }
        if (item.CertificateId == run.CertificateId || item.Domain != input.Domain)
        { await AttentionAsync(run, token, "CLEANUP_SCOPE_CHANGED", "旧证书快照身份不匹配，禁止清理。", ct); return; }
        var certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(certificate => certificate.Id == item.CertificateId, ct);
        if (certificate is null) { await BeginDnsCleanupAsync("旧证书已不存在，核对最后的吊销 DNS 清理。"); return; }
        if (certificate.AccountId != input.AccountId || DeploymentSourceBinding.NormalizeDomain(certificate.Domain) != input.Domain)
        { await AttentionAsync(run, token, "CLEANUP_SCOPE_CHANGED", "旧证书当前账号或域名与快照不符，禁止清理。", ct); return; }
        if (await ProtectedAsync(certificate.Id, ct))
        {
            if (item.RevocationValidation is { Count: > 0 })
            { await AttentionAsync(run, token, "CERTIFICATE_IN_USE", "旧证书重新被部署引用，保留吊销验证台账，需核对后继续。", ct); return; }
            item.Status = "Skipped"; item.Code = "CERTIFICATE_IN_USE"; item.Message = "仍有部署绑定或在途任务使用此旧证书，已保留。"; await SaveCleanupAsync(); return;
        }
        if (item.ApplicationCleanup is null)
        {
            var captured = await certificates.CaptureApplicationCleanupForScheduleAsync(certificate.Id, ct);
            if (!captured.Success || captured.Data is null)
            { await FailureOrRetryAsync(run, token, captured.Code, "旧证书申请验证清理台账暂未保存，未提交吊销或删除。", ct); return; }
            item.ApplicationCleanup = captured.Data;
            await SaveCleanupAsync();
        }
        // 已提交的动作只查询同一资源；持久化阶段先于外部调用，恢复不能重放吊销/删除。
        if (item.Status is "RevokeSubmitting" or "Revoking" or "DeleteSubmitting" or "Deleting")
        {
            var previous = item.Status;
            IReadOnlyList<DnsChallenge> revokeChallenges = [];
            var refreshed = await certificates.RefreshForScheduleAsync(certificate.Id, ct, values => revokeChallenges = values);
            if (!refreshed.Success)
            {
                // 只读查询短暂失败继续退避轮询，不重复任何吊销、删除或 DNS 创建动作。
                item.Code = SafeCode(refreshed.Code); item.Message = "已有清理动作暂时无法查询，将继续核对同一证书。";
                await SaveCleanupAsync(60); return;
            }
            certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(certificate => certificate.Id == item.CertificateId, ct);
            if (certificate is null) { await BeginDnsCleanupAsync("已核对云端证书不存在，开始最后的吊销 DNS 清理。"); return; }
            // 云端刷新会更新证书字段，写入吊销 DNS 前再次核对本轮固定身份。
            if (certificate.AccountId != input.AccountId || DeploymentSourceBinding.NormalizeDomain(certificate.Domain) != input.Domain)
            { await AttentionAsync(run, token, "CLEANUP_SCOPE_CHANGED", "刷新后的旧证书账号或域名与本轮快照不符，未写入吊销 DNS。", ct); return; }
            if (previous is "RevokeSubmitting" or "Revoking" && certificate.Status == "Revoked")
            { item.Status = "Pending"; item.Code = "REVOKED_CONFIRMED"; item.Message = "已确认吊销，下步单独提交删除。"; await SaveCleanupAsync(); return; }
            var kind = previous is "RevokeSubmitting" or "Revoking" ? "Revoke" : "Delete";
            if (kind == "Revoke" && revokeChallenges.Count > 0)
            {
                var validation = await revocationDns.EnsureAsync(run, item, input, revokeChallenges, PersistDnsProgressAsync, ct);
                item.Code = SafeCode(validation.Code); item.Message = validation.Message;
                if (!validation.Success)
                { await SaveCleanupAsync(); await FailureOrRetryAsync(run, token, item.Code, item.Message, ct); return; }
                if (!validation.Data) { await SaveCleanupAsync(30); return; }
                item.Status = "Revoking"; item.Message = "吊销 DNS 验证记录已就绪，等待云平台确认吊销。";
                await SaveCleanupAsync(30); return;
            }
            if (kind == "Revoke" && item.Code is ("ADDITIONAL_REVOKE_VALIDATION" or "REVOCATION_DNS_PENDING"))
            {
                item.Message = "云端尚未返回吊销专用验证记录，后台将继续查询原吊销；不会猜测或重新提交。";
                await SaveCleanupAsync(60); return;
            }
            var job = await db.CertificateJobs.AsNoTracking().Where(job => job.CertificateId == certificate.Id && job.Kind == kind)
                .OrderByDescending(job => job.CreatedAtUtc).FirstOrDefaultAsync(ct);
            if (job?.Status is "Waiting" or "Submitting")
            { item.Status = kind == "Revoke" ? "Revoking" : "Deleting"; item.Message = "等待云端确认已有清理动作。"; await SaveCleanupAsync(30); return; }
            item.Message = "已有清理动作未确认完成，后台将继续查询原操作，不重复提交。";
            await SaveCleanupAsync(60); return;
        }
        if (item.Status != "Pending") { await AttentionAsync(run, token, "CLEANUP_NEEDS_ATTENTION", "旧证书清理状态待核对，未重新提交。", ct); return; }
        if (!await EnabledAsync(run.ScheduleId, ct))
        { run.Message = "计划已停用，保留旧证书和吊销 DNS 台账等待继续。"; await SaveCleanupAsync(30); return; }
        if (certificate.Status == "Issued" && certificate.NotAfterUtc <= DateTime.UtcNow)
        {
            // 不伪造 Expired 绕过原有删除保护，必须由云端查询确认。
            var refreshed = await certificates.RefreshForScheduleAsync(certificate.Id, ct);
            if (!refreshed.Success) { await FailureOrRetryAsync(run, token, refreshed.Code, "旧证书过期状态暂时无法查询，未吊销或删除。", ct); return; }
            certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(certificate => certificate.Id == item.CertificateId, ct);
            if (certificate is null) { await BeginDnsCleanupAsync("旧证书已不存在，核对吊销 DNS 台账。"); return; }
            if (certificate.AccountId != input.AccountId || DeploymentSourceBinding.NormalizeDomain(certificate.Domain) != input.Domain)
            { await AttentionAsync(run, token, "CLEANUP_SCOPE_CHANGED", "刷新后的旧证书账号或域名与本轮快照不符，禁止清理。", ct); return; }
            if (certificate.Status == "Issued")
            { item.Message = "云端尚未确认旧证书过期，后台将继续查询，不伪造过期状态。"; await SaveCleanupAsync(60); return; }
        }
        if (certificate.Status is not ("Issued" or "Expired" or "Revoked"))
        { await AttentionAsync(run, token, "CLEANUP_STATE_CHANGED", "旧证书状态不允许清理，未执行新的操作。", ct); return; }
        if (certificate.Status == "Expired" && (certificate.NotAfterUtc is null || certificate.NotAfterUtc > DateTime.UtcNow))
        { await AttentionAsync(run, token, "EXPIRY_UNCONFIRMED", "旧证书有效期未确认结束，禁止删除。", ct); return; }
        if (!await AllDeploymentsVerifiedAsync(run, input, ct) || await ProtectedAsync(certificate.Id, ct))
        { await AttentionAsync(run, token, "CLEANUP_PROTECTION_CHANGED", "部署核对或旧证书使用状态发生变化，已阻止清理。", ct); return; }
        var revoke = certificate.Status == "Issued";
        item.Status = revoke ? "RevokeSubmitting" : "DeleteSubmitting";
        item.Message = revoke ? "吊销意图已记录，准备提交。" : "删除意图已记录，准备提交。";
        Audit(run, revoke ? "ScheduleOldCertificateRevoke" : "ScheduleOldCertificateDelete", "INTENT_SAVED", "旧证书：" + item.CertificateId);
        await SaveCleanupAsync();
        await FenceAsync(run, token, ct);
        var result = revoke ? await certificates.RevokeAsync(certificate.Id, "superseded", ct) : await certificates.DeleteAsync(certificate.Id, ct);
        if (!result.Success)
        {
            item.Code = SafeCode(result.Code); item.Message = "旧证书清理未完成（" + item.Code + "），请核对旧证书详情；保留现场，不自动重发。";
            if (DefinitelyRejectedRetryable(result.Code))
            {
                item.Status = "Pending";
                item.Message = "云平台明确未受理本次清理，后台将在重新核对条件后重试。";
            }
            await SaveCleanupAsync();
            await FailureOrRetryAsync(run, token, result.Code, item.Message, ct); return;
        }
        if (revoke && result.Data?.Challenges is { Count: > 0 })
        {
            item.Status = "Revoking"; item.Code = "REVOCATION_DNS_PENDING";
            item.Message = "吊销已提交，下一步读取吊销专用验证记录并自动处理托管 DNS。";
            await SaveCleanupAsync(); return;
        }
        item.Status = revoke ? "Revoking" : await db.Certificates.AnyAsync(certificate => certificate.Id == item.CertificateId, ct) ? "Deleting" : "DnsCleaning";
        item.Code = ""; item.Message = revoke ? "已提交吊销，等待云端确认后才删除。" : item.Status == "DnsCleaning" ? "已确认删除旧证书，最后清理本轮吊销 DNS 记录。" : "已提交删除，等待云端确认。";
        await SaveCleanupAsync(15);

        async Task PersistDnsProgressAsync(CancellationToken cancellationToken)
        {
            if (!await EnabledAsync(run.ScheduleId, cancellationToken)) throw new OperationCanceledException("计划已停用，停止新的 DNS 操作。");
            run.OldCertificatesJson = JsonSerializer.Serialize(old, Json);
            await SaveRunAsync(run, token, cancellationToken);
        }

        async Task BeginDnsCleanupAsync(string message)
        {
            item!.Status = "DnsCleaning"; item.Code = ""; item.Message = message;
            await SaveCleanupAsync();
        }

        async Task CompleteDnsCleanupAsync()
        {
            if (item!.ApplicationCleanup is not null)
            {
                if (item.ApplicationCleanup.CertificateId != item.CertificateId || item.ApplicationCleanup.AccountId != input.AccountId ||
                    DeploymentSourceBinding.NormalizeDomain(item.ApplicationCleanup.Domain) != input.Domain)
                { await AttentionAsync(run, token, "APPLICATION_DNS_SCOPE_CHANGED", "旧证书申请验证台账与本轮身份不符，未执行清理。", ct); return; }
                var application = await certificates.AdvanceApplicationCleanupForScheduleAsync(item.ApplicationCleanup, PersistDnsProgressAsync, ct);
                if (!application.Success)
                { await FailureOrRetryAsync(run, token, application.Code, application.Message, ct); return; }
                if (!application.Data) { await SaveCleanupAsync(30); return; }
            }
            var cleaned = await revocationDns.CleanupAsync(run, item!, input, PersistDnsProgressAsync, ct);
            item!.Code = SafeCode(cleaned.Code); item.Message = cleaned.Message;
            if (!cleaned.Success)
            { await SaveCleanupAsync(); await FailureOrRetryAsync(run, token, item.Code, item.Message, ct); return; }
            if (!cleaned.Data) { await SaveCleanupAsync(30); return; }
            item.Status = "Deleted";
            item.Message = "旧证书已删除；" + (item.ApplicationCleanup?.Status == "CompletedWithSkips" ? "申请验证 DNS 的受保护记录已保留；" : "") + cleaned.Message;
            await SaveCleanupAsync();
        }

        async Task<bool> AdvanceNewApplicationCleanupAsync()
        {
            var snapshot = Read<CertificateScheduleRunSnapshot>(run.ConfigSnapshotJson)!;
            if (snapshot.ApplicationCleanupStatus is "Completed" or "Disabled" or "CompletedWithSkips") return true;
            if (snapshot.ApplicationCleanup is null)
            {
                var captured = await certificates.CaptureApplicationCleanupForScheduleAsync(run.CertificateId, ct);
                if (!captured.Success || captured.Data is null)
                { await FailureOrRetryAsync(run, token, captured.Code, "本轮申请验证 DNS 台账暂不可用。", ct); return false; }
                snapshot.ApplicationCleanup = captured.Data;
                snapshot.ApplicationCleanupStatus = "Running";
                await PersistApplicationAsync(ct);
            }
            var ledger = snapshot.ApplicationCleanup;
            if (ledger.CertificateId != run.CertificateId || ledger.AccountId != input.AccountId ||
                DeploymentSourceBinding.NormalizeDomain(ledger.Domain) != input.Domain)
            { await AttentionAsync(run, token, "APPLICATION_DNS_SCOPE_CHANGED", "本轮申请验证台账身份不符，未执行清理。", ct); return false; }
            var cleaned = await certificates.AdvanceApplicationCleanupForScheduleAsync(ledger, PersistApplicationAsync, ct);
            if (!cleaned.Success)
            {
                snapshot.ApplicationCleanupStatus = "NeedsAttention";
                await PersistApplicationAsync(ct);
                await FailureOrRetryAsync(run, token, cleaned.Code, cleaned.Message, ct); return false;
            }
            if (!cleaned.Data)
            {
                run.Message = "部署已完成，后台继续核对本轮申请验证 DNS 清理。";
                await SaveRunAsync(run, token, ct, 30); return false;
            }
            snapshot.ApplicationCleanupStatus = ledger.Status is "Completed" or "CompletedWithSkips" or "Disabled"
                ? ledger.Status : ledger.Enabled ? "Completed" : "Disabled";
            await PersistApplicationAsync(ct);
            return true;

            async Task PersistApplicationAsync(CancellationToken cancellationToken)
            {
                if (!await EnabledAsync(run.ScheduleId, cancellationToken)) throw new OperationCanceledException("计划已停用，暂停申请验证 DNS 清理。");
                run.ConfigSnapshotJson = JsonSerializer.Serialize(snapshot, Json);
                await SaveRunAsync(run, token, cancellationToken);
            }
        }

        async Task SaveCleanupAsync(int delay = 1)
        {
            run.OldCertificatesJson = JsonSerializer.Serialize(old, Json);
            run.CleanupStatus = "Running";
            await SaveRunAsync(run, token, ct, delay);
        }
    }

    private async Task<bool> AllDeploymentsVerifiedAsync(CertificateScheduleRun run, CertificateScheduleInput input, CancellationToken ct)
    {
        var certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(item => item.Id == run.CertificateId, ct);
        if (certificate is null || certificate.AccountId != input.AccountId ||
            DeploymentSourceBinding.NormalizeDomain(certificate.Domain) != input.Domain || certificate.Status != "Issued" ||
            certificate.NotAfterUtc is null || certificate.NotAfterUtc <= DateTime.UtcNow || certificate.NotBeforeUtc > DateTime.UtcNow)
            return false;
        var progress = Read<List<ScheduleTargetProgress>>(run.TargetsJson) ?? [];
        if (!ProgressMatches(input, progress) || !progress.All(TargetSucceeded)) return false;
        foreach (var target in progress)
        {
            if (target.BatchId.Length == 0) return false;
            var batch = await db.DeploymentBatches.AsNoTracking().SingleOrDefaultAsync(batch => batch.Id == target.BatchId, ct);
            if (batch is null || batch.CertificateId != run.CertificateId || batch.Status != "Succeeded") return false;
            var tasks = await db.DeploymentTasks.AsNoTracking().Where(task => task.BatchId == target.BatchId).ToListAsync(ct);
            if (tasks.Count == 0 || tasks.Any(task => task.TargetId != target.TargetId || task.Status is not ("Succeeded" or "Skipped") ||
                string.IsNullOrEmpty(task.VerificationLevel) || task.VerificationLevel == "None")) return false;
            foreach (var task in tasks)
            {
                if (!await db.DeploymentBindings.AsNoTracking().AnyAsync(binding => binding.TargetId == task.TargetId &&
                    binding.ResourceKey == task.ResourceKey && binding.CertificateId == run.CertificateId && binding.LastTaskId == task.Id, ct))
                    return false;
                // 回滚任务的批次仍可能引用新证书，必须按真实资源阻止并行回滚/更新期间清理。
                if (await db.DeploymentTasks.AsNoTracking().AnyAsync(other => other.Id != task.Id && other.ResourceKey == task.ResourceKey &&
                    (other.Status == "Queued" || other.Status == "Running" || other.Status == "Recovering" || other.Status == "NeedsAttention"), ct)) return false;
            }
        }
        return true;
    }

    private async Task<bool> ProtectedAsync(string certificateId, CancellationToken ct) =>
        await db.DeploymentBindings.AnyAsync(binding => binding.CertificateId == certificateId, ct) ||
        await db.DeploymentTasks.AnyAsync(task =>
            (task.Status == "Queued" || task.Status == "Running" || task.Status == "Recovering" || task.Status == "NeedsAttention") &&
            db.DeploymentBatches.Any(batch => batch.Id == task.BatchId && batch.CertificateId == certificateId), ct);

    private static bool TaskVerified(DeploymentTaskView task) => task.Status is "Succeeded" or "Skipped" &&
        !string.IsNullOrEmpty(task.VerificationLevel) && task.VerificationLevel != "None";
    private static bool TargetSucceeded(ScheduleTargetProgress item) => item.Status is "Succeeded" or "Skipped";
    private static bool ProgressMatches(CertificateScheduleInput input, List<ScheduleTargetProgress> progress) => input.TargetIds.Length > 0 &&
        progress.Count == input.TargetIds.Length && progress.Select(item => item.TargetId).Distinct().Count() == progress.Count &&
        input.TargetIds.All(id => progress.Any(item => item.TargetId == id));
    private Task<bool> EnabledAsync(string id, CancellationToken ct) => db.CertificateSchedules.AsNoTracking().AnyAsync(item => item.Id == id && item.Enabled, ct);
    private static string ServiceUser(CertificateScheduleRun run) => "schedule:" + run.ScheduleId;
    private static T? Read<T>(string json) => JsonSerializer.Deserialize<T>(json, Json);
    private static string SafeCode(string value) => new(value.Where(character => char.IsAsciiLetterOrDigit(character) || character is '_' or '.' or '-').Take(100).ToArray());

    private async Task FenceAsync(CertificateScheduleRun run, string token, CancellationToken ct)
    {
        if (!await db.CertificateScheduleRuns.AsNoTracking().AnyAsync(item => item.Id == run.Id && item.Active && item.LeaseToken == token && item.LeaseUntilUtc > DateTime.UtcNow, ct))
            throw new OperationCanceledException("周期任务执行租约已变化。");
    }

    private async Task SaveRunAsync(CertificateScheduleRun run, string token, CancellationToken ct, int delay = 1)
    {
        await FenceAsync(run, token, ct);
        run.NextCheckAtUtc = DateTime.UtcNow.AddSeconds(delay);
        await db.SaveChangesAsync(ct);
    }

    private async Task AttentionAsync(CertificateScheduleRun run, string token, string code, string message, CancellationToken ct)
    {
        if (run.Status == "CleaningOldCertificates" || run.CleanupStatus == "Running") run.CleanupStatus = "NeedsAttention";
        run.Status = "NeedsAttention"; run.Code = code; run.Message = message;
        Audit(run, "ScheduleRunNeedsAttention", code, message);
        await SaveRunAsync(run, token, ct, 300);
    }

    private async Task FinishAsync(CertificateScheduleRun run, string token, string status, string code, string message, CancellationToken ct)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        await FenceAsync(run, token, ct);
        run.Active = false; run.Status = status; run.Code = code; run.Message = message;
        run.FinishedAtUtc = DateTime.UtcNow; run.NextCheckAtUtc = DateTime.UtcNow;
        Audit(run, "ScheduleRunFinished", code, message);
        await AdvanceScheduleAfterRunAsync(run.ScheduleId, ct);
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
    }

    /// <summary>耗时轮次结束后跳过已错过的执行点；始终保留首次执行锚点，禁止连发补单。</summary>
    private async Task AdvanceScheduleAfterRunAsync(string scheduleId, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var schedule = await db.CertificateSchedules.AsNoTracking().SingleOrDefaultAsync(item => item.Id == scheduleId, ct);
        if (schedule is null || schedule.NextRunAtUtc > now) return;
        var next = CertificateScheduleTiming.NextAfter(schedule.FirstRunAtUtc, schedule.IntervalValue, schedule.IntervalUnit, now);
        await db.CertificateSchedules.Where(item => item.Id == scheduleId && item.ConfigRevision == schedule.ConfigRevision && item.NextRunAtUtc <= now)
            .ExecuteUpdateAsync(update => update.SetProperty(item => item.NextRunAtUtc, next), ct);
    }

    private void Audit(CertificateScheduleRun run, string action, string code, string message) => db.AuditLogs.Add(new()
    {
        Id = ids.NewId(), UserId = "system", Username = "system", Action = action, ResourceId = run.Id,
        Success = code is "OK" or "SCHEDULED" or "MANUAL" or "ISSUED" or "INTENT_SAVED" or "PLAN_SAVED" or "QUEUED",
        Code = code, Message = message.Length > 4000 ? message[..4000] : message, CreatedAtUtc = DateTime.UtcNow
    });

    private async Task HeartbeatAsync(string runId, string token, CancellationTokenSource operation, CancellationToken ct)
    {
        if (scopes is null) return;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(20), ct);
                using var scope = scopes.CreateScope();
                var database = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var changed = await database.CertificateScheduleRuns.Where(run => run.Id == runId && run.Active && run.LeaseToken == token && run.LeaseUntilUtc > DateTime.UtcNow)
                    .ExecuteUpdateAsync(update => update.SetProperty(run => run.LeaseUntilUtc, DateTime.UtcNow.AddMinutes(5)), ct);
                if (changed != 1) { operation.Cancel(); return; }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { return; }
            catch (Exception) { operation.Cancel(); return; }
        }
    }
}
