using System.Text.RegularExpressions;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>持久化编排与云适配分离，所有可预期状态都返回业务结果。</summary>
public sealed partial class CertificateManagementService(AppDbContext db, ICloudAccountStore accounts,
    ICloudProviderResolver providers, DomainManagementService domains, IIdGenerator ids, IMcpExecutionGate? mcpGate = null)
{
    internal static readonly SemaphoreSlim OperationGate = new(1, 1);

    public async Task<ApiResult<int>> SyncAsync(string accountId, CancellationToken ct)
        => await SyncCoreAsync(accountId, null, ct);

    private async Task<ApiResult<int>> SyncCoreAsync(string accountId, Func<CancellationToken, Task>? beforeWrite, CancellationToken ct)
    {
        var context = await ResolveAccountAsync(accountId, ct);
        if (!context.Success || context.Data is null) return ApiResult<int>.Fail(context.Code, context.Message);
        await OperationGate.WaitAsync(ct);
        try
        {
            // 云端快照和本地合并必须与删除串行，避免删除前抓取的旧快照在删除完成后重新入库。
            var response = await context.Data.Provider.ListAsync(context.Data.Account, ct);
            if (!response.Success || response.Data is null) return ApiResult<int>.Fail(response.Code, response.Message);
            if (beforeWrite is not null) await beforeWrite(ct);
            var existing = await db.Certificates.Where(x => x.AccountId == accountId).ToListAsync(ct);
            foreach (var cloud in response.Data)
            {
                var item = existing.Find(x => Matches(x, cloud.Reference));
                if (item is null && context.Data.Account.Provider == "Acme" && !string.IsNullOrEmpty(cloud.Reference.OrderId))
                {
                    // 台账已保存订单而通用快照尚未提交时，必须合并回原申请，避免生成第二个本地证书。
                    var localId = await db.CertificateIssuanceStates.AsNoTracking().Where(x => x.AccountId == accountId &&
                        x.Provider == "Acme" && x.OrderUrl == cloud.Reference.OrderId).Select(x => x.Id).SingleOrDefaultAsync(ct);
                    if (localId is not null) item = existing.Find(x => x.Id == localId);
                }
                if (item is null)
                {
                    item = new ManagedCertificate { Id = ids.NewId(), AccountId = accountId, Provider = context.Data.Account.Provider };
                    db.Certificates.Add(item); existing.Add(item);
                }
                var deleting = item.Status.Equals("Deleting", StringComparison.OrdinalIgnoreCase);
                Copy(cloud, item);
                // 删除任务未完成时，即使云端列表仍返回证书，也保持本地操作状态，避免界面误显示为可再次删除。
                if (deleting) item.Status = "Deleting";
            }
            // ListAsync 只有在完整分页成功时才会返回成功；进行中或活跃证书如果已不在完整云端快照中，
            // 说明用户可能直接在云控制台删除了它，应清理本地卡住的记录。
            // 云端全量快照是同步后的唯一事实来源；已过期、已吊销等终态记录如果不在快照中，
            // 说明它已在云端删除，也应清理本地记录。没有云端引用的提交结果未知申请仍需保留，
            // 避免云端查询延迟导致用户重复提交。
            foreach (var item in existing.Where(x => x.AccountId == accountId &&
                ShouldRemoveMissingAfterSync(x) &&
                HasReference(Reference(x)) && !response.Data.Any(cloud => Matches(x, cloud.Reference))).ToArray())
            {
                await RemoveLocalCertificateAsync(item, ct);
            }
            await db.SaveChangesAsync(ct);
            return ApiResult<int>.Ok(response.Data.Count, "证书同步完成");
        }
        finally { OperationGate.Release(); }
    }

    public Task<ApiResult<ManagedCertificate>> ApplyAsync(CertificateApplyRequest request, CancellationToken ct) =>
        ApplyCoreAsync(request, null, null, null, ct);

    /// <summary>周期任务先持久化本轮关联和免费实例预约，再调用云端；跨实例恢复不重新创建申请。</summary>
    public Task<ApiResult<ManagedCertificate>> ApplyForScheduleAsync(CertificateApplyRequest request, string scheduleRunId,
        string leaseToken, IReadOnlyList<string>? freeInstanceIds, CancellationToken ct) =>
        ApplyCoreAsync(request, scheduleRunId, leaseToken, freeInstanceIds, ct);

    private async Task<ApiResult<ManagedCertificate>> ApplyCoreAsync(CertificateApplyRequest request, string? scheduleRunId,
        string? leaseToken, IReadOnlyList<string>? freeInstanceIds, CancellationToken ct)
    {
        var prepared = await PrepareApplicationInternalAsync(request, ct);
        if (!prepared.Success || prepared.Data is null) return ApiResult<ManagedCertificate>.Fail(prepared.Code, prepared.Message);
        request = prepared.Data.Request;
        var domain = prepared.Data.Domain;
        var context = ApiResult<CertificateContext>.Ok(prepared.Data.Context);

        await OperationGate.WaitAsync(ct);
        try
        {
            // SQLite 串行化事务将实例占用检查、提交意图和运行关联一起提交，网络调用在事务之后。
            await using var reservation = scheduleRunId is null ? null : await db.Database.BeginTransactionAsync(ct);
            CertificateScheduleRun? scheduleRun = null;
            if (scheduleRunId is not null)
            {
                scheduleRun = await db.CertificateScheduleRuns.SingleOrDefaultAsync(run => run.Id == scheduleRunId, ct);
                if (scheduleRun is null) return ApiResult<ManagedCertificate>.Fail("SCHEDULE_RUN_MISSING", "周期运行记录不存在。");
                await db.Entry(scheduleRun).ReloadAsync(ct);
                if (!scheduleRun.Active || scheduleRun.LeaseToken != leaseToken || scheduleRun.LeaseUntilUtc is not { } leaseUntil || leaseUntil <= DateTime.UtcNow ||
                    !await db.CertificateSchedules.AnyAsync(schedule => schedule.Id == scheduleRun.ScheduleId && schedule.Enabled, ct))
                    return ApiResult<ManagedCertificate>.Fail("SCHEDULE_LEASE_LOST", "周期计划已停用或执行租约已变化。");
                if (!string.IsNullOrEmpty(scheduleRun.CertificateId))
                {
                    var previous = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(item => item.Id == scheduleRun.CertificateId, ct);
                    return previous is null ? ApiResult<ManagedCertificate>.Fail("SCHEDULE_CERTIFICATE_MISSING", "本轮已关联的证书记录不存在，不能重复申请。")
                        : ApiResult<ManagedCertificate>.Ok(previous, "恢复本轮已有申请。");
                }
                if (context.Data!.Account.Provider == "Aliyun")
                {
                    var occupied = await db.Certificates.AsNoTracking().Where(item => item.AccountId == request.AccountId && item.InstanceId != "")
                        .Select(item => item.InstanceId).ToListAsync(ct);
                    var instance = freeInstanceIds?.FirstOrDefault(id => !occupied.Contains(id, StringComparer.Ordinal));
                    if (string.IsNullOrEmpty(instance))
                        return ApiResult<ManagedCertificate>.Fail("FREE_INSTANCE_UNAVAILABLE", "没有可预约的未使用免费测试实例，请在阿里云控制台领取后重试。");
                    request = request with { InstanceId = instance, ApiVersion = "V2" };
                }
            }
            var inProgress = await db.Certificates.AnyAsync(x => x.AccountId == request.AccountId && x.Domain == domain &&
                (x.Status == "Submitting" || x.Status == "SubmissionUnknown" || x.Status == "PendingValidation" || x.Status == "Processing"), ct);
            if (inProgress) return ApiResult<ManagedCertificate>.Fail("APPLICATION_IN_PROGRESS", "该账号下此域名已有进行中或结果未知的申请，请先核对云端订单");
            var (entity, job) = CreateApplicationIntent(request, domain, context.Data!.Account.Provider, "Submitting",
                context.Data.Account.Provider == "Acme" && context.Data.Account.AcmeDirectoryUrl == AcmeProtocolClient.StagingDirectory);
            if (scheduleRun is not null)
            {
                scheduleRun.CertificateId = entity.Id;
                scheduleRun.Status = "WaitingForIssuance";
                scheduleRun.Message = "本轮申请意图已保存，等待云端验证及签发。";
                scheduleRun.NextCheckAtUtc = DateTime.UtcNow.AddSeconds(30);
                db.AuditLogs.Add(new() { Id = ids.NewId(), UserId = "system", Username = "system", Action = "ScheduleApplyIntent",
                    ResourceId = scheduleRun.Id, Success = true, Code = "INTENT_SAVED", Message = "已关联本轮证书申请，域名：" + domain, CreatedAtUtc = DateTime.UtcNow });
            }
            // 先保存提交意图，进程中断后不会再次创建云订单。
            await db.SaveChangesAsync(ct);
            if (reservation is not null) await reservation.CommitAsync(ct);
            return await DispatchApplicationInternalAsync(entity, job, request, context.Data!, ct);
        }
        finally { OperationGate.Release(); }
    }

    /// <summary>周期任务仅查询已有云端资源；确认不存在才清理本地记录，不重发申请、吊销或删除。</summary>
    public async Task<ApiResult<bool>> RefreshForScheduleAsync(string id, CancellationToken ct,
        Action<IReadOnlyList<DnsChallenge>>? revocationChallenges = null)
    {
        await OperationGate.WaitAsync(ct);
        try
        {
            var item = await db.Certificates.SingleOrDefaultAsync(item => item.Id == id, ct);
            if (item is null) return ApiResult<bool>.Ok(false, "证书本地记录已不存在。");
            if (!HasReference(Reference(item)))
                return ApiResult<bool>.Fail("SUBMISSION_UNKNOWN", "此申请没有可查询的云端引用，请核对云控制台。");
            var context = await ResolveAccountAsync(item.AccountId, ct);
            if (!context.Success || context.Data is null) return ApiResult<bool>.Fail(context.Code, context.Message);
            var result = await context.Data.Provider.GetAsync(context.Data.Account, Reference(item), ct);
            if (!result.Success || result.Data is null)
            {
                if (IsCloudNotFound(result.Code) && item.Status is ("Expired" or "Revoked" or "Deleting"))
                {
                    await RemoveLocalCertificateAsync(item, ct);
                    return ApiResult<bool>.Ok(false, "云端已确认证书不存在。");
                }
                return ApiResult<bool>.Fail(result.Code, result.Message);
            }
            if (result.Data.Certificate.Status is ("Deleted" or "NotFound") && item.Status is ("Expired" or "Revoked" or "Deleting"))
            {
                await RemoveLocalCertificateAsync(item, ct);
                return ApiResult<bool>.Ok(false, "云端已确认证书不存在。");
            }
            // 吊销挑战有独立来源；不写入申请验证记录，防止申请清理任务提前删除吊销验证值。
            revocationChallenges?.Invoke(result.Data.RevocationChallenges ?? []);
            var deleting = item.Status == "Deleting";
            var revoking = item.Status == "Revoking";
            Copy(result.Data.Certificate, item);
            // 查询用于核对既有异步动作，不能把云端尚未变化的状态重新暴露为可部署证书。
            if (deleting) item.Status = "Deleting";
            if (revoking && item.Status == "Issued") item.Status = "Revoking";
            await SaveChallengesAsync(item, result.Data.Challenges, ct);
            var apply = await db.CertificateJobs.Where(job => job.CertificateId == id && job.Kind == "Apply" && (job.Status == "Submitting" || job.Status == "SubmissionUnknown"))
                .OrderByDescending(job => job.CreatedAtUtc).FirstOrDefaultAsync(ct);
            if (apply is not null && item.Status is not ("Submitting" or "SubmissionUnknown"))
            { apply.Status = "Waiting"; apply.NextRunAtUtc = DateTime.UtcNow; apply.LeaseUntilUtc = null; }
            await db.SaveChangesAsync(ct);
            return ApiResult<bool>.Ok(true, "已有云端证书状态已核对。");
        }
        finally { OperationGate.Release(); }
    }

    public async Task<ApiResult<CloudOperation>> RevokeAsync(string id, string reason, CancellationToken ct)
    {
        await OperationGate.WaitAsync(ct);
        try
        {
            var item = await db.Certificates.FindAsync([id], ct);
            if (item is null) return ApiResult<CloudOperation>.Fail("NOT_FOUND", "证书不存在");
            if (item.Status is not ("Issued" or "Expired")) return ApiResult<CloudOperation>.Fail("INVALID_STATE", "仅已签发或已过期证书可发起吊销");
            var context = await ResolveAccountAsync(item.AccountId, ct);
            if (!context.Success || context.Data is null) return ApiResult<CloudOperation>.Fail(context.Code, context.Message);
            await DemandMcpMaintenanceWriteAsync(ct, firstWrite: true);
            var originalStatus = item.Status;
            item.Status = "Revoking";
            var job = new CertificateJob { Id = ids.NewId(), CertificateId = id, Kind = "Revoke", Status = "Submitting", CreatedAtUtc = DateTime.UtcNow, NextRunAtUtc = DateTime.UtcNow };
            db.CertificateJobs.Add(job);
            await LinkMcpMaintenanceJobAsync(job, ct);
            await db.SaveChangesAsync(ct);
            var result = await context.Data.Provider.RevokeAsync(context.Data.Account, Reference(item), reason, ct);
            job.Status = result.Success ? "Waiting" : IsUncertain(result.Code) ? "SubmissionUnknown" : "Failed";
            job.Message = result.Message;
            if (result.Success && result.Data is not null)
            {
                job.RequestId = result.Data.RequestId;
                if (result.Data.State == "Revoked") { item.Status = "Revoked"; item.RawStatus = "Revoked"; job.Status = "Completed"; }
                if (result.Data.Challenges is { Count: > 0 })
                {
                    job.Message = "吊销需要额外域名验证，请按验证记录完成后核对云端状态";
                    // 吊销挑战只交给周期任务的独立台账，不能混入申请验证记录。
                }
            }
            else if (!IsUncertain(result.Code)) item.Status = originalStatus;
            await db.SaveChangesAsync(ct);
            return result;
        }
        finally { OperationGate.Release(); }
    }

    /// <summary>取消待验证或审核中的申请。成功后保留本地“已取消”记录，方便用户确认并继续删除。</summary>
    public async Task<ApiResult<CloudOperation>> CancelAsync(string id, CancellationToken ct)
    {
        await OperationGate.WaitAsync(ct);
        try
        {
            var item = await db.Certificates.FindAsync([id], ct);
            if (item is null) return ApiResult<CloudOperation>.Fail("NOT_FOUND", "证书不存在");
            if (item.Status is not ("PendingValidation" or "Processing"))
                return ApiResult<CloudOperation>.Fail("CANCEL_STATE_NOT_ALLOWED", "仅待验证或审核中的证书申请可以取消审核。");
            var context = await ResolveAccountAsync(item.AccountId, ct);
            if (!context.Success || context.Data is null) return ApiResult<CloudOperation>.Fail(context.Code, context.Message);
            await DemandMcpMaintenanceWriteAsync(ct, firstWrite: true);
            var result = await context.Data.Provider.CancelAsync(context.Data.Account, Reference(item), ct);
            if (!result.Success || result.Data is null)
            {
                // 网络或云端响应未知时保留审核中状态，避免把未确认的取消误记为完成。
                if (IsUncertain(result.Code))
                {
                    item.Status = "Processing";
                    item.RawStatus = "Cancelling";
                    item.SyncedAtUtc = DateTime.UtcNow;
                    if (mcpMaintenanceOperationId is not null)
                    {
                        // 取消结果未知时冻结原申请Job，禁止它继续建DNS或推进签发，等待只读核对。
                        var uncertain = await db.CertificateJobs.Where(x => x.CertificateId == id && x.Kind == "Apply")
                            .OrderByDescending(x => x.CreatedAtUtc).FirstOrDefaultAsync(ct);
                        if (uncertain is null)
                        {
                            uncertain = new CertificateJob { Id = ids.NewId(), CertificateId = id, CreatedAtUtc = DateTime.UtcNow };
                            db.CertificateJobs.Add(uncertain);
                        }
                        uncertain.Kind = "Cancel"; uncertain.Status = "SubmissionUnknown";
                        uncertain.Message = "原 MCP 取消提交结果未知，保留同一申请等待人工核对，未继续申请。";
                        await LinkMcpMaintenanceJobAsync(uncertain, ct);
                    }
                    await db.SaveChangesAsync(ct);
                }
                return result;
            }

            item.Status = result.Data.State.Equals("Cancelled", StringComparison.OrdinalIgnoreCase) ||
                          result.Data.State.Equals("Deleted", StringComparison.OrdinalIgnoreCase)
                ? "Cancelled" : "Processing";
            item.RawStatus = result.Data.State;
            item.SyncedAtUtc = DateTime.UtcNow;
            var applyJob = await db.CertificateJobs.Where(x => x.CertificateId == id && x.Kind == "Apply")
                .OrderByDescending(x => x.CreatedAtUtc).FirstOrDefaultAsync(ct);
            if (applyJob is not null)
            {
                if (mcpMaintenanceOperationId is not null) { applyJob.Kind = "Cancel"; await LinkMcpMaintenanceJobAsync(applyJob, ct); }
                applyJob.Status = item.Status == "Cancelled" ? "Completed" : "Waiting";
                applyJob.Message = item.Status == "Cancelled" ? "申请已取消" : "等待云端确认取消审核";
                applyJob.NextRunAtUtc = DateTime.UtcNow.AddSeconds(30);
            }
            else if (mcpMaintenanceOperationId is not null && item.Status != "Cancelled")
            {
                var cancelJob = new CertificateJob { Id = ids.NewId(), CertificateId = id, Kind = "Cancel", Status = "Waiting", CreatedAtUtc = DateTime.UtcNow, NextRunAtUtc = DateTime.UtcNow };
                db.CertificateJobs.Add(cancelJob); await LinkMcpMaintenanceJobAsync(cancelJob, ct);
            }
            if (item.Status == "Cancelled") await CleanupAsync(item, ct);
            await db.SaveChangesAsync(ct);
            return result;
        }
        finally { OperationGate.Release(); }
    }

    public async Task<ApiResult<CertificateDownload>> DownloadAsync(string id, string format, CancellationToken ct)
    {
        var item = await db.Certificates.FindAsync([id], ct);
        if (item is null) return ApiResult<CertificateDownload>.Fail("NOT_FOUND", "证书不存在");
        if (item.Status != "Issued") return ApiResult<CertificateDownload>.Fail("INVALID_STATE", "仅已签发证书支持下载");
        if (!item.CanDownload) return ApiResult<CertificateDownload>.Fail("CERTIFICATE_MATERIAL_UNAVAILABLE", "未在本机保存完整私钥材料的证书不能下载。");
        var context = await ResolveAccountAsync(item.AccountId, ct);
        if (!context.Success || context.Data is null) return ApiResult<CertificateDownload>.Fail(context.Code, context.Message);
        var result = await context.Data.Provider.DownloadAsync(context.Data.Account, Reference(item), format, ct);
        if (!result.Success || result.Data is null) return result;
        // 云端返回的文件名包含证书 ID，用户侧统一按绑定域名、下载类型和业务日期命名。
        var fileName = CertificateDownloadHelper.BuildFileName(PrimaryDomain(item.Domain), format, item.CertificateId.Length > 0 ? item.CertificateId : item.Id);
        return ApiResult<CertificateDownload>.Ok(result.Data with { FileName = fileName }, result.Message);
    }

    /// <summary>删除已过期、已吊销或已取消证书。云端确认成功后才删除本地快照，未知结果保留记录等待核对。</summary>
    public async Task<ApiResult<CloudOperation>> DeleteAsync(string id, CancellationToken ct)
    {
        await OperationGate.WaitAsync(ct);
        try
        {
            var item = await db.Certificates.FindAsync([id], ct);
            if (item is null) return ApiResult<CloudOperation>.Fail("NOT_FOUND", "证书不存在");
            var expired = item.Status.Equals("Expired", StringComparison.OrdinalIgnoreCase);
            var revoked = item.Status.Equals("Revoked", StringComparison.OrdinalIgnoreCase);
            var cancelled = item.Status.Equals("Cancelled", StringComparison.OrdinalIgnoreCase);
            if (!expired && !revoked && !cancelled)
                return ApiResult<CloudOperation>.Fail("DELETE_STATE_NOT_ALLOWED", "仅已过期、已吊销或已取消证书允许删除，其他状态请先同步或执行对应操作");
            if (expired && (item.NotAfterUtc is not { } end || end > DateTime.UtcNow))
                return ApiResult<CloudOperation>.Fail("EXPIRED_CERTIFICATE_REQUIRED", "证书有效期尚未结束，已阻止删除");
            var context = await ResolveAccountAsync(item.AccountId, ct);
            if (!context.Success || context.Data is null) return ApiResult<CloudOperation>.Fail(context.Code, context.Message);
            await DemandMcpMaintenanceWriteAsync(ct, firstWrite: true);
            await ArchiveApplicationCleanupBeforeRemovalAsync(item, ct);
            var result = await context.Data.Provider.DeleteAsync(context.Data.Account, Reference(item), ct);
            if (!result.Success || result.Data is null)
            {
                // 云端已明确找不到时，删除已完成；网络、权限等未知结果仍保留本地记录。
                if (IsCloudNotFound(result.Code))
                {
                    await RemoveLocalCertificateAsync(item, ct);
                    return ApiResult<CloudOperation>.Ok(new("", "Deleted"), "云端证书已不存在，本地记录已清理");
                }
                return result;
            }
            if (result.Data.State.Equals("NotFound", StringComparison.OrdinalIgnoreCase) || result.Data.State.Equals("Deleted", StringComparison.OrdinalIgnoreCase))
            {
                await RemoveLocalCertificateAsync(item, ct);
                return result;
            }
            if (result.Data.State.Equals("Deleting", StringComparison.OrdinalIgnoreCase) || result.Data.State.Equals("Pending", StringComparison.OrdinalIgnoreCase))
            {
                // 腾讯云关联资源检查可能返回异步任务；持久化任务，由后台轮询云端是否已消失。
                item.Status = "Deleting";
                item.RawStatus = result.Data.State;
                item.SyncedAtUtc = DateTime.UtcNow;
                var job = await db.CertificateJobs.FirstOrDefaultAsync(x => x.CertificateId == id && x.Kind == "Delete" &&
                    (x.Status == "Waiting" || x.Status == "Submitting"), ct);
                if (job is null)
                {
                    job = new CertificateJob { Id = ids.NewId(), CertificateId = id, Kind = "Delete", Status = "Waiting",
                        CreatedAtUtc = DateTime.UtcNow, NextRunAtUtc = DateTime.UtcNow };
                    db.CertificateJobs.Add(job);
                }
                await LinkMcpMaintenanceJobAsync(job, ct);
                job.RequestId = result.Data.RequestId;
                job.Message = result.Message + (string.IsNullOrWhiteSpace(result.Data.TaskId) ? "" : $" TaskId：{result.Data.TaskId}");
                job.NextRunAtUtc = DateTime.UtcNow;
                await db.SaveChangesAsync(ct);
                return result;
            }
            // 成功响应但状态无法解释时不删除，也不伪造完成；交由管理员核对云端。
            item.RawStatus = result.Data.State;
            item.SyncedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(ct);
            return result;
        }
        finally { OperationGate.Release(); }
    }

    public sealed record BatchDeleteItem(string Id, bool Success, string Code, string Message);

    public async Task<ApiResult<IReadOnlyList<BatchDeleteItem>>> DeleteBatchAsync(IReadOnlyCollection<string> ids, CancellationToken ct)
    {
        if (ids is null || ids.Count == 0) return ApiResult<IReadOnlyList<BatchDeleteItem>>.Fail("IDS_REQUIRED", "请选择至少一张证书");
        if (ids.Count > 100) return ApiResult<IReadOnlyList<BatchDeleteItem>>.Fail("TOO_MANY_IDS", "单次最多删除 100 张证书");
        var items = new List<BatchDeleteItem>(ids.Count);
        foreach (var id in ids.Where(x => !string.IsNullOrWhiteSpace(x)).Distinct(StringComparer.Ordinal))
        {
            var result = await DeleteAsync(id.Trim(), ct);
            items.Add(new(id, result.Success, result.Code, result.Message));
        }
        return ApiResult<IReadOnlyList<BatchDeleteItem>>.Ok(items, items.All(x => x.Success) ? "已删除所选证书" : "部分证书未删除，请查看逐项结果");
    }

    public async Task<ApiResult<bool>> RetryCleanupAsync(string id, CancellationToken ct)
    {
        var item = await db.Certificates.FindAsync([id], ct);
        if (item is null) return ApiResult<bool>.Fail("NOT_FOUND", "证书不存在");
        if (!item.AutoCleanup || item.Status != "Issued") return ApiResult<bool>.Fail("INVALID_STATE", "仅签发成功且开启自动清理的申请可重试清理");
        await DemandMcpMaintenanceWriteAsync(ct, firstWrite: true);
        item.CleanupStatus = "Pending";
        var job = new CertificateJob { Id = ids.NewId(), CertificateId = id, Kind = "Cleanup", Status = "Waiting", CreatedAtUtc = DateTime.UtcNow, NextRunAtUtc = DateTime.UtcNow };
        db.CertificateJobs.Add(job);
        await LinkMcpMaintenanceJobAsync(job, ct);
        await db.SaveChangesAsync(ct);
        return ApiResult<bool>.Ok(true, "已安排清理核验任务");
    }

    /// <summary>只捕获原申请的清理范围；调用方将返回值保存到既有运行 JSON，不产生新的申请。</summary>
    public async Task<ApiResult<ScheduleApplicationDnsCleanup>> CaptureApplicationCleanupForScheduleAsync(string certificateId, CancellationToken ct)
    {
        var certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(item => item.Id == certificateId, ct);
        if (certificate is null) return ApiResult<ScheduleApplicationDnsCleanup>.Fail("CERTIFICATE_MISSING", "原证书已不存在且没有申请验证清理快照，不能猜测 DNS 删除范围。");
        var snapshot = new ScheduleApplicationDnsCleanup
        {
            CertificateId = certificate.Id, AccountId = certificate.AccountId, Domain = certificate.Domain,
            Provider = certificate.Provider, ValidationMode = certificate.ValidationMode,
            Enabled = certificate.AutoCleanup && certificate.ValidationMode is ("NativeAutoDns" or "ManagedDns"),
            Status = certificate.AutoCleanup ? "Pending" : "Disabled"
        };
        await AppendApplicationRecordsAsync(snapshot, certificate, ct);
        return ApiResult<ScheduleApplicationDnsCleanup>.Ok(snapshot);
    }

    /// <summary>推进固定申请验证快照；每次写入前先持久化意图，未知结果只查询同一精确记录。</summary>
    public async Task<ApiResult<bool>> AdvanceApplicationCleanupForScheduleAsync(ScheduleApplicationDnsCleanup snapshot,
        Func<CancellationToken, Task> persist, CancellationToken ct)
    {
        await OperationGate.WaitAsync(ct);
        try { return await AdvanceApplicationCleanupCoreAsync(snapshot, persist, ct); }
        finally { OperationGate.Release(); }
    }

    private async Task<ApiResult<bool>> AdvanceApplicationCleanupCoreAsync(ScheduleApplicationDnsCleanup snapshot,
        Func<CancellationToken, Task> persist, CancellationToken ct)
    {
        if (!snapshot.Enabled) { snapshot.Status = "Disabled"; return ApiResult<bool>.Ok(true, "按原申请配置保留验证记录。"); }
        if (!IsValidDomain(snapshot.Domain) || string.IsNullOrEmpty(snapshot.CertificateId) || string.IsNullOrEmpty(snapshot.AccountId) ||
            snapshot.ValidationMode is not ("ManagedDns" or "NativeAutoDns"))
            return ApiResult<bool>.Fail("APPLICATION_DNS_SCOPE_INVALID", "申请验证清理快照身份不完整，未写入 DNS。");
        var certificate = await db.Certificates.SingleOrDefaultAsync(value => value.Id == snapshot.CertificateId, ct);
        if (certificate is not null)
        {
            if (certificate.AccountId != snapshot.AccountId || NormalizeDns(certificate.Domain) != NormalizeDns(snapshot.Domain) || certificate.Provider != snapshot.Provider)
                return ApiResult<bool>.Fail("APPLICATION_DNS_SCOPE_CHANGED", "原申请账号、域名或平台发生变化，已阻止清理。");
            if (certificate.Status is not ("Issued" or "Cancelled" or "Expired" or "Revoked" or "Deleting"))
                return ApiResult<bool>.Ok(false, "原申请尚未结束验证，继续等待，不提前删除 DNS。");
            await AppendApplicationRecordsAsync(snapshot, certificate, ct);
        }
        // 原生腾讯 DNS 的删除权属于证书平台，本系统始终只读取并确认。
        var cloudManaged = snapshot.ValidationMode == "NativeAutoDns" && snapshot.Provider == "TencentCloud";
        if (cloudManaged && snapshot.Records.Count == 0 && certificate?.CleanupStatus != "Completed")
            return ApiResult<bool>.Ok(false, "等待云平台提供原申请验证记录后继续核对清理。");
        var preserved = false;
        foreach (var record in snapshot.Records)
        {
            if (record.Status == "Deleted") continue;
            if (record.IsPersistent || record.Status is "RetainedPersistent" or "Reused" or "Changed" or "Shared" or "Preserved")
            {
                record.Status = record.IsPersistent ? "RetainedPersistent" : record.Status;
                record.Message = "持久、复用、共享或已变化的申请验证记录按原范围保留。";
                preserved = true; await SaveAsync(); continue;
            }
            if (string.IsNullOrWhiteSpace(record.ZoneId) || string.IsNullOrWhiteSpace(record.ZoneName) ||
                string.IsNullOrWhiteSpace(record.AccountId) || record.Type is not ("TXT" or "CNAME") ||
                string.IsNullOrWhiteSpace(record.Value) || record.Value.Any(char.IsControl) ||
                !DnsChallengeNameValid(record.Name) ||
                !BelongsTo(AbsoluteDnsName(record.Name, record.ZoneName), record.ZoneName) || !BelongsTo(snapshot.Domain, record.ZoneName))
                return ApiResult<bool>.Fail("APPLICATION_DNS_SCOPE_INVALID", "申请验证台账的区域或记录身份不完整，未执行删除。");
            var zone = await db.Domains.AsNoTracking().SingleOrDefaultAsync(value => value.Id == record.ZoneId, ct);
            if (zone is null || zone.AccountId != record.AccountId || NormalizeDns(zone.Name) != NormalizeDns(record.ZoneName))
                return ApiResult<bool>.Fail("APPLICATION_DNS_ZONE_CHANGED", "原申请 DNS 托管区域已变化，未切换到其他账号执行。");
            var context = await domains.ResolveAsync(record.ZoneId, ct);
            if (!context.Success || context.Data is null) return ApiResult<bool>.Fail(context.Code, context.Message);
            var list = await context.Data.Provider.ListRecordsAsync(context.Data.Account, context.Data.Domain.Name, ct);
            if (!list.Success || list.Data is null) return ApiResult<bool>.Ok(false, "申请验证 DNS 查询暂不可用，将自动继续核对。");
            var matching = list.Data.Where(value => ApplicationRecordMatches(value, record)).ToArray();
            if (cloudManaged || !record.CreatedBySystem || string.IsNullOrEmpty(record.RecordId))
            {
                if (cloudManaged)
                {
                    if (matching.Length > 0) return ApiResult<bool>.Ok(false, "等待证书平台清理其创建的申请验证 DNS。");
                    record.Status = "Deleted"; record.Message = "已确认云平台申请验证记录不存在。"; await SaveAsync(); continue;
                }
                // 创建回执丢失不能取得删除权；读取到相同值只复用，未读取到也不重新创建。
                record.Status = matching.Length > 0 ? "Reused" : "Preserved";
                record.RecordId = matching.Length == 1 ? matching[0].Id : record.RecordId;
                record.Message = "原创建回执不足，已核对并保留；不会重复创建或认领删除权。";
                preserved = true; await SaveAsync(); continue;
            }
            var current = list.Data.Where(value => value.Id == record.RecordId).ToArray();
            if (current.Length == 0) { record.Status = "Deleted"; record.Message = "已确认原申请验证记录不存在。"; await SaveAsync(); continue; }
            if (current.Length != 1 || !ApplicationRecordMatches(current[0], record) || !DnsRecordEnabled(current[0]))
            { record.Status = "Changed"; record.CreatedBySystem = false; record.Message = "原申请验证记录的内容或启用状态已变化，保留现场。"; preserved = true; await SaveAsync(); continue; }
            if (await ApplicationRecordReferencedAsync(snapshot, record, ct))
            { record.Status = "Shared"; record.Message = "其他申请或吊销轮次仍引用此 DNS，保留。"; preserved = true; await SaveAsync(); continue; }
            // 读回证明同一 ID 仍是本轮拥有的精确记录时，重复删除该 ID 是可安全重试的。
            // 若先前删除已经完成，上面的不存在性检查会直接结束，不会再次发送请求。
            record.Status = "Deleting"; record.Message = "精确申请验证 DNS 删除意图已持久化。";
            await SaveAsync();
            // 意图保存后重读身份和共享引用，防止等待期间发生人工修改或出现新的使用者。
            var fresh = await context.Data.Provider.ListRecordsAsync(context.Data.Account, context.Data.Domain.Name, ct);
            if (!fresh.Success || fresh.Data is null)
            { record.Status = "Created"; record.Message = "删除前查询暂不可用，尚未发送删除。"; await SaveAsync(); return ApiResult<bool>.Ok(false, record.Message); }
            current = fresh.Data.Where(value => value.Id == record.RecordId).ToArray();
            if (current.Length == 0) { record.Status = "Deleted"; await SaveAsync(); continue; }
            if (current.Length != 1 || !ApplicationRecordMatches(current[0], record) || !DnsRecordEnabled(current[0]))
            { record.Status = "Changed"; record.CreatedBySystem = false; preserved = true; await SaveAsync(); continue; }
            if (await ApplicationRecordReferencedAsync(snapshot, record, ct))
            { record.Status = "Shared"; preserved = true; await SaveAsync(); continue; }
            // 前置读取可能耗时；调用计划的持久化回调再次核验租约和启用状态后才提交写入。
            await SaveAsync();
            if (mcpGate is not null)
            {
                var allowed = await CheckMcpCertificateWriteAsync(snapshot.CertificateId, ct);
                if (!allowed.Success) return ApiResult<bool>.Fail(allowed.Code, allowed.Message);
            }
            ApiResult<CloudOperation> deleted;
            try { deleted = await context.Data.Provider.DeleteRecordAsync(context.Data.Account, context.Data.Domain.Name, record.RecordId, ct); }
            catch (McpExecutionDeniedException) { throw; }
            catch (Exception) when (!ct.IsCancellationRequested)
            { record.Status = "DeletionUnknown"; record.Message = "申请验证 DNS 删除响应中断，将查询同一记录确认。"; await SaveAsync(); return ApiResult<bool>.Ok(false, record.Message); }
            record.Status = deleted.Success || IsUncertain(deleted.Code) ? "DeletionUnknown" : "Created";
            record.Code = deleted.Success ? "" : deleted.Code;
            record.Message = deleted.Success ? "申请验证 DNS 删除已提交，等待不存在性确认。" : "申请验证 DNS 删除尚未完成，将继续核对。";
            await SaveAsync();
            if (!deleted.Success && !IsUncertain(deleted.Code)) return ApiResult<bool>.Fail(deleted.Code, deleted.Message);
            var readback = await context.Data.Provider.ListRecordsAsync(context.Data.Account, context.Data.Domain.Name, ct);
            if (readback.Success && readback.Data is not null && readback.Data.All(value => value.Id != record.RecordId))
            { record.Status = "Deleted"; record.Message = "已读回确认原申请验证记录不存在。"; await SaveAsync(); continue; }
            return ApiResult<bool>.Ok(false, record.Message);
        }
        snapshot.Status = preserved ? "CompletedWithSkips" : "Completed";
        await SaveAsync();
        return ApiResult<bool>.Ok(true, preserved ? "申请验证临时 DNS 已处理，受保护记录已保留。" : "申请验证临时 DNS 已全部核对清理。");

        async Task SaveAsync()
        {
            foreach (var value in snapshot.Records)
            {
                var local = await db.ValidationRecords.SingleOrDefaultAsync(row => row.Id == value.ValidationRecordId && row.CertificateId == snapshot.CertificateId, ct);
                if (local is null || AbsoluteDnsName(local.Name, value.ZoneName) != value.Name || local.Type != value.Type || local.Value != value.Value) continue;
                local.Status = value.Status; local.Message = value.Message; local.RecordId = value.RecordId.Length == 0 ? local.RecordId : value.RecordId;
                local.CreatedBySystem = value.CreatedBySystem;
            }
            if (certificate is not null) certificate.CleanupStatus = snapshot.Status is "Completed" or "CompletedWithSkips"
                ? snapshot.Records.Any(value => value.Status == "Changed") ? "Failed" : "Completed" : "Pending";
            await persist(ct);
            await db.SaveChangesAsync(ct);
        }
    }

    private async Task AppendApplicationRecordsAsync(ScheduleApplicationDnsCleanup snapshot, ManagedCertificate certificate, CancellationToken ct)
    {
        var records = await db.ValidationRecords.AsNoTracking().Where(value => value.CertificateId == snapshot.CertificateId).ToListAsync(ct);
        var zones = await db.Domains.AsNoTracking().Where(value => value.Status != "NotPresent").ToListAsync(ct);
        foreach (var row in records)
        {
            var existing = snapshot.Records.SingleOrDefault(value => value.ValidationRecordId == row.Id);
            if (existing is not null)
            {
                existing.IsPersistent |= row.IsPersistent;
                if (AbsoluteDnsName(row.Name, existing.ZoneName) != existing.Name || row.Type != existing.Type || row.Value != existing.Value ||
                    row.DnsZoneId is not null && row.DnsZoneId != existing.ZoneId ||
                    !string.IsNullOrEmpty(existing.RecordId) && row.RecordId is not null && row.RecordId != existing.RecordId)
                { existing.Status = "Changed"; existing.CreatedBySystem = false; existing.Message = "本地原验证记录身份已变化，保留已有快照且不执行删除。"; }
                else if (!existing.CreatedBySystem && row.CreatedBySystem && row.Status == "Created" && !string.IsNullOrEmpty(row.RecordId))
                {
                    // 后台原执行者已把明确创建回执保存到同一验证行，可以继承这份证据。
                    existing.CreatedBySystem = true; existing.RecordId = row.RecordId; existing.Status = "Created";
                }
                else if (row.Status is "RetainedPersistent" or "Changed" or "Shared") existing.Status = row.Status;
                continue;
            }
            var zone = zones.SingleOrDefault(value => value.Id == (row.DnsZoneId ?? certificate.DnsZoneId)) ??
                zones.Where(value => value.AccountId == certificate.AccountId && BelongsTo(certificate.Domain, value.Name)).OrderByDescending(value => value.Name.Length).FirstOrDefault();
            snapshot.Records.Add(new()
            {
                ValidationRecordId = row.Id, Name = zone is null ? row.Name : AbsoluteDnsName(row.Name, zone.Name), Type = row.Type, Value = row.Value,
                ZoneId = zone?.Id ?? "", ZoneName = zone?.Name ?? "", AccountId = zone?.AccountId ?? "", RecordId = row.RecordId ?? "",
                CreatedBySystem = row.CreatedBySystem, IsPersistent = row.IsPersistent, Status = row.Status, Message = row.Message
            });
        }
    }

    private async Task<bool> ApplicationRecordReferencedAsync(ScheduleApplicationDnsCleanup snapshot, ScheduleApplicationDnsRecord record, CancellationToken ct)
    {
        var references = await db.ValidationRecords.AsNoTracking().Where(value => value.Id != record.ValidationRecordId && value.Status != "Deleted").ToListAsync(ct);
        if (references.Any(value => (value.DnsZoneId is null || value.DnsZoneId == record.ZoneId) &&
            (value.RecordId == record.RecordId || value.Type.Equals(record.Type, StringComparison.OrdinalIgnoreCase) &&
                AbsoluteDnsName(value.Name, record.ZoneName) == record.Name && value.Value == record.Value))) return true;
        var runs = await db.CertificateScheduleRuns.AsNoTracking().Where(value => value.Active)
            .Select(value => new { value.OldCertificatesJson, value.ConfigSnapshotJson }).ToListAsync(ct);
        foreach (var run in runs)
        {
            List<ScheduleCertificateCleanup>? old;
            JsonNode? config;
            try
            {
                old = JsonSerializer.Deserialize<List<ScheduleCertificateCleanup>>(run.OldCertificatesJson, new JsonSerializerOptions(JsonSerializerDefaults.Web));
                config = JsonNode.Parse(run.ConfigSnapshotJson);
            }
            catch (JsonException) { return true; }
            if ((old ?? []).Any(value => value.Status is not ("Deleted" or "Skipped") && value.RevocationValidation?.Any(other =>
                other.Status != "Deleted" && other.ZoneId == record.ZoneId && (other.RecordId == record.RecordId ||
                other.Name == record.Name && other.Type == record.Type && other.Value == record.Value)) == true)) return true;
            var application = config?["applicationCleanup"]?.Deserialize<ScheduleApplicationDnsCleanup>(new JsonSerializerOptions(JsonSerializerDefaults.Web));
            if (ApplicationSnapshotReferences(application, snapshot, record) ||
                (old ?? []).Any(value => value.Status is not ("Deleted" or "Skipped") && ApplicationSnapshotReferences(value.ApplicationCleanup, snapshot, record))) return true;
        }
        return false;
    }

    private static bool ApplicationSnapshotReferences(ScheduleApplicationDnsCleanup? other, ScheduleApplicationDnsCleanup snapshot, ScheduleApplicationDnsRecord record) =>
        other is not null && other.CertificateId != snapshot.CertificateId && other.Records.Any(value => value.Status != "Deleted" && value.ZoneId == record.ZoneId &&
            (value.RecordId == record.RecordId || value.Name == record.Name && value.Type == record.Type && value.Value == record.Value));

    private static string NormalizeDns(string value) => value.Trim().ToLowerInvariant().TrimEnd('.');
    private static bool DnsChallengeNameValid(string value) => value.Length is > 0 and <= 253 && value.Contains('.') &&
        value.Split('.').All(label => label.Length is > 0 and <= 63 && Regex.IsMatch(label, "^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$"));
    private static string AbsoluteDnsName(string name, string zone)
    {
        var value = NormalizeDns(name); var root = NormalizeDns(zone);
        return value == "@" ? root : value == root || value.EndsWith("." + root, StringComparison.Ordinal) ? value : value + "." + root;
    }
    private static bool ApplicationRecordMatches(DnsRecord value, ScheduleApplicationDnsRecord record) =>
        AbsoluteDnsName(value.Name, record.ZoneName) == record.Name && value.Type.Equals(record.Type, StringComparison.OrdinalIgnoreCase) &&
        (record.Type == "CNAME" ? NormalizeDns(value.Value) == NormalizeDns(record.Value) : value.Value == record.Value);
    private static bool DnsRecordEnabled(DnsRecord value) => value.Status.Equals("Enabled", StringComparison.OrdinalIgnoreCase) &&
        !(value.Type.Equals("CNAME", StringComparison.OrdinalIgnoreCase) && value.Proxied);

    public async Task ProcessJobAsync(string jobId, CancellationToken ct)
    {
        // MCP 首次派发由同一个持久证书队列承载，与普通 Submitting 的未知结果恢复严格区分。
        if (await db.CertificateJobs.AsNoTracking().AnyAsync(row => row.Id == jobId && row.Status == "McpQueued", ct))
        { await DispatchMcpApplicationAsync(jobId, ct); return; }
        var previousMaintenanceOperation = mcpMaintenanceOperationId;
        await OperationGate.WaitAsync(ct);
        try
        {
            var job = await db.CertificateJobs.FindAsync([jobId], ct);
            if (job is null || job.Status is not ("Waiting" or "Submitting")) return;
            var item = await db.Certificates.FindAsync([job.CertificateId], ct);
            if (item is null) { job.Status = "Failed"; job.Message = "本地证书不存在"; await db.SaveChangesAsync(ct); return; }
            mcpMaintenanceOperationId = await db.McpOperations.AsNoTracking().Where(x => (x.Kind == "Business" || x.Kind == "ScheduleMaintenance") && x.CertificateJobId == jobId)
                .OrderByDescending(x => x.CreatedAtUtc).Select(x => x.Id).FirstOrDefaultAsync(ct);
            using var cloudWrites = Common.Mcp.McpCloudMutationGuard.Enter(async token =>
            {
                var allowed = await CheckMcpCertificateWriteAsync(item.Id, token);
                if (!allowed.Success) throw new McpExecutionDeniedException(allowed.Code, "原 MCP 证书任务授权已撤销，未发送云端写入。");
            }, mcpMaintenanceOperationId);
            if (mcpMaintenanceOperationId is not null)
            {
                var allowed = await CheckMcpCertificateWriteAsync(item.Id, ct);
                if (!allowed.Success)
                {
                    job.Status = "Failed"; job.Message = "原 MCP 维护授权已失效，任务已停止。";
                    await db.McpOperations.Where(x => x.Id == mcpMaintenanceOperationId).ExecuteUpdateAsync(update => update
                        .SetProperty(x => x.Status, "Blocked").SetProperty(x => x.Code, "MCP_AUTHORIZATION_REVOKED"), ct);
                    await db.SaveChangesAsync(ct); return;
                }
            }
            if (job.Kind.Equals("Delete", StringComparison.OrdinalIgnoreCase))
            {
                await ProcessDeleteJobAsync(job, item, ct);
                await RefreshMcpMaintenanceJobAsync(jobId, job.Status, ct);
                return;
            }
            if (job.Status == "Submitting" && job.Kind == "Apply" && item.Provider == "Acme")
            {
                var issuance = await db.CertificateIssuanceStates.AsNoTracking().SingleOrDefaultAsync(x => x.Id == item.Id &&
                    x.AccountId == item.AccountId && x.Provider == "Acme", ct);
                if (issuance is { OrderUrl.Length: > 0 })
                {
                    // 创建订单回执已保存但通用快照未提交时，恢复同一远端引用，不再创建订单或密钥。
                    item.OrderId = issuance.OrderUrl; item.CertificateId = issuance.RemoteCertificateId;
                    item.ApiVersion = "AcmeV2"; job.Status = "Waiting";
                    await db.SaveChangesAsync(ct);
                }
            }
            if (job.Status == "Submitting")
            {
                job.Status = "SubmissionUnknown"; job.Message = "提交中断，需核对云端结果，系统不会重复提交";
                if (job.Kind == "Apply") item.Status = "SubmissionUnknown";
                await db.SaveChangesAsync(ct);
                await RefreshMcpApplicationStateAsync(job.Id, job.Status, job.Message, ct); return;
            }
            job.Attempts++; job.LeaseUntilUtc = DateTime.UtcNow.AddMinutes(5);
            await db.SaveChangesAsync(ct);
            var context = await ResolveAccountAsync(item.AccountId, ct);
            if (!context.Success || context.Data is null) { await DelayAsync(job, context.Message, ct); return; }
            var result = await context.Data.Provider.GetAsync(context.Data.Account, Reference(item), ct);
            if (!result.Success || result.Data is null) { await DelayAsync(job, result.Message, ct); return; }
            Copy(result.Data.Certificate, item);
            await SaveChallengesAsync(item, result.Data.Challenges, ct);
            await db.SaveChangesAsync(ct);
            if (job.Kind == "Revoke")
            {
                job.Status = item.Status == "Revoked" ? "Completed" : "Waiting";
                job.Message = item.Status == "Revoked" ? "云端已确认吊销" : "等待云端确认吊销，若需验证请查看验证记录";
            }
            else if (job.Kind == "Cancel")
            {
                job.Status = item.Status == "Cancelled" ? "Completed" : "Waiting";
                job.Message = "核对原申请取消状态，不继续申请或创建验证记录。";
                if (item.Status == "Cancelled") await CleanupAsync(item, ct);
            }
            else if (item.Status == "Issued")
            {
                if (item.AutoCleanup && item.ValidationMode is ("NativeAutoDns" or "ManagedDns")) await CleanupAsync(item, ct);
                job.Status = item.CleanupStatus is "Failed" or "Unknown" or "Pending" ? "Waiting" : "Completed";
                job.Message = job.Status == "Completed" ? "证书已签发，验证记录处理完成" : "证书已签发，DNS 清理仍需处理";
            }
            else if (item.Status == "Cancelled")
            {
                job.Status = "Completed";
                job.Message = "云端已确认申请取消";
            }
            else if (item.Status is "Failed" or "Expired" or "Revoked")
            {
                job.Status = "Failed"; job.Message = result.Data.FailureReason ?? "申请进入终态，请查看云端状态";
            }
            else if (item.ValidationMode == "ManagedDns" ||
                     (item.ValidationMode == "NativeAutoDns" && item.Provider == "Aliyun"))
            {
                await ProvisionDnsAsync(item, ct);
                job.Message = "等待 DNS 验证与签发";
            }
            if (job.Kind == "Apply" && item.Provider == "Acme" && item.Status is ("PendingValidation" or "Processing"))
            {
                // DNS-01 接受挑战与 finalize 均有副作用，只能由已授权的申请任务推进。
                var allowed = await CheckMcpCertificateWriteAsync(item.Id, ct);
                if (allowed.Success)
                {
                    var advanced = await context.Data.Provider.ContinueApplicationAsync(context.Data.Account, Reference(item), ct);
                    if (advanced.Success && advanced.Data is not null)
                    {
                        Copy(advanced.Data.Certificate, item);
                        await SaveChallengesAsync(item, advanced.Data.Challenges, ct);
                    }
                    else job.Message = advanced.Message;
                }
                else job.Message = allowed.Message;
            }
            job.NextRunAtUtc = DateTime.UtcNow.AddSeconds(Math.Min(300, 30 + job.Attempts * 10));
            job.LeaseUntilUtc = null;
            await db.SaveChangesAsync(ct);
            await RefreshMcpApplicationStateAsync(job.Id, job.Status, job.Message, ct);
            await RefreshMcpMaintenanceJobAsync(job.Id, job.Status, ct);
        }
        finally { mcpMaintenanceOperationId = previousMaintenanceOperation; OperationGate.Release(); }
    }

    private async Task ProvisionDnsAsync(ManagedCertificate item, CancellationToken ct)
    {
        if (item.DnsZoneId is null) return;
        var context = await domains.ResolveAsync(item.DnsZoneId, ct);
        if (!context.Success || context.Data is null) { item.CleanupStatus = "Unknown"; return; }
        var records = await db.ValidationRecords.Where(x => x.CertificateId == item.Id).ToListAsync(ct);
        foreach (var record in records.Where(x => x.Status is "Pending" or "Creating" or "CreationUnknown" or "Failed"))
        {
            if (!BelongsTo(record.Name.TrimEnd('.'), context.Data.Domain.Name)) { record.Status = "Blocked"; record.Message = "验证记录超出所选托管域"; continue; }
            var list = await context.Data.Provider.ListRecordsAsync(context.Data.Account, context.Data.Domain.Name, ct);
            if (!list.Success || list.Data is null) { record.Message = list.Message; continue; }
            var relative = RelativeName(record.Name, context.Data.Domain.Name);
            var matching = list.Data.Where(x => SameRecord(x, relative, record.Type, record.Value, context.Data.Domain.Name)).ToArray();
            if (matching.Length > 1) { record.Status = "Blocked"; record.Message = "存在多条相同验证记录，不能随意认领记录 ID"; continue; }
            var existing = matching.SingleOrDefault();
            if (existing is not null)
            {
                if (!DnsRecordEnabled(existing)) { record.Status = "Blocked"; record.Message = "相同验证记录未启用，未修改其状态"; continue; }
                var owned = record.CreatedBySystem && record.RecordId == existing.Id;
                record.RecordId = existing.Id; record.Status = owned ? "Created" : "Reused"; record.CreatedBySystem = owned;
                record.Message = owned ? "已确认原创建回执对应的验证记录" : "复用已有验证记录，不自动删除"; continue;
            }
            if (record.Status is "Creating" or "CreationUnknown")
            { record.Message = "已有 DNS 创建意图，继续只读核对，不重复提交未知创建"; continue; }
            var atName = list.Data.Where(value => AbsoluteDnsName(value.Name, context.Data.Domain.Name) == AbsoluteDnsName(record.Name, context.Data.Domain.Name)).ToArray();
            if (record.Type == "CNAME" && atName.Length > 0 || atName.Any(value => value.Type.Equals("CNAME", StringComparison.OrdinalIgnoreCase)))
            { record.Status = "Blocked"; record.Message = "验证位置存在冲突记录，未覆盖已有 DNS"; continue; }
            record.Status = "Creating"; record.DnsZoneId = item.DnsZoneId;
            await db.SaveChangesAsync(ct);
            ApiResult<DnsRecord> created;
            if (mcpGate is not null)
            {
                var allowed = await CheckMcpCertificateWriteAsync(item.Id, ct);
                if (!allowed.Success) { record.Status = "Blocked"; record.Message = allowed.Message; await db.SaveChangesAsync(ct); continue; }
            }
            try { created = await context.Data.Provider.CreateRecordAsync(context.Data.Account, context.Data.Domain.Name, new(relative, record.Type, record.Value), ct); }
            catch (McpExecutionDeniedException) { throw; }
            catch (Exception) when (!ct.IsCancellationRequested)
            { record.Status = "CreationUnknown"; record.Message = "DNS 创建响应中断，等待只读核对原记录"; await db.SaveChangesAsync(ct); continue; }
            if (!created.Success || created.Data is null || string.IsNullOrEmpty(created.Data.Id) ||
                !SameRecord(created.Data, relative, record.Type, record.Value, context.Data.Domain.Name) || !DnsRecordEnabled(created.Data))
            {
                record.Status = created.Success || IsUncertain(created.Code) ? "CreationUnknown" : "Failed";
                record.Message = created.Message; continue;
            }
            record.RecordId = created.Data.Id; record.CreatedBySystem = true; record.Status = "Created"; record.Message = "已创建本次临时验证记录";
            await db.SaveChangesAsync(ct);
        }
    }

    private async Task CleanupAsync(ManagedCertificate item, CancellationToken ct)
    {
        var captured = await CaptureApplicationCleanupForScheduleAsync(item.Id, ct);
        if (!captured.Success || captured.Data is null) { item.CleanupStatus = "Unknown"; return; }
        var result = await AdvanceApplicationCleanupCoreAsync(captured.Data, token => db.SaveChangesAsync(token), ct);
        if (!result.Success) item.CleanupStatus = item.ValidationMode == "NativeAutoDns" && item.Provider == "TencentCloud" ? "Unknown" : "Failed";
        else if (!result.Data) item.CleanupStatus = "Pending";
    }

    private async Task SaveChallengesAsync(ManagedCertificate item, IReadOnlyList<DnsChallenge> challenges, CancellationToken ct)
    {
        var existing = await db.ValidationRecords.Where(x => x.CertificateId == item.Id).ToListAsync(ct);
        var zone = item.DnsZoneId is null ? null : await db.Domains.FindAsync([item.DnsZoneId], ct);
        foreach (var challenge in challenges)
        {
            var name = challenge.IsRelative && zone is not null && BelongsTo(item.Domain, zone.Name) && !BelongsTo(challenge.Name.TrimEnd('.'), zone.Name)
                ? challenge.Name == "@" ? zone.Name : challenge.Name.TrimEnd('.') + "." + zone.Name : challenge.Name;
            var saved = existing.FirstOrDefault(x => x.Name == name && x.Type == challenge.Type && x.Value == challenge.Value);
            if (saved is not null) { if (challenge.IsPersistent) saved.IsPersistent = true; continue; }
            var record = new ValidationRecord { Id = ids.NewId(), CertificateId = item.Id, Domain = challenge.Domain, Name = name,
                Type = challenge.Type, Value = challenge.Value, DnsZoneId = item.DnsZoneId,
                IsPersistent = challenge.IsPersistent, Status = "Pending" };
            db.ValidationRecords.Add(record); existing.Add(record);
        }
    }

    private async Task DelayAsync(CertificateJob job, string message, CancellationToken ct)
    {
        job.Message = message; job.LeaseUntilUtc = null; job.NextRunAtUtc = DateTime.UtcNow.AddMinutes(2);
        await db.SaveChangesAsync(ct);
    }

    /// <summary>轮询异步删除。云端明确不存在视为完成，查询未知或网络失败保留本地记录。</summary>
    private async Task ProcessDeleteJobAsync(CertificateJob job, ManagedCertificate item, CancellationToken ct)
    {
        job.Attempts++;
        job.LeaseUntilUtc = DateTime.UtcNow.AddMinutes(5);
        await db.SaveChangesAsync(ct);
        var context = await ResolveAccountAsync(item.AccountId, ct);
        if (!context.Success || context.Data is null) { await DelayAsync(job, context.Message, ct); return; }
        var result = await context.Data.Provider.GetAsync(context.Data.Account, Reference(item), ct);
        if (!result.Success || result.Data is null)
        {
            if (IsCloudNotFound(result.Code))
            {
                job.Status = "Completed";
                job.Message = "云端已确认证书不存在，已清理本地记录";
                job.LeaseUntilUtc = null;
                await RemoveLocalCertificateAsync(item, ct);
                return;
            }
            await DelayAsync(job, result.Message, ct);
            return;
        }
        if (result.Data.Certificate.Status is "Deleted" or "NotFound")
        {
            job.Status = "Completed";
            job.Message = "云端已确认证书不存在，已清理本地记录";
            job.LeaseUntilUtc = null;
            await RemoveLocalCertificateAsync(item, ct);
            return;
        }
        // 证书仍在云端，保留删除中状态并继续轮询；Copy 只用于刷新原始状态和有效期。
        Copy(result.Data.Certificate, item);
        item.Status = "Deleting";
        item.RawStatus = result.Data.Certificate.RawStatus;
        job.Status = "Waiting";
        job.Message = "云端仍在处理删除任务，等待下一次核验";
        job.NextRunAtUtc = DateTime.UtcNow.AddSeconds(Math.Min(300, 30 + job.Attempts * 10));
        job.LeaseUntilUtc = null;
        await db.SaveChangesAsync(ct);
    }

    private async Task RemoveLocalCertificateAsync(ManagedCertificate item, CancellationToken ct)
    {
        await DemandMcpMaintenanceWriteAsync(ct);
        // 同步或异步删除也可能移除证书；先把清理材料转入已有运行 JSON，不能随验证行一起丢失。
        await ArchiveApplicationCleanupBeforeRemovalAsync(item, ct);
        var records = await db.ValidationRecords.Where(x => x.CertificateId == item.Id).ToListAsync(ct);
        var jobs = await db.CertificateJobs.Where(x => x.CertificateId == item.Id).ToListAsync(ct);
        db.ValidationRecords.RemoveRange(records);
        db.CertificateJobs.RemoveRange(jobs);
        db.Certificates.Remove(item);
        await db.SaveChangesAsync(ct);
    }

    private async Task ArchiveApplicationCleanupBeforeRemovalAsync(ManagedCertificate certificate, CancellationToken ct)
    {
        var captured = await CaptureApplicationCleanupForScheduleAsync(certificate.Id, ct);
        if (!captured.Success || captured.Data is null)
            throw new InvalidOperationException("无法固定原证书申请验证清理台账，已阻止删除本地证书及验证行。");
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web);
        var runIds = await db.CertificateScheduleRuns.AsNoTracking().Where(run => run.Active &&
            (run.CertificateId == certificate.Id || run.OldCertificatesJson.Contains(certificate.Id))).Select(run => run.Id).ToListAsync(ct);
        foreach (var runId in runIds)
        {
            var archived = false;
            for (var attempt = 0; attempt < 8; attempt++)
            {
                var run = await db.CertificateScheduleRuns.AsNoTracking().SingleOrDefaultAsync(value => value.Id == runId && value.Active, ct);
                if (run is null) { archived = true; break; }
                var old = JsonNode.Parse(run.OldCertificatesJson)?.AsArray() ?? throw new InvalidOperationException("运行清理台账无法读取，已阻止删除原验证行。");
                var changed = false;
                foreach (var item in old)
                {
                    if (item is not JsonObject entry || entry["certificateId"]?.GetValue<string>() != certificate.Id) continue;
                    if (ValidExisting(entry["applicationCleanup"])) continue;
                    entry["applicationCleanup"] = JsonSerializer.SerializeToNode(captured.Data, options); changed = true;
                }
                var newConfig = run.ConfigSnapshotJson;
                if (run.CertificateId == certificate.Id)
                {
                    var config = JsonNode.Parse(run.ConfigSnapshotJson)?.AsObject() ?? throw new InvalidOperationException("运行申请台账无法读取，已阻止删除原验证行。");
                    if (!ValidExisting(config["applicationCleanup"]))
                    { config["applicationCleanup"] = JsonSerializer.SerializeToNode(captured.Data, options); newConfig = config.ToJsonString(options); changed = true; }
                }
                if (!changed) { archived = true; break; }
                var newOld = old.ToJsonString(options);
                // 只追加到当前原文，不能用跟踪实体覆盖另一个 Worker 已推进的整块 JSON。
                // 活跃执行者可能仍持有同一租约中的旧快照，确需追加时旋转 token 将其栅栏掉。
                var nextToken = run.LeaseUntilUtc > DateTime.UtcNow ? ids.NewId() : run.LeaseToken;
                var updated = await db.CertificateScheduleRuns.Where(value => value.Id == run.Id && value.Active &&
                        value.LeaseToken == run.LeaseToken && value.ConfigSnapshotJson == run.ConfigSnapshotJson && value.OldCertificatesJson == run.OldCertificatesJson)
                    .ExecuteUpdateAsync(update => update.SetProperty(value => value.ConfigSnapshotJson, newConfig)
                        .SetProperty(value => value.OldCertificatesJson, newOld).SetProperty(value => value.LeaseToken, nextToken), ct);
                if (updated == 1) { archived = true; break; }
            }
            if (!archived) throw new DbUpdateConcurrencyException("运行清理台账持续变化，尚未安全归档，保留原证书和验证行等待重试。");
        }

        bool ValidExisting(JsonNode? node)
        {
            if (node is null) return false;
            var existing = node.Deserialize<ScheduleApplicationDnsCleanup>(options);
            if (existing is null || existing.CertificateId != certificate.Id || existing.AccountId != captured.Data.AccountId ||
                NormalizeDns(existing.Domain) != NormalizeDns(captured.Data.Domain))
                throw new InvalidOperationException("既有申请清理快照身份不匹配，保留原验证行等待核对。");
            return true;
        }
    }

    private async Task<ApiResult<CertificateContext>> ResolveAccountAsync(string accountId, CancellationToken ct)
    {
        var account = await accounts.GetCredentialsAsync(accountId, ct);
        if (!account.Success || account.Data is null) return ApiResult<CertificateContext>.Fail(account.Code, account.Message);
        if (!account.Data.UseForCertificates) return ApiResult<CertificateContext>.Fail("SSL_DISABLED", "该账号未启用 SSL 用途");
        var provider = providers.ResolveCertificate(account.Data.Provider);
        return provider.Success && provider.Data is not null ? ApiResult<CertificateContext>.Ok(new(account.Data, provider.Data))
            : ApiResult<CertificateContext>.Fail(provider.Code, provider.Message);
    }

    private static bool Matches(ManagedCertificate local, CloudCertificateReference cloud) => local.ApiVersion == cloud.ApiVersion &&
        ((!string.IsNullOrWhiteSpace(cloud.CertificateId) && local.CertificateId == cloud.CertificateId) ||
         (!string.IsNullOrWhiteSpace(cloud.OrderId) && local.OrderId == cloud.OrderId) ||
         (string.IsNullOrWhiteSpace(cloud.CertificateId) && !string.IsNullOrWhiteSpace(cloud.InstanceId) && local.InstanceId == cloud.InstanceId));

    private static bool HasReference(CloudCertificateReference reference) =>
        !string.IsNullOrWhiteSpace(reference.CertificateId) || !string.IsNullOrWhiteSpace(reference.OrderId) || !string.IsNullOrWhiteSpace(reference.InstanceId);

    private static bool ShouldRemoveMissingAfterSync(ManagedCertificate item) =>
        item.Status is not ("Submitting" or "SubmissionUnknown");

    private static void Copy(CloudCertificate cloud, ManagedCertificate entity)
    {
        if (!string.IsNullOrWhiteSpace(cloud.Reference.CertificateId)) entity.CertificateId = cloud.Reference.CertificateId;
        if (!string.IsNullOrWhiteSpace(cloud.Reference.OrderId)) entity.OrderId = cloud.Reference.OrderId;
        if (!string.IsNullOrWhiteSpace(cloud.Reference.InstanceId)) entity.InstanceId = cloud.Reference.InstanceId;
        entity.ApiVersion = cloud.Reference.ApiVersion;
        if (!string.IsNullOrWhiteSpace(cloud.Domain)) entity.Domain = PrimaryDomain(cloud.Domain);
        if (!string.IsNullOrWhiteSpace(cloud.Alias)) entity.Alias = cloud.Alias;
        if (!string.IsNullOrWhiteSpace(cloud.ProductCode)) entity.ProductCode = cloud.ProductCode;
        entity.HasPrivateKey = cloud.HasPrivateKey;
        entity.IsStaging = cloud.IsStaging;
        if (cloud.IsFree.HasValue) entity.IsFree = cloud.IsFree;
        entity.RawStatus = cloud.RawStatus;
        entity.Status = cloud.Status switch { "Pending" or "Validating" => "PendingValidation", "Expiring" => "Issued", "Cancelling" => "Processing", "Refunded" => "Cancelled", _ => cloud.Status };
        entity.NotBeforeUtc = cloud.NotBeforeUtc?.UtcDateTime; entity.NotAfterUtc = cloud.NotAfterUtc?.UtcDateTime;
        entity.SyncedAtUtc = DateTime.UtcNow;
    }

    public static bool IsValidDomain(string domain) => domain.Length <= 253 && domain.Contains('.') &&
        !System.Net.IPAddress.TryParse(domain, out _) && domain.Split('.').All(x => x.Length is > 0 and <= 63 && Regex.IsMatch(x, "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"));
    /// <summary>证书模型只保存用户提交的主域名；云端返回的 www 别名不作为第二个绑定域名展示。</summary>
    public static string PrimaryDomain(string value)
    {
        var domains = value.Split([',', ';', '\r', '\n', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(x => x.TrimEnd('.').ToLowerInvariant())
            .Where(IsValidDomain)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (domains.Length == 0) return value.Trim();
        return domains.FirstOrDefault(x => !x.StartsWith("www.", StringComparison.OrdinalIgnoreCase)) ?? domains[0];
    }
    public static bool BelongsTo(string domain, string zone) => domain.Equals(zone, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase);
    public static string RelativeName(string name, string zone) => name.TrimEnd('.').Equals(zone, StringComparison.OrdinalIgnoreCase) ? "@" : name.TrimEnd('.').EndsWith("." + zone, StringComparison.OrdinalIgnoreCase) ? name.TrimEnd('.')[..^(zone.Length + 1)] : name;
    private static bool SameRecord(DnsRecord record, string name, string type, string value, string zone) =>
        RelativeName(record.Name, zone).Equals(name, StringComparison.OrdinalIgnoreCase) && record.Type.Equals(type, StringComparison.OrdinalIgnoreCase) &&
        (type is "CNAME" or "NS" ? record.Value.TrimEnd('.').Equals(value.TrimEnd('.'), StringComparison.OrdinalIgnoreCase) : record.Value.Equals(value, StringComparison.Ordinal));
    private static bool IsUncertain(string code) => code.Contains("UNKNOWN", StringComparison.OrdinalIgnoreCase) || code.Contains("TRANSPORT", StringComparison.OrdinalIgnoreCase) || code.Contains("TIMEOUT", StringComparison.OrdinalIgnoreCase) || code.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase) || code.Contains("HTTP", StringComparison.OrdinalIgnoreCase) || code.Contains("NETWORK", StringComparison.OrdinalIgnoreCase) || code.Contains("SOCKET", StringComparison.OrdinalIgnoreCase) || code.Contains("CONNECTION", StringComparison.OrdinalIgnoreCase);
    private static bool IsCloudNotFound(string code) => code.Contains("NOTFOUND", StringComparison.OrdinalIgnoreCase) ||
        code.Contains("NOT_FOUND", StringComparison.OrdinalIgnoreCase) || code.Contains("NOTEXIST", StringComparison.OrdinalIgnoreCase) ||
        code.Contains("RESOURCE_NOT_FOUND", StringComparison.OrdinalIgnoreCase) || code.Contains("CERTIFICATE_NOT_FOUND", StringComparison.OrdinalIgnoreCase) ||
        code.Contains("CLOUDORDERNOTFOUND", StringComparison.OrdinalIgnoreCase);
    private static CloudCertificateReference Reference(ManagedCertificate item) => new(item.CertificateId, item.OrderId, item.InstanceId, item.ApiVersion);
    private sealed record CertificateContext(CloudAccountCredentials Account, ICloudCertificateService Provider);
}
