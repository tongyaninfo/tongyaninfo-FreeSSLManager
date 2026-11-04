using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl.Deployment;

public sealed partial class DeploymentService
{
    /// <summary>周期恢复始终保留原批次和任务，避免提交回执丢失时生成第二次部署。</summary>
    public async Task<ApiResult<DeploymentBatchView>> RecoverForScheduleAsync(string batchId, string runId, string leaseToken, CancellationToken ct)
    {
        var run = await db.CertificateScheduleRuns.AsNoTracking().SingleOrDefaultAsync(x => x.Id == runId, ct);
        var batch = await db.DeploymentBatches.AsNoTracking().SingleOrDefaultAsync(x => x.Id == batchId, ct);
        if (run is null || batch is null) return ApiResult<DeploymentBatchView>.Fail("NOT_FOUND", "原运行或部署批次不存在，不能创建替代部署。");
        if (!run.Active || run.LeaseToken != leaseToken || run.LeaseUntilUtc <= DateTime.UtcNow || run.LeaseUntilUtc is null || run.CertificateId != batch.CertificateId)
            return ApiResult<DeploymentBatchView>.Fail("SCHEDULE_LEASE_LOST", "运行关联或执行租约已变化，不能恢复部署。");
        var progress = JsonSerializer.Deserialize<List<ScheduleTargetProgress>>(run.TargetsJson, Json) ?? [];
        var tasks = await db.DeploymentTasks.AsNoTracking().Where(x => x.BatchId == batchId).ToListAsync(ct);
        if (tasks.Count == 0 || tasks.Any(task => !progress.Any(item => item.BatchId == batchId && item.TargetId == task.TargetId)))
            return ApiResult<DeploymentBatchView>.Fail("BATCH_IDENTITY_CHANGED", "原批次不属于本轮目标，不能恢复。");
        foreach (var task in tasks)
        {
            if (task.CancelRequested || task.Status is "Cancelled" or "Resolved" or "RolledBack") continue;
            if (task.Status is "Succeeded" or "Skipped")
            {
                await RepairCompletedBindingAsync(task, batch, ct);
                continue;
            }
            if (task.Status == "Running" && task.LeaseUntilUtc > DateTime.UtcNow) continue;
            if (task.Status is "NeedsAttention" or "Running" || task.Status == "Failed" && (task.Code == "REMOTE_RESULT_UNKNOWN" || task.ReceiptJson.Length > 2))
            {
                if (executors.Resolve(task.ExecutorKey).Data is not IDeploymentRecoveryExecutor) continue;
                if (await HasLaterResourceResultAsync(task, ct))
                    return ApiResult<DeploymentBatchView>.Fail("RECOVERY_CONFLICT", "此资源已有后续部署或回滚结果，不能恢复旧任务的文件或命令。");
                await db.DeploymentTasks.Where(x => x.Id == task.Id && !x.CancelRequested && x.Status == task.Status &&
                        (x.LeaseUntilUtc == null || x.LeaseUntilUtc <= DateTime.UtcNow))
                    .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Recovering").SetProperty(x => x.Phase, "Recover")
                        .SetProperty(x => x.Message, "正在核对原部署结果，随后只继续尚未完成的步骤。")
                        .SetProperty(x => x.LeaseUntilUtc, (DateTime?)null).SetProperty(x => x.FinishedAtUtc, (DateTime?)null), ct);
                continue;
            }
            if (task.Status is "Draft" or "Queued" || task.Status == "Failed" && task.Code is "MATERIAL_UNAVAILABLE" or "PLAN_STALE")
            {
                var refreshed = await RefreshPreparedTaskAsync(task, batch, run.Id, leaseToken, ct);
                if (!refreshed.Success) return ApiResult<DeploymentBatchView>.Fail(refreshed.Code, refreshed.Message);
            }
        }
        await RefreshBatchAsync(batchId, ct);
        return await GetAsync(batchId, ct);
    }

    private async Task<bool> IsScheduledBatchAsync(string batchId, CancellationToken ct)
    {
        var candidates = await db.CertificateScheduleRuns.AsNoTracking().Where(x => x.Active && x.TargetsJson.Contains(batchId))
            .Select(x => x.TargetsJson).ToListAsync(ct);
        return candidates.Any(json => (JsonSerializer.Deserialize<List<ScheduleTargetProgress>>(json, Json) ?? []).Any(x => x.BatchId == batchId));
    }

    /// <summary>即使新旧证书相同，也不能让历史任务重放旧命令或夺回后续任务的当前绑定。</summary>
    private async Task<bool> HasLaterResourceResultAsync(DeploymentTask task, CancellationToken ct)
    {
        if (await db.DeploymentTasks.AsNoTracking().AnyAsync(x => x.Id != task.Id && x.ResourceKey == task.ResourceKey && x.CreatedAtUtc >= task.CreatedAtUtc &&
            (x.Status == "Succeeded" || x.Status == "Skipped" || x.Status == "RolledBack" || x.Status == "Resolved" || x.Status == "Running" || x.Status == "Recovering" || x.Status == "NeedsAttention"), ct)) return true;
        var binding = await db.DeploymentBindings.AsNoTracking().SingleOrDefaultAsync(x => x.TargetId == task.TargetId && x.ResourceKey == task.ResourceKey, ct);
        if (binding is null || binding.LastTaskId == task.Id) return false;
        var owner = await db.DeploymentTasks.AsNoTracking().Where(x => x.Id == binding.LastTaskId).Select(x => (DateTime?)x.CreatedAtUtc).SingleOrDefaultAsync(ct);
        return owner is { } created ? created >= task.CreatedAtUtc : binding.UpdatedAtUtc >= task.CreatedAtUtc;
    }

    private async Task<ApiResult<bool>> RefreshPreparedTaskAsync(DeploymentTask task, DeploymentBatch batch, string runId, string token, CancellationToken ct)
    {
        if (!await db.CertificateSchedules.AnyAsync(schedule => schedule.Enabled && db.CertificateScheduleRuns.Any(run => run.Id == runId && run.ScheduleId == schedule.Id), ct))
            return ApiResult<bool>.Fail("SCHEDULE_DISABLED", "计划已停用，未重新生成部署草稿。");
        var source = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(x => x.Id == batch.CertificateId, ct);
        if (source is null || source.Status != "Issued") return ApiResult<bool>.Fail("CERTIFICATE_INVALID", "原证书已不存在或不可部署，不会重新申请。");
        var target = ReadTarget(task);
        var current = await db.DeploymentTargets.AsNoTracking().SingleOrDefaultAsync(x => x.Id == task.TargetId, ct);
        if (current is null || !current.Enabled) return ApiResult<bool>.Fail("TARGET_DISABLED", "原部署目标已停用。");
        var snapshot = await db.DeploymentMaterialSnapshots.AsNoTracking().SingleOrDefaultAsync(x => x.Id == task.MaterialSnapshotId, ct);
        var needsPlan = batch.ExpiresAtUtc <= DateTime.UtcNow && task.Status == "Draft" || task.Status == "Failed";
        var needsMaterial = snapshot is null || snapshot.ExpiresAtUtc <= DateTime.UtcNow;
        if (!needsPlan && !needsMaterial) return ApiResult<bool>.Ok(true);
        if (current.ConfigRevision != task.ConfigRevision)
            return ApiResult<bool>.Fail("CONFIGURATION_CHANGED", "目标配置已变更，不能自动扩大原任务的部署范围。");
        var material = await ReadOrRebuildMaterialAsync(task, batch, ct);
        if (!material.Success || material.Data is null) return ApiResult<bool>.Fail(material.Code, material.Message);
        var plan = ReadPlan(task);
        if (needsPlan)
        {
            var resolved = executors.Resolve(task.ExecutorKey);
            if (resolved.Data is null || resolved.Data.Descriptor.Revision != task.ExecutorRevision)
                return ApiResult<bool>.Fail("EXECUTOR_UNSUPPORTED", "原执行器版本不可用。");
            var rebuilt = await resolved.Data.PlanAsync(target, material.Data.Metadata,
                new(task.TargetId, plan.RemoteResourceId, plan.SiteIds) { UseConfiguredRemoteCertificateId = false }, ct);
            if (!rebuilt.Success || rebuilt.Data is null) return ApiResult<bool>.Fail(rebuilt.Code, rebuilt.Message);
            if (rebuilt.Data.ResourceKey != task.ResourceKey) return ApiResult<bool>.Fail("RESOURCE_CONFLICT", "重新预检的资源范围与原任务不同。");
            if (rebuilt.Data.PreconditionsJson != plan.PreconditionsJson || rebuilt.Data.RemoteResourceId != plan.RemoteResourceId)
                return ApiResult<bool>.Fail("RECOVERY_CONFLICT", "原计划生成后远端资源已被修改，不能把外部变化当作新的覆盖基线。");
            plan = rebuilt.Data;
        }
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var owned = await db.CertificateScheduleRuns.Where(x => x.Id == runId && x.Active && x.LeaseToken == token && x.LeaseUntilUtc > DateTime.UtcNow)
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.LeaseToken, token), ct);
        if (owned != 1) return ApiResult<bool>.Fail("SCHEDULE_LEASE_LOST", "重建期间运行租约已变化。");
        var oldRevision = batch.PlanRevision;
        var replacement = needsMaterial ? CreateMaterialSnapshot(material.Data) : null;
        var snapshotId = replacement?.Id ?? task.MaterialSnapshotId;
        var planJson = JsonSerializer.Serialize(plan, Json);
        var nextStatus = batch.Status == "Draft" ? "Draft" : "Queued";
        // 网络预检期间 Queued 可能被 Worker 领取；条件更新失败时回滚，绝不把 Running 改回排队。
        var changedTask = await db.DeploymentTasks.Where(x => x.Id == task.Id && x.Status == task.Status && x.LeaseId == task.LeaseId &&
                !x.CancelRequested && (x.LeaseUntilUtc == null || x.LeaseUntilUtc <= DateTime.UtcNow))
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.PlanJson, planJson).SetProperty(x => x.MaterialSnapshotId, snapshotId)
                .SetProperty(x => x.Status, nextStatus).SetProperty(x => x.Code, "").SetProperty(x => x.FinishedAtUtc, (DateTime?)null)
                .SetProperty(x => x.LeaseUntilUtc, (DateTime?)null).SetProperty(x => x.Message, "已恢复原证书的部署计划和材料，沿原批次继续。"), ct);
        if (changedTask != 1) return ApiResult<bool>.Fail("CONFLICT", "重建期间原部署任务已由其他执行者接管，请稍后核对。");
        if (replacement is not null) db.DeploymentMaterialSnapshots.Add(replacement);
        await db.DeploymentBatches.Where(x => x.Id == batch.Id).ExecuteUpdateAsync(update => update
            .SetProperty(x => x.PlanRevision, oldRevision + 1).SetProperty(x => x.MaterialSnapshotId, snapshotId)
            .SetProperty(x => x.ExpiresAtUtc, DateTime.UtcNow.AddMinutes(10)), ct);
        db.AuditLogs.Add(new() { Id = ids.NewId(), UserId = "system", Username = "system", Action = "ScheduleDeploymentRebuilt", ResourceId = task.Id,
            Success = true, Code = "PLAN_REBUILT", Message = $"沿原批次恢复，证书={batch.CertificateId}，原计划版本={oldRevision}，新版本={oldRevision + 1}，原计划SHA256={Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(task.PlanJson)))}，原动作={ReadPlan(task).Action}，新动作={plan.Action}，原材料快照={task.MaterialSnapshotId}，新材料快照={snapshotId}。", CreatedAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
        return ApiResult<bool>.Ok(true);
    }

    /// <summary>优先使用原加密字节重建快照；缺失时只读取原证书，身份不一致立即停止。</summary>
    private async Task<ApiResult<CertificateMaterial>> ReadOrRebuildMaterialAsync(DeploymentTask task, DeploymentBatch batch, CancellationToken ct)
    {
        var snapshot = await db.DeploymentMaterialSnapshots.AsNoTracking().SingleOrDefaultAsync(x => x.Id == task.MaterialSnapshotId, ct);
        CertificateMaterial material;
        if (snapshot is not null)
        {
            var payload = JsonSerializer.Deserialize<MaterialPayload>(MaterialProtector(snapshot.Id).Unprotect(snapshot.ProtectedPayload), Json)!;
            material = new() { Metadata = payload.Metadata, CertificatePem = payload.CertificatePem, ChainPem = payload.ChainPem,
                FullChainPem = payload.FullChainPem, PrivateKeyPem = payload.PrivateKeyPem,
                SourcePackages = (payload.SourcePackages ?? []).Select(package => new CertificateSourcePackage(package.Format,
                    package.Files.Select(file => new CertificateSourceFile(file.Name, file.Role, file.Content, file.Sha256, file.ContainsSecrets)).ToArray())).ToArray() };
        }
        else
        {
            var downloaded = await materials.GetAsync(batch.CertificateId, ct);
            if (!downloaded.Success || downloaded.Data is null) return ApiResult<CertificateMaterial>.Fail(downloaded.Code, downloaded.Message);
            material = downloaded.Data;
            var target = ReadTarget(task);
            if (!string.IsNullOrWhiteSpace(target.Configuration.SourceFormat))
            {
                var package = await materials.GetSourceAsync(batch.CertificateId, target.Configuration.SourceFormat, material.Metadata, ct);
                if (!package.Success || package.Data is null) return ApiResult<CertificateMaterial>.Fail(package.Code, package.Message);
                // 部分激活后不能混用重新下载的容器和密码文件；所有映射字节必须仍属于原固定源包。
                RemoteFileDeploymentService.FileDeploymentReceipt? receipt;
                try { receipt = JsonSerializer.Deserialize<RemoteFileDeploymentService.FileDeploymentReceipt>(task.ReceiptJson, Json); }
                catch (JsonException) { return ApiResult<CertificateMaterial>.Fail("RECOVERY_RECEIPT_INVALID", "原源包回执无法读取，不能重新组合已经部分部署的文件。"); }
                if (receipt?.Files is { Count: > 0 })
                {
                    var variables = RemotePathHelper.MaterialVariables(material.Metadata);
                    if (receipt.Files.Count != target.Configuration.Files.Count)
                        return ApiResult<CertificateMaterial>.Fail("MATERIAL_IDENTITY_CHANGED", "原源包文件集合不完整，不能混用新下载的容器和密码。");
                    foreach (var mapping in target.Configuration.Files)
                    {
                        var directory = string.IsNullOrWhiteSpace(mapping.Directory) ? target.Configuration.OutputDirectory : mapping.Directory;
                        var path = RemotePathHelper.Resolve(directory, mapping.FileName, target.ExecutorKey.StartsWith("windows.", StringComparison.Ordinal), variables);
                        var recorded = path.Success ? receipt.Files.SingleOrDefault(file => file.Path == path.Data) : null;
                        var file = package.Data.Files.SingleOrDefault(file => file.Name == mapping.SourceFileName && file.Role == mapping.Role);
                        if (recorded is null || file is null || recorded.NewDigest != Convert.ToHexString(SHA256.HashData(file.Content)))
                            return ApiResult<CertificateMaterial>.Fail("MATERIAL_IDENTITY_CHANGED", "重新下载的源包字节已变化，不能让原容器与新的密码或配套文件混合部署。");
                    }
                }
                material = new() { Metadata = material.Metadata, CertificatePem = material.CertificatePem, ChainPem = material.ChainPem,
                    FullChainPem = material.FullChainPem, PrivateKeyPem = material.PrivateKeyPem, SourcePackages = [package.Data] };
            }
        }
        if (material.Metadata.CertificateId != batch.CertificateId || material.Metadata.Fingerprint != batch.Fingerprint ||
            material.Metadata.MaterialDigest != batch.MaterialDigest || DeploymentSourceBinding.NormalizeDomain(material.Metadata.Domain) != DeploymentSourceBinding.NormalizeDomain(batch.CertificateDomain) ||
            material.Metadata.NotAfterUtc <= DateTime.UtcNow || material.Metadata.NotBeforeUtc > DateTime.UtcNow)
            return ApiResult<CertificateMaterial>.Fail("MATERIAL_IDENTITY_CHANGED", "恢复材料与本轮原证书不一致或已过期，不会重新申请。");
        return ApiResult<CertificateMaterial>.Ok(material);
    }

    private DeploymentMaterialSnapshot CreateMaterialSnapshot(CertificateMaterial material)
    {
        var id = ids.NewId(); var now = DateTime.UtcNow;
        var payload = new MaterialPayload(material.Metadata, material.CertificatePem, material.ChainPem, material.FullChainPem, material.PrivateKeyPem,
            material.SourcePackages.Select(package => new SourcePackagePayload(package.Format,
                package.Files.Select(file => new SourceFilePayload(file.Name, file.Role, file.Content, file.Sha256, file.ContainsSecrets)).ToArray())).ToArray());
        return new() { Id = id, CertificateId = material.Metadata.CertificateId, MetadataJson = JsonSerializer.Serialize(material.Metadata, Json),
            ProtectedPayload = MaterialProtector(id).Protect(JsonSerializer.Serialize(payload, Json)), CreatedAtUtc = now, ExpiresAtUtc = now.AddHours(24) };
    }

    private async Task RepairCompletedBindingAsync(DeploymentTask task, DeploymentBatch batch, CancellationToken ct)
    {
        if (task.Code != "OK" || task.FinishedAtUtc is null || task.VerificationLevel is not ("FilesChecked" or "PlatformReadback" or "TlsObserved")) return;
        if (await db.DeploymentBindings.AnyAsync(x => x.TargetId == task.TargetId && x.ResourceKey == task.ResourceKey, ct)) return;
        var inspected = await InspectAsync(task.Id, ct);
        if (!inspected.Success || inspected.Data?.MatchesExpected != true || inspected.Data.VerificationLevel is not ("FilesChecked" or "FileHashReadback" or "PlatformReadback" or "TlsObserved")) return;
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        // 网络核对期间可能已有后续部署提交；再次检查并让写事务保持互斥。
        if (await db.DeploymentBindings.AnyAsync(x => x.TargetId == task.TargetId && x.ResourceKey == task.ResourceKey, ct) ||
            await db.DeploymentTasks.AnyAsync(x => x.Id != task.Id && x.ResourceKey == task.ResourceKey && x.CreatedAtUtc >= task.CreatedAtUtc &&
                x.Status != "Draft" && x.Status != "Cancelled", ct)) return;
        db.DeploymentBindings.Add(new() { Id = ids.NewId(), TargetId = task.TargetId, ResourceKey = task.ResourceKey, CertificateId = batch.CertificateId,
            Fingerprint = batch.Fingerprint, MaterialDigest = batch.MaterialDigest, LastTaskId = task.Id, RemoteResourceId = task.RemoteResourceId, UpdatedAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
    }

    private async Task WaitForRecoveryAsync(DeploymentTask task, string message, CancellationToken ct)
    {
        DeploymentCredentials? credentials = null;
        try { credentials = ReadTarget(task).Credentials; } catch (CryptographicException) { }
        var safe = DeploymentSafeText.Redact(message, credentials);
        var changed = await db.DeploymentTasks.Where(x => x.Id == task.Id && x.Status == "Running" && x.LeaseId == task.LeaseId && x.LeaseUntilUtc > DateTime.UtcNow && !x.CancelRequested)
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Recovering").SetProperty(x => x.Phase, "RecoverWait")
                .SetProperty(x => x.Code, "RECOVERY_RETRY").SetProperty(x => x.Message, safe)
                .SetProperty(x => x.ReceiptJson, task.ReceiptJson).SetProperty(x => x.LeaseUntilUtc, DateTime.UtcNow.AddSeconds(30))
                .SetProperty(x => x.FinishedAtUtc, (DateTime?)null), ct);
        if (changed == 1) { task.Status = "Recovering"; await AddStepAsync(task.Id, "Recover", "Waiting", safe, ct); }
    }

    /// <summary>成功证明、资源绑定和任务状态同事务提交，防止重启留下成功但无绑定的半完成状态。</summary>
    private async Task CompleteWithBindingAsync(DeploymentTask task, DeploymentExecutionResult result, string certificateId,
        CertificateMaterialMetadata metadata, DeploymentTargetContext target, CancellationToken ct)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        DeploymentBinding? binding = null;
        try
        {
            var owned = await FinishAsync(task, result.Skipped ? "Skipped" : "Succeeded", "OK", result.Message, target, ct);
            if (!owned) return;
            binding = await db.DeploymentBindings.SingleOrDefaultAsync(x => x.TargetId == task.TargetId && x.ResourceKey == task.ResourceKey, ct);
            if (binding is null) { binding = new() { Id = ids.NewId(), TargetId = task.TargetId, ResourceKey = task.ResourceKey }; db.DeploymentBindings.Add(binding); }
            binding.CertificateId = certificateId; binding.Fingerprint = metadata.Fingerprint; binding.MaterialDigest = metadata.MaterialDigest;
            binding.LastTaskId = task.Id; binding.RemoteResourceId = task.RemoteResourceId; binding.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(ct); await RefreshBatchAsync(task.BatchId, ct); await transaction.CommitAsync(ct);
        }
        catch
        {
            // 回滚不会重置 EF 跟踪状态；不能让异常处理中的 SaveChanges 把绑定偷偷补写到事务外。
            if (binding is not null) db.Entry(binding).State = EntityState.Detached;
            throw;
        }
    }
}
