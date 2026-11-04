using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
namespace SslManager.Api.Service.impl.Deployment;

/// <summary>部署计划和任务持久化；不确定远端结果绝不自动重试。</summary>
public sealed partial class DeploymentService(AppDbContext db, IDeploymentTargetService targets,
    IDeploymentExecutorResolver executors, ICertificateMaterialService materials, IDataProtectionProvider protection,
    IIdGenerator ids, IServiceScopeFactory? scopes = null, IMcpExecutionGate? mcpGate = null) : IDeploymentService
{
    private static readonly JsonSerializerOptions Json = DeploymentTargetService.Json;
    private IDataProtector CredentialProtector(string id) => protection.CreateProtector("SslManager.Deployment.TaskCredentials.v1", id);
    private IDataProtector MaterialProtector(string id) => protection.CreateProtector("SslManager.Deployment.Material.v1", id);
    private sealed record MaterialPayload(CertificateMaterialMetadata Metadata, string CertificatePem, string ChainPem,
        string FullChainPem, string PrivateKeyPem, SourcePackagePayload[]? SourcePackages = null);
    // 源文件字节只进入 DataProtection 加密载荷，不进入计划、元数据、配置或 API 响应。
    private sealed record SourceFilePayload(string Name, string Role, byte[] Content, string Sha256, bool ContainsSecrets);
    private sealed record SourcePackagePayload(string Format, SourceFilePayload[] Files);

    public Task<ApiResult<DeploymentPlanView>> PlanAsync(string certificateId, DeploymentPlanRequest request, string userId, CancellationToken ct) =>
        PlanCoreAsync(certificateId, request, userId, null, null, ct);

    public Task<ApiResult<DeploymentPlanView>> PlanForScheduleAsync(string certificateId, DeploymentPlanRequest request,
        string userId, string scheduleRunId, string leaseToken, CancellationToken ct) =>
        PlanCoreAsync(certificateId, request, userId, scheduleRunId, leaseToken, ct);

    /// <summary>计划及 MCP 来源在同次保存关联，批次所有者始终是有效调用用户。</summary>
    public Task<ApiResult<DeploymentPlanView>> PlanForMcpAsync(string certificateId, DeploymentPlanRequest request,
        McpOperation operation, CancellationToken ct) =>
        PlanCoreAsync(certificateId, request, operation.EffectiveUserId, null, null, ct, operation);

    private async Task<ApiResult<DeploymentPlanView>> PlanCoreAsync(string certificateId, DeploymentPlanRequest request,
        string userId, string? scheduleRunId, string? leaseToken, CancellationToken ct, McpOperation? mcpOperation = null)
    {
        if (request.Targets is not { Count: > 0 and <= 20 } || request.Targets.Select(x => x.TargetId).Distinct().Count() != request.Targets.Count)
            return ApiResult<DeploymentPlanView>.Fail("VALIDATION", "请选择 1～20 个不同的部署目标。");
        var source = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(x => x.Id == certificateId, ct);
        if (source is null) return ApiResult<DeploymentPlanView>.Fail("NOT_FOUND", "证书不存在。");
        if (source.Status != "Issued") return ApiResult<DeploymentPlanView>.Fail("INVALID_STATE", "仅已签发证书可以部署。");
        var materialResult = await materials.GetAsync(certificateId, ct);
        if (!materialResult.Success || materialResult.Data is null) return ApiResult<DeploymentPlanView>.Fail(materialResult.Code, materialResult.Message);
        var material = materialResult.Data;
        if (material.Metadata.NotAfterUtc <= DateTime.UtcNow || material.Metadata.NotBeforeUtc > DateTime.UtcNow)
            return ApiResult<DeploymentPlanView>.Fail("CERTIFICATE_INVALID", "证书当前不在有效期内。");
        var now = DateTime.UtcNow;
        var batch = new DeploymentBatch { Id = ids.NewId(), CertificateId = certificateId, CertificateDomain = material.Metadata.Domain,
            Fingerprint = material.Metadata.Fingerprint, MaterialDigest = material.Metadata.MaterialDigest, CreatedBy = userId,
            CreatedAtUtc = now, ExpiresAtUtc = now.AddMinutes(10), MaterialSnapshotId = ids.NewId() };
        var staged = new List<DeploymentTask>(); var preview = new List<DeploymentPlanTargetView>(); var resources = new HashSet<string>(StringComparer.Ordinal);
        var sourcePackages = new Dictionary<string, CertificateSourcePackage>(StringComparer.Ordinal);
        foreach (var selection in request.Targets)
        {
            var contextResult = await targets.GetContextAsync(selection.TargetId, ct);
            if (!contextResult.Success || contextResult.Data is null) return ApiResult<DeploymentPlanView>.Fail(contextResult.Code, contextResult.Message);
            var target = contextResult.Data;
            if (!string.IsNullOrEmpty(target.Configuration.SourceFormat))
            {
                if (target.ExecutorKey != "linux.files.ssh.v1" || !DeploymentSourceBinding.Matches(target.Configuration, material.Metadata))
                    return ApiResult<DeploymentPlanView>.Fail("SOURCE_CERTIFICATE_MISMATCH", "此文件映射绑定了其他域名，请选择对应域名的证书或修改部署目标的绑定域名。");
                var format = target.Configuration.SourceFormat;
                if (!sourcePackages.TryGetValue(format, out var package))
                {
                    var downloaded = await materials.GetSourceAsync(certificateId, format, material.Metadata, ct);
                    if (!downloaded.Success || downloaded.Data is null)
                        return ApiResult<DeploymentPlanView>.Fail(downloaded.Code, downloaded.Message);
                    package = downloaded.Data;
                    sourcePackages.Add(format, package);
                }
                var resolvedMappings = new List<DeploymentFileMapping>();
                foreach (var mapping in target.Configuration.Files)
                {
                    var resolved = DeploymentSourceBinding.ResolveSourceFile(package, mapping);
                    if (!resolved.Success || resolved.Data is null)
                        return ApiResult<DeploymentPlanView>.Fail(resolved.Code, resolved.Message);
                    resolvedMappings.Add(mapping with { SourceFileName = resolved.Data.Name });
                }
                // 只固定本次任务的新源包路径，不改目标输出路径、命令或持久配置。
                target.Configuration.Files = resolvedMappings;
            }
            var executorResult = executors.Resolve(target.ExecutorKey);
            if (!executorResult.Success || executorResult.Data is null) return ApiResult<DeploymentPlanView>.Fail(executorResult.Code, executorResult.Message);
            if (executorResult.Data.Descriptor.Revision != target.ExecutorRevision)
                return ApiResult<DeploymentPlanView>.Fail("EXECUTOR_VERSION_CHANGED", "执行器修订已变化，请重新保存和测试目标。");
            var planResult = await executorResult.Data.PlanAsync(target, material.Metadata, selection, ct);
            if (!planResult.Success || planResult.Data is null) return ApiResult<DeploymentPlanView>.Fail(planResult.Code, DeploymentSafeText.Redact(planResult.Message, target.Credentials));
            var plan = planResult.Data;
            if (await db.DeploymentTasks.AnyAsync(x => x.ResourceKey == plan.ResourceKey && (x.Status == "NeedsAttention" || x.Status == "Recovering"), ct))
                return ApiResult<DeploymentPlanView>.Fail("TARGET_BUSY", "此远端资源存在结果未知的任务，请人工核对并明确解除后再部署。");
            if (string.IsNullOrWhiteSpace(plan.ResourceKey) || !resources.Add(plan.ResourceKey))
                return ApiResult<DeploymentPlanView>.Fail("RESOURCE_CONFLICT", "所选目标指向同一部署资源，请分别部署。");
            var taskId = ids.NewId();
            staged.Add(new() { Id = taskId, BatchId = batch.Id, TargetId = target.Id, TargetName = target.Name, ExecutorKey = target.ExecutorKey,
                ExecutorRevision = target.ExecutorRevision, ConfigRevision = target.ConfigRevision, ResourceKey = plan.ResourceKey,
                TargetSnapshotJson = JsonSerializer.Serialize(target, Json), ProtectedCredentials = CredentialProtector(taskId).Protect(JsonSerializer.Serialize(target.Credentials, Json)),
                PlanJson = JsonSerializer.Serialize(plan, Json), MaterialSnapshotId = batch.MaterialSnapshotId,
                ReceiptJson = target.ExecutorKey is "safeline.ce.9.x" or "synology.dsm.7.x" ? PlatformDeploymentCheckpoint.Prepared(plan).Serialize()
                    : "{\"schemaVersion\":1,\"executionState\":\"NotStarted\"}",
                Fingerprint = material.Metadata.Fingerprint, CreatedAtUtc = now, Message = DeploymentSafeText.Redact(plan.Summary, target.Credentials) });
            preview.Add(new(taskId, target.Id, target.Name, target.ExecutorKey, target.ConfigRevision, plan));
        }
        if (scheduleRunId is not null)
        {
            if (request.Targets.Count != 1)
                return ApiResult<DeploymentPlanView>.Fail("VALIDATION", "周期部署需要按目标独立生成计划。");
            var run = await db.CertificateScheduleRuns.SingleOrDefaultAsync(item => item.Id == scheduleRunId, ct);
            if (run is null) return ApiResult<DeploymentPlanView>.Fail("SCHEDULE_RUN_MISSING", "周期运行记录不存在。");
            await db.Entry(run).ReloadAsync(ct);
            if (!run.Active || run.LeaseToken != leaseToken || run.LeaseUntilUtc is not { } leaseUntil || leaseUntil <= DateTime.UtcNow || run.CertificateId != certificateId ||
                !await db.CertificateSchedules.AnyAsync(item => item.Id == run.ScheduleId && item.Enabled, ct))
                return ApiResult<DeploymentPlanView>.Fail("SCHEDULE_LEASE_LOST", "周期计划已停用或执行租约已变化。");
            var progress = JsonSerializer.Deserialize<List<ScheduleTargetProgress>>(run.TargetsJson, Json) ?? [];
            var selected = progress.SingleOrDefault(item => item.TargetId == request.Targets[0].TargetId);
            if (selected is null || !string.IsNullOrEmpty(selected.BatchId))
                return ApiResult<DeploymentPlanView>.Fail("SCHEDULE_BATCH_EXISTS", "本轮目标已有部署批次，不能重复生成。");
            if (selected.ConfigRevision > 0 && selected.ConfigRevision != staged.Single().ConfigRevision)
                return ApiResult<DeploymentPlanView>.Fail("CONFIGURATION_CHANGED", "本轮申请后目标配置已变化，不能自动采用新的输出路径或命令。");
            selected.BatchId = batch.Id; selected.Status = "Draft"; selected.Message = "部署批次已与本轮目标关联，等待提交。";
            run.TargetsJson = JsonSerializer.Serialize(progress, Json);
            db.AuditLogs.Add(new() { Id = ids.NewId(), UserId = userId, Username = "system", Action = "ScheduleDeploymentPlan",
                ResourceId = run.Id, Success = true, Code = "PLAN_SAVED", Message = "已固定目标部署批次：" + selected.TargetId, CreatedAtUtc = now });
        }
        var payload = new MaterialPayload(material.Metadata, material.CertificatePem, material.ChainPem, material.FullChainPem, material.PrivateKeyPem,
            sourcePackages.Values.Select(package => new SourcePackagePayload(package.Format,
                package.Files.Select(file => new SourceFilePayload(file.Name, file.Role, file.Content, file.Sha256, file.ContainsSecrets)).ToArray())).ToArray());
        await using var mcpTransaction = mcpOperation is null ? null : await db.Database.BeginTransactionAsync(ct);
        if (mcpOperation is not null)
        {
            mcpOperation.BatchId = batch.Id; mcpOperation.CertificateId = certificateId; mcpOperation.PlanRevision = batch.PlanRevision;
            mcpOperation.UpdatedAtUtc = now; mcpOperation.Version++;
        }
        db.DeploymentMaterialSnapshots.Add(new() { Id = batch.MaterialSnapshotId, CertificateId = certificateId,
            MetadataJson = JsonSerializer.Serialize(material.Metadata, Json), ProtectedPayload = MaterialProtector(batch.MaterialSnapshotId).Protect(JsonSerializer.Serialize(payload, Json)),
            CreatedAtUtc = now, ExpiresAtUtc = now.AddHours(24) });
        db.DeploymentBatches.Add(batch); db.DeploymentTasks.AddRange(staged);
        await db.SaveChangesAsync(ct);
        if (mcpTransaction is not null) await mcpTransaction.CommitAsync(ct);
        return ApiResult<DeploymentPlanView>.Ok(new(batch.Id, batch.PlanRevision, batch.ExpiresAtUtc, material.Metadata, preview), "部署计划已生成，请核对变更范围后提交。");
    }

    public async Task<ApiResult<DeploymentPlanView>> RollbackPlanAsync(string taskId, string userId, CancellationToken ct)
    {
        var source = await db.DeploymentTasks.AsNoTracking().SingleOrDefaultAsync(x => x.Id == taskId, ct);
        if (source is null) return ApiResult<DeploymentPlanView>.Fail("NOT_FOUND", "原部署任务不存在。");
        if (source.Status is not ("Succeeded" or "Failed" or "Resolved") || !string.IsNullOrEmpty(source.SourceTaskId))
            return ApiResult<DeploymentPlanView>.Fail("CONFLICT", "请先人工核对未知任务；只可恢复已经结束的原部署任务。");
        var executor = executors.Resolve(source.ExecutorKey);
        if (!executor.Success || executor.Data is not IRollbackDeploymentExecutor || !executor.Data.Descriptor.SupportsRollback)
            return ApiResult<DeploymentPlanView>.Fail("ROLLBACK_UNSUPPORTED", "此执行器不支持经过验证的恢复操作。");
        if (string.IsNullOrWhiteSpace(source.ReceiptJson) || source.ReceiptJson == "{}")
            return ApiResult<DeploymentPlanView>.Fail("ROLLBACK_UNAVAILABLE", "原任务没有可用的恢复回执。");
        var binding = await db.DeploymentBindings.AsNoTracking().SingleOrDefaultAsync(x => x.TargetId == source.TargetId && x.ResourceKey == source.ResourceKey, ct);
        if (binding is not null && binding.LastTaskId != source.Id)
            return ApiResult<DeploymentPlanView>.Fail("PLAN_STALE", "此资源已有后续部署，不能直接恢复旧任务。");
        var current = await db.DeploymentTargets.AsNoTracking().SingleOrDefaultAsync(x => x.Id == source.TargetId, ct);
        if (current is null || !current.Enabled || current.ConfigRevision != source.ConfigRevision)
            return ApiResult<DeploymentPlanView>.Fail("PLAN_STALE", "原目标配置已经变化或停用，请人工核对恢复范围。");
        if (await db.DeploymentTasks.AnyAsync(x => x.ResourceKey == source.ResourceKey && x.Status == "NeedsAttention", ct))
            return ApiResult<DeploymentPlanView>.Fail("TARGET_BUSY", "此资源存在待核对任务，请先核对解除。");
        var snapshot = await db.DeploymentMaterialSnapshots.AsNoTracking().SingleOrDefaultAsync(x => x.Id == source.MaterialSnapshotId, ct);
        if (snapshot is null) return ApiResult<DeploymentPlanView>.Fail("MATERIAL_UNAVAILABLE", "原部署元数据不存在，无法生成恢复计划。");
        var metadata = JsonSerializer.Deserialize<CertificateMaterialMetadata>(snapshot.MetadataJson, Json)!;
        DeploymentTargetContext target;
        try { target = ReadTarget(source); }
        catch (CryptographicException) { return ApiResult<DeploymentPlanView>.Fail("CREDENTIALS_UNAVAILABLE", "原任务凭据无法解密。"); }
        var sourcePlan = ReadPlan(source);
        var remote = await executor.Data.PlanAsync(target, metadata, new(target.Id, sourcePlan.RemoteResourceId, sourcePlan.SiteIds), ct);
        if (!remote.Success || remote.Data is null) return ApiResult<DeploymentPlanView>.Fail(remote.Code, remote.Message);
        var plan = remote.Data with { Action = "Rollback", Summary = "恢复原任务备份文件，不自动执行后置命令；恢复前再次核对当前文件和备份。" };
        if (plan.ResourceKey != source.ResourceKey) return ApiResult<DeploymentPlanView>.Fail("PLAN_STALE", "当前恢复资源范围与原任务不一致。");
        var sourceBatch = await db.DeploymentBatches.AsNoTracking().SingleAsync(x => x.Id == source.BatchId, ct);
        var now = DateTime.UtcNow; var id = ids.NewId();
        var batch = new DeploymentBatch { Id = ids.NewId(), OperationType = "Rollback", CertificateId = sourceBatch.CertificateId,
            CertificateDomain = sourceBatch.CertificateDomain, CreatedBy = userId, MaterialSnapshotId = source.MaterialSnapshotId,
            CreatedAtUtc = now, ExpiresAtUtc = now.AddMinutes(10) };
        var task = new DeploymentTask { Id = id, BatchId = batch.Id, SourceTaskId = source.Id, TargetId = source.TargetId,
            TargetName = source.TargetName, ExecutorKey = source.ExecutorKey, ExecutorRevision = source.ExecutorRevision,
            ConfigRevision = source.ConfigRevision, ResourceKey = source.ResourceKey, TargetSnapshotJson = source.TargetSnapshotJson,
            ProtectedCredentials = CredentialProtector(id).Protect(JsonSerializer.Serialize(target.Credentials, Json)),
            PlanJson = JsonSerializer.Serialize(plan, Json), MaterialSnapshotId = source.MaterialSnapshotId,
            ReceiptJson = source.ReceiptJson, CreatedAtUtc = now, Message = plan.Summary };
        db.DeploymentBatches.Add(batch); db.DeploymentTasks.Add(task); await db.SaveChangesAsync(ct);
        return ApiResult<DeploymentPlanView>.Ok(new(batch.Id, batch.PlanRevision, batch.ExpiresAtUtc, metadata,
            [new(task.Id, target.Id, target.Name, target.ExecutorKey, target.ConfigRevision, plan)]), "恢复计划已生成，确认后才执行。");
    }

    public Task<ApiResult<DeploymentBatchView>> SubmitAsync(string batchId, DeploymentSubmitRequest request, string userId, CancellationToken ct) =>
        SubmitCoreAsync(batchId, request, userId, null, ct);

    public Task<ApiResult<DeploymentBatchView>> SubmitForMcpAsync(string batchId, DeploymentSubmitRequest request, McpOperation operation, CancellationToken ct) =>
        SubmitCoreAsync(batchId, request, operation.EffectiveUserId, operation, ct);

    private async Task<ApiResult<DeploymentBatchView>> SubmitCoreAsync(string batchId, DeploymentSubmitRequest request, string userId, McpOperation? mcpOperation, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.IdempotencyKey) || request.IdempotencyKey.Length > 128)
            return ApiResult<DeploymentBatchView>.Fail("VALIDATION", "请提供 1～128 字符的提交幂等键。");
        var batch = await db.DeploymentBatches.AsNoTracking().SingleOrDefaultAsync(x => x.Id == batchId, ct);
        if (batch is null) return ApiResult<DeploymentBatchView>.Fail("NOT_FOUND", "部署计划不存在。");
        if (batch.CreatedBy != userId) return ApiResult<DeploymentBatchView>.Fail("FORBIDDEN", "只能提交自己创建的部署计划。");
        var key = userId + ":" + request.IdempotencyKey;
        if (batch.IdempotencyKey == key && batch.Status != "Draft") return await GetAsync(batchId, ct);
        if (batch.Status != "Draft" || batch.PlanRevision != request.PlanRevision || batch.ExpiresAtUtc <= DateTime.UtcNow)
            return ApiResult<DeploymentBatchView>.Fail("PLAN_STALE", "部署计划已提交或过期，请重新预览。");
        if (await db.DeploymentBatches.AnyAsync(x => x.IdempotencyKey == key && x.Id != batchId, ct))
            return ApiResult<DeploymentBatchView>.Fail("CONFLICT", "此幂等键已用于其他部署。");
        var taskRows = await db.DeploymentTasks.AsNoTracking().Where(x => x.BatchId == batchId).ToListAsync(ct);
        foreach (var task in taskRows)
        {
            if (await db.DeploymentTasks.AnyAsync(x => x.ResourceKey == task.ResourceKey && (x.Status == "NeedsAttention" || x.Status == "Recovering"), ct))
                return ApiResult<DeploymentBatchView>.Fail("TARGET_BUSY", "此远端资源存在待核对任务，提交已阻止。");
            var current = await db.DeploymentTargets.AsNoTracking().SingleOrDefaultAsync(x => x.Id == task.TargetId, ct);
            if (current is null || !current.Enabled || current.ConfigRevision != task.ConfigRevision)
                return ApiResult<DeploymentBatchView>.Fail("PLAN_STALE", "目标配置或启用状态已变化，请重新预览。");
        }
        if (batch.OperationType == "Deploy")
        {
            var fresh = await materials.GetAsync(batch.CertificateId, ct);
            if (!fresh.Success || fresh.Data is null || fresh.Data.Metadata.MaterialDigest != batch.MaterialDigest)
                return ApiResult<DeploymentBatchView>.Fail("PLAN_STALE", "证书材料已变化或无法核对，请重新预览。");
        }
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var changed = await db.DeploymentBatches.Where(x => x.Id == batchId && x.Status == "Draft" && x.PlanRevision == request.PlanRevision && x.ExpiresAtUtc > DateTime.UtcNow)
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Queued").SetProperty(x => x.IdempotencyKey, key).SetProperty(x => x.SubmittedAtUtc, DateTime.UtcNow), ct);
        if (changed != 1) return ApiResult<DeploymentBatchView>.Fail("CONFLICT", "部署计划已被另一请求提交。");
        await db.DeploymentTasks.Where(x => x.BatchId == batchId && x.Status == "Draft")
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Queued").SetProperty(x => x.Phase, "Queued").SetProperty(x => x.Message, "等待后台部署。"), ct);
        if (mcpOperation is not null)
        {
            mcpOperation.Status = "Queued"; mcpOperation.ConsumedAtUtc = DateTime.UtcNow;
            mcpOperation.Message = "部署已进入原任务队列。"; mcpOperation.Code = "QUEUED";
            mcpOperation.UpdatedAtUtc = DateTime.UtcNow; mcpOperation.Version++;
            await db.SaveChangesAsync(ct);
        }
        await transaction.CommitAsync(ct);
        return await GetAsync(batchId, ct);
    }

    public async Task<ApiResult<PageResult<DeploymentBatchView>>> ListAsync(int page, int pageSize, string? search, CancellationToken ct)
    {
        page = Math.Max(1, page); pageSize = Math.Clamp(pageSize, 1, 100);
        var query = db.DeploymentBatches.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search)) query = query.Where(x => x.CertificateDomain.Contains(search) || x.CertificateId.Contains(search));
        var total = await query.CountAsync(ct);
        var rows = await query.OrderByDescending(x => x.CreatedAtUtc).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        var views = new List<DeploymentBatchView>();
        foreach (var row in rows) views.Add(await ToBatchAsync(row, ct));
        return ApiResult<PageResult<DeploymentBatchView>>.Ok(new(views, total, page, pageSize));
    }
    public async Task<ApiResult<DeploymentBatchView>> GetAsync(string batchId, CancellationToken ct)
    {
        var row = await db.DeploymentBatches.AsNoTracking().SingleOrDefaultAsync(x => x.Id == batchId, ct);
        return row is null ? ApiResult<DeploymentBatchView>.Fail("NOT_FOUND", "部署批次不存在。") : ApiResult<DeploymentBatchView>.Ok(await ToBatchAsync(row, ct));
    }
    public async Task<ApiResult<DeploymentTaskView>> GetTaskAsync(string taskId, CancellationToken ct)
    {
        var row = await db.DeploymentTasks.AsNoTracking().SingleOrDefaultAsync(x => x.Id == taskId, ct);
        if (row is null) return ApiResult<DeploymentTaskView>.Fail("NOT_FOUND", "部署任务不存在。");
        var steps = await db.DeploymentTaskSteps.AsNoTracking().Where(x => x.TaskId == taskId).OrderBy(x => x.CreatedAtUtc)
            .Select(x => new DeploymentStepView(x.Id, x.Phase, x.Status, x.Message, x.CreatedAtUtc)).ToListAsync(ct);
        return ApiResult<DeploymentTaskView>.Ok(ToTask(row, steps));
    }
    public async Task<ApiResult<DeploymentTaskView>> CancelAsync(string taskId, CancellationToken ct)
    {
        var row = await db.DeploymentTasks.AsNoTracking().SingleOrDefaultAsync(x => x.Id == taskId, ct);
        if (row is null) return ApiResult<DeploymentTaskView>.Fail("NOT_FOUND", "部署任务不存在。");
        if (row.Status is not ("Draft" or "Queued" or "Running" or "Recovering")) return ApiResult<DeploymentTaskView>.Fail("CONFLICT", "任务已经结束。");
        // 与 Worker 领取竞争时，只有仍在排队的任务才能声明为“执行前取消”。
        var cancelled = await db.DeploymentTasks.Where(x => x.Id == taskId && (x.Status == "Draft" || x.Status == "Queued"))
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.CancelRequested, true).SetProperty(x => x.Status, "Cancelled")
                .SetProperty(x => x.Phase, "Cancelled").SetProperty(x => x.Message, "任务在远端执行前取消。").SetProperty(x => x.FinishedAtUtc, DateTime.UtcNow), ct);
        if (cancelled == 0)
        {
            // 恢复任务可能已经写入过远端；停止自动推进但继续保护原资源，不能称为执行前取消。
            var stopped = await db.DeploymentTasks.Where(x => x.Id == taskId && x.Status == "Recovering")
                .ExecuteUpdateAsync(update => update.SetProperty(x => x.CancelRequested, true).SetProperty(x => x.Status, "NeedsAttention")
                    .SetProperty(x => x.Phase, "RecoverStopped").SetProperty(x => x.Code, "CANCELLED_NEEDS_ATTENTION")
                    .SetProperty(x => x.Message, "已停止自动恢复，远端可能已有变更，保留原回执等待核对。")
                    .SetProperty(x => x.LeaseUntilUtc, (DateTime?)null).SetProperty(x => x.FinishedAtUtc, DateTime.UtcNow), ct);
            var requested = stopped == 1 ? 1 : await db.DeploymentTasks.Where(x => x.Id == taskId && x.Status == "Running")
                .ExecuteUpdateAsync(update => update.SetProperty(x => x.CancelRequested, true), ct);
            if (requested == 0) return ApiResult<DeploymentTaskView>.Fail("CONFLICT", "任务已经结束，请刷新查看结果。");
        }
        await RefreshBatchAsync(row.BatchId, ct);
        return await GetTaskAsync(taskId, ct);
    }
    public async Task<ApiResult<DeploymentInspection>> InspectAsync(string taskId, CancellationToken ct)
    {
        var row = await db.DeploymentTasks.AsNoTracking().SingleOrDefaultAsync(x => x.Id == taskId, ct);
        if (row is null) return ApiResult<DeploymentInspection>.Fail("NOT_FOUND", "部署任务不存在。");
        try
        {
            var context = ReadTarget(row); var plan = ReadPlan(row); var snapshot = await db.DeploymentMaterialSnapshots.AsNoTracking().SingleOrDefaultAsync(x => x.Id == row.MaterialSnapshotId, ct);
            if (snapshot is null) return ApiResult<DeploymentInspection>.Fail("MATERIAL_UNAVAILABLE", "材料元数据不存在。");
            var metadata = JsonSerializer.Deserialize<CertificateMaterialMetadata>(snapshot.MetadataJson, Json)!;
            var resolved = executors.Resolve(row.ExecutorKey);
            if (!resolved.Success || resolved.Data is null) return ApiResult<DeploymentInspection>.Fail(resolved.Code, resolved.Message);
            var result = await resolved.Data.InspectAsync(new(context, plan, metadata, row.ReceiptJson), ct);
            // 核对只补充证据；命令是否执行不能仅凭证书相同判定，因此不自动改写原任务为成功。
            if (result.Data is not null) await AddStepAsync(row.Id, "Inspect", result.Success ? "Succeeded" : "Failed", DeploymentSafeText.Redact(result.Data.Message, context.Credentials), ct);
            return result;
        }
        catch (CryptographicException) { return ApiResult<DeploymentInspection>.Fail("CREDENTIALS_UNAVAILABLE", "任务凭据无法解密。"); }
    }

    public async Task<ApiResult<DeploymentTaskView>> ResolveAsync(string taskId, string note, string userId, string username, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(note) || note.Length > 1000)
            return ApiResult<DeploymentTaskView>.Fail("VALIDATION", "请填写已人工核对的结果及解除原因，最多 1000 字符。");
        var row = await db.DeploymentTasks.SingleOrDefaultAsync(x => x.Id == taskId, ct);
        if (row is null) return ApiResult<DeploymentTaskView>.Fail("NOT_FOUND", "部署任务不存在。");
        if (row.Status != "NeedsAttention") return ApiResult<DeploymentTaskView>.Fail("CONFLICT", "只有结果未知的任务可人工解除。");
        DeploymentCredentials? secrets = null;
        try { secrets = ReadTarget(row).Credentials; } catch (CryptographicException) { }
        var safeNote = DeploymentSafeText.Redact(note.Trim(), secrets);
        // 人工解除只释放后续计划，不代表原任务或后置命令已经执行成功。
        row.Status = "Resolved"; row.Phase = "Resolved"; row.Code = "MANUALLY_RESOLVED";
        row.Message = "管理员人工核对后解除：" + safeNote; row.LeaseUntilUtc = null; row.FinishedAtUtc = DateTime.UtcNow;
        db.AuditLogs.Add(new() { Id = ids.NewId(), UserId = userId, Username = username, Action = "ResolveDeploymentResult",
            ResourceId = row.Id, Success = true, Code = "MANUALLY_RESOLVED", Message = safeNote, CreatedAtUtc = DateTime.UtcNow });
        await AddStepAsync(row.Id, "Resolved", "Resolved", row.Message, ct); await db.SaveChangesAsync(ct);
        await RefreshBatchAsync(row.BatchId, ct);
        return await GetTaskAsync(taskId, ct);
    }

    public async Task<bool> ProcessNextAsync(CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        // 失去租约只报告结果未知，不能重放可能已经完成的上传、绑定或重启。
        var expired = await db.DeploymentTasks.AsNoTracking().Where(x => x.Status == "Running" && (x.LeaseUntilUtc == null || x.LeaseUntilUtc < now)).ToListAsync(ct);
        foreach (var old in expired)
        {
            var recover = !old.CancelRequested && string.IsNullOrEmpty(old.SourceTaskId) && executors.Resolve(old.ExecutorKey).Data is IDeploymentRecoveryExecutor && await IsScheduledBatchAsync(old.BatchId, ct);
            await db.DeploymentTasks.Where(x => x.Id == old.Id && x.Status == "Running" && (x.LeaseUntilUtc == null || x.LeaseUntilUtc < now))
                .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, recover ? "Recovering" : "NeedsAttention").SetProperty(x => x.Code, "REMOTE_RESULT_UNKNOWN")
                    .SetProperty(x => x.Message, recover ? "执行中断，正在自动核对远端并恢复原任务。" : "执行租约中断，请核对远端结果；系统不会自动重试。")
                    .SetProperty(x => x.LeaseUntilUtc, (DateTime?)null).SetProperty(x => x.FinishedAtUtc, recover ? (DateTime?)null : now), ct);
            await RefreshBatchAsync(old.BatchId, ct);
        }
        var candidate = await db.DeploymentTasks.AsNoTracking().Where(x => (x.Status == "Queued" || x.Status == "Recovering" && (x.LeaseUntilUtc == null || x.LeaseUntilUtc <= now)) && !x.CancelRequested &&
                !db.DeploymentTasks.Any(running => running.Id != x.Id && (running.Status == "Running" || running.Status == "NeedsAttention" || running.Status == "Recovering") && running.ResourceKey == x.ResourceKey))
            .OrderBy(x => x.CreatedAtUtc).FirstOrDefaultAsync(ct);
        if (candidate is null) return false;
        var lease = ids.NewId();
        var recovering = candidate.Status == "Recovering";
        var claimed = await db.DeploymentTasks.Where(x => x.Id == candidate.Id && x.Status == candidate.Status && !x.CancelRequested &&
                (x.Status != "Recovering" || x.LeaseUntilUtc == null || x.LeaseUntilUtc <= now) &&
                !db.DeploymentTasks.Any(running => running.Id != x.Id && (running.Status == "Running" || running.Status == "NeedsAttention" || running.Status == "Recovering") && running.ResourceKey == x.ResourceKey))
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Running").SetProperty(x => x.Phase, recovering ? "Recover" : "Preflight")
                .SetProperty(x => x.LeaseId, lease).SetProperty(x => x.LeaseUntilUtc, now.AddMinutes(2)).SetProperty(x => x.StartedAtUtc, now), ct);
        if (claimed != 1) return true;
        db.ChangeTracker.Clear();
        var task = await db.DeploymentTasks.SingleAsync(x => x.Id == candidate.Id, ct);
        // 后续所有进度写入均带租约条件；不让跟踪实体绕过条件更新覆盖新执行者。
        db.Entry(task).State = EntityState.Detached;
        await RefreshBatchAsync(task.BatchId, ct);
        DeploymentTargetContext? target = null;
        var mcpMutationStarted = false;
        using var executionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        using var heartbeatCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var heartbeat = HeartbeatAsync(task.Id, lease, executionCts, heartbeatCts.Token);
        try
        {
            target = ReadTarget(task);
            if (mcpGate is not null)
            {
                var allowed = await mcpGate.CheckDeploymentAsync(task.BatchId, executionCts.Token);
                if (!allowed.Success)
                { await FinishAsync(task, "Failed", allowed.Code, allowed.Message, target, ct); return true; }
            }
            if (recovering && !await IsScheduledBatchAsync(task.BatchId, executionCts.Token))
            { await FinishAsync(task, "NeedsAttention", "SCHEDULE_RUN_ENDED", "原计划轮次已结束，已停止自动恢复并保留远端现场。", target, ct); return true; }
            if (recovering && await HasLaterResourceResultAsync(task, executionCts.Token))
            { await FinishAsync(task, "NeedsAttention", "RECOVERY_CONFLICT", "此资源已有后续部署或回滚结果，不能恢复旧任务的文件或命令。", target, ct); return true; }
            var current = await db.DeploymentTargets.AsNoTracking().SingleOrDefaultAsync(x => x.Id == task.TargetId, ct);
            if (current is null || !current.Enabled) { await FinishAsync(task, "Failed", "TARGET_DISABLED", "部署目标已停用。", target, ct); return true; }
            if (!string.IsNullOrEmpty(task.SourceTaskId))
            {
                await ExecuteRollbackAsync(task, target, executionCts.Token);
                return true;
            }
            var certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(x => x.Id == (db.DeploymentBatches.Where(b => b.Id == task.BatchId).Select(b => b.CertificateId).First()), ct);
            if (certificate is null || certificate.Status != "Issued") { await FinishAsync(task, "Failed", "CERTIFICATE_INVALID", "证书已不存在或不再是已签发状态。", target, ct); return true; }
            var snapshot = await db.DeploymentMaterialSnapshots.AsNoTracking().SingleOrDefaultAsync(x => x.Id == task.MaterialSnapshotId, ct);
            if ((snapshot is null || snapshot.ExpiresAtUtc <= DateTime.UtcNow) && await IsScheduledBatchAsync(task.BatchId, ct))
            {
                var batch = await db.DeploymentBatches.AsNoTracking().SingleAsync(x => x.Id == task.BatchId, ct);
                var rebuilt = await ReadOrRebuildMaterialAsync(task, batch, ct);
                if (!rebuilt.Success || rebuilt.Data is null) { await FinishAsync(task, "NeedsAttention", rebuilt.Code, rebuilt.Message, target, ct); return true; }
                var originalSnapshotId = task.MaterialSnapshotId;
                snapshot = CreateMaterialSnapshot(rebuilt.Data);
                await using var materialTransaction = await db.Database.BeginTransactionAsync(ct);
                db.DeploymentMaterialSnapshots.Add(snapshot); await db.SaveChangesAsync(ct);
                var saved = await db.DeploymentTasks.Where(x => x.Id == task.Id && x.Status == "Running" && x.LeaseId == lease && x.LeaseUntilUtc > DateTime.UtcNow)
                    .ExecuteUpdateAsync(update => update.SetProperty(x => x.MaterialSnapshotId, snapshot.Id), ct);
                if (saved != 1) return true;
                task.MaterialSnapshotId = snapshot.Id;
                await db.DeploymentBatches.Where(x => x.Id == task.BatchId).ExecuteUpdateAsync(update => update.SetProperty(x => x.MaterialSnapshotId, snapshot.Id), ct);
                db.AuditLogs.Add(new() { Id = ids.NewId(), UserId = "system", Username = "system", Action = "ScheduleDeploymentMaterialRebuilt", ResourceId = task.Id,
                    Success = true, Code = "MATERIAL_REBUILT", Message = $"原证书={batch.CertificateId}，原批次={batch.Id}，原材料快照={originalSnapshotId}，新材料快照={snapshot.Id}。", CreatedAtUtc = DateTime.UtcNow });
                await db.SaveChangesAsync(ct); await materialTransaction.CommitAsync(ct);
            }
            if (snapshot is null || snapshot.ExpiresAtUtc <= DateTime.UtcNow) { await FinishAsync(task, "Failed", "MATERIAL_UNAVAILABLE", "固定证书材料已缺失或过期，请重新生成计划。", target, ct); return true; }
            var payload = JsonSerializer.Deserialize<MaterialPayload>(MaterialProtector(snapshot.Id).Unprotect(snapshot.ProtectedPayload), Json)!;
            var material = new CertificateMaterial { Metadata = payload.Metadata, CertificatePem = payload.CertificatePem,
                ChainPem = payload.ChainPem, FullChainPem = payload.FullChainPem, PrivateKeyPem = payload.PrivateKeyPem,
                SourcePackages = (payload.SourcePackages ?? []).Select(package => new CertificateSourcePackage(package.Format,
                    package.Files.Select(file => new CertificateSourceFile(file.Name, file.Role, file.Content, file.Sha256, file.ContainsSecrets)).ToArray())).ToArray() };
            if (material.Metadata.NotAfterUtc <= DateTime.UtcNow) { await FinishAsync(task, "Failed", "CERTIFICATE_INVALID", "证书已过期。", target, ct); return true; }
            var resolved = executors.Resolve(task.ExecutorKey);
            if (!resolved.Success || resolved.Data is null || resolved.Data.Descriptor.Revision != task.ExecutorRevision)
            { await FinishAsync(task, "Failed", "EXECUTOR_UNSUPPORTED", "任务固定的执行器不可用或修订不一致。", target, ct); return true; }
            var plan = ReadPlan(task);
            var recheck = recovering ? ApiResult<DeploymentTargetPlan>.Ok(plan) : await resolved.Data.PlanAsync(target, material.Metadata,
                new(task.TargetId, plan.RemoteResourceId, plan.SiteIds) { UseConfiguredRemoteCertificateId = false }, executionCts.Token);
            if (!recheck.Success || recheck.Data is null)
            {
                if (resolved.Data is IDeploymentRecoveryExecutor && IsRecoveryTransient(recheck.Code) && await IsScheduledBatchAsync(task.BatchId, ct))
                    await WaitForRecoveryAsync(task, recheck.Message, ct);
                else await FinishAsync(task, "Failed", recheck.Code, recheck.Message, target, ct);
                return true;
            }
            if (recheck.Data.ResourceKey != plan.ResourceKey || recheck.Data.PreconditionsJson != plan.PreconditionsJson)
            { await FinishAsync(task, "Failed", "PLAN_STALE", "排队期间远端资源已变化，请重新预览。", target, ct); return true; }
            if (task.CancelRequested) { await FinishAsync(task, "Cancelled", "CANCELLED", "任务已取消。", target, ct); return true; }
            var context = new DeploymentExecutionContext
            {
                TaskId = task.Id, Target = target, Material = material, Plan = plan, IsRecovery = recovering, ReceiptJson = task.ReceiptJson,
                BeforeExternalMutationAsync = mcpGate is null ? null : async token =>
                {
                    var allowed = await mcpGate.CheckDeploymentAsync(task.BatchId, token);
                    if (!allowed.Success) throw new McpExecutionDeniedException(allowed.Code, allowed.Message);
                    mcpMutationStarted = true;
                },
                SaveCheckpointAsync = async (phase, receipt, token) =>
                {
                    var changed = await db.DeploymentTasks.Where(x => x.Id == task.Id && x.Status == "Running" && x.LeaseId == lease &&
                            x.LeaseUntilUtc > DateTime.UtcNow && !x.CancelRequested && db.DeploymentTargets.Any(current => current.Id == task.TargetId && current.Enabled) &&
                            (!recovering || db.CertificateScheduleRuns.Any(run => run.Active && run.TargetsJson.Contains(task.BatchId))))
                        .ExecuteUpdateAsync(update => update.SetProperty(x => x.ReceiptJson, receipt).SetProperty(x => x.Phase, phase)
                            .SetProperty(x => x.LeaseUntilUtc, DateTime.UtcNow.AddMinutes(2)), token);
                    if (changed != 1) throw new OperationCanceledException(token);
                    task.ReceiptJson = receipt; task.Phase = phase;
                    await AddStepAsync(task.Id, phase, "Checkpoint", "已持久化本步骤恢复信息。", token);
                },
                ReportProgressAsync = async (phase, message, token) =>
                {
                    var row = await db.DeploymentTasks.AsNoTracking().SingleAsync(x => x.Id == task.Id, token);
                    if (row.CancelRequested || row.Status != "Running" || row.LeaseId != lease) throw new OperationCanceledException(token);
                    if (recovering && !await IsScheduledBatchAsync(task.BatchId, token)) throw new OperationCanceledException(token);
                    var enabled = await db.DeploymentTargets.AsNoTracking().Where(x => x.Id == task.TargetId).Select(x => x.Enabled).FirstOrDefaultAsync(token);
                    if (!enabled) throw new OperationCanceledException(token);
                    task.Phase = phase; task.Message = DeploymentSafeText.Redact(message, target.Credentials);
                    var changed = await db.DeploymentTasks.Where(x => x.Id == task.Id && x.Status == "Running" && x.LeaseId == lease && x.LeaseUntilUtc > DateTime.UtcNow)
                        .ExecuteUpdateAsync(update => update.SetProperty(x => x.Phase, phase).SetProperty(x => x.Message, task.Message)
                            .SetProperty(x => x.LeaseUntilUtc, DateTime.UtcNow.AddMinutes(2)), token);
                    if (changed != 1) throw new OperationCanceledException(token);
                    await AddStepAsync(task.Id, phase, "Running", task.Message, token);
                }
            };
            ApiResult<DeploymentExecutionResult> result;
            if (recovering)
            {
                if (resolved.Data is not IDeploymentRecoveryExecutor recovery)
                { await FinishAsync(task, "NeedsAttention", "RECOVERY_UNSUPPORTED", "原执行器不支持经过验证的恢复。", target, ct); return true; }
                var recovered = await recovery.RecoverAsync(context, executionCts.Token);
                if (recovered.Data?.Result?.ReceiptJson is { Length: > 2 } recoveredReceipt) task.ReceiptJson = recoveredReceipt;
                if (recovered.Success && recovered.Data?.Disposition == "Completed" && recovered.Data.Result is not null)
                    result = ApiResult<DeploymentExecutionResult>.Ok(recovered.Data.Result);
                else if (recovered.Data?.Disposition == "Blocked")
                { await FinishAsync(task, "NeedsAttention", "RECOVERY_BLOCKED", recovered.Data.Message, target, ct); return true; }
                else
                { await WaitForRecoveryAsync(task, recovered.Data?.Message ?? recovered.Message, ct); return true; }
            }
            else result = await resolved.Data.ExecuteAsync(context, executionCts.Token);
            if (result.Data is not null)
            {
                task.VerificationLevel = result.Data.VerificationLevel;
                task.RemoteResourceId = result.Data.RemoteResourceId;
                task.ReceiptJson = result.Data.ReceiptJson;
            }
            if (result.Success && result.Data is not null)
            {
                await CompleteWithBindingAsync(task, result.Data, snapshot.CertificateId, material.Metadata, target, ct);
            }
            else
            {
                var unknown = IsUnknown(result.Code);
                if ((unknown || IsRecoveryTransient(result.Code)) && resolved.Data is IDeploymentRecoveryExecutor && await IsScheduledBatchAsync(task.BatchId, ct))
                    await WaitForRecoveryAsync(task, result.Message, ct);
                else await FinishAsync(task, unknown ? "NeedsAttention" : "Failed", result.Code, result.Message, target, ct);
            }
        }
        catch (McpExecutionDeniedException exception)
        {
            await FinishAsync(task, mcpMutationStarted ? "NeedsAttention" : "Failed", exception.Code,
                mcpMutationStarted ? "MCP 授权已撤销，已停止后续写入并保留原现场供核对。" : exception.Message, target, CancellationToken.None);
        }
        catch (OperationCanceledException)
        {
            var cancelled = await db.DeploymentTasks.AsNoTracking().Where(x => x.Id == task.Id).Select(x => x.CancelRequested).SingleAsync(CancellationToken.None);
            if (recovering && !await IsScheduledBatchAsync(task.BatchId, CancellationToken.None))
                await FinishAsync(task, "NeedsAttention", "SCHEDULE_RUN_ENDED", "原计划轮次已结束，已停止自动恢复并保留远端现场。", target, CancellationToken.None);
            else if (!cancelled && executors.Resolve(task.ExecutorKey).Data is IDeploymentRecoveryExecutor && await IsScheduledBatchAsync(task.BatchId, CancellationToken.None))
                await WaitForRecoveryAsync(task, "执行已中断，服务恢复后先核对远端，再继续原任务。", CancellationToken.None);
            else await FinishAsync(task, "NeedsAttention", "REMOTE_RESULT_UNKNOWN", "执行中断或取消，远端可能已有变更，请核对后处理。", target, CancellationToken.None);
        }
        catch (Exception)
        {
            var cancelled = await db.DeploymentTasks.AsNoTracking().Where(x => x.Id == task.Id).Select(x => x.CancelRequested).SingleAsync(CancellationToken.None);
            if (recovering && !await IsScheduledBatchAsync(task.BatchId, CancellationToken.None))
                await FinishAsync(task, "NeedsAttention", "SCHEDULE_RUN_ENDED", "原计划轮次已结束，已停止自动恢复并保留远端现场。", target, CancellationToken.None);
            else if (!cancelled && executors.Resolve(task.ExecutorKey).Data is IDeploymentRecoveryExecutor && await IsScheduledBatchAsync(task.BatchId, CancellationToken.None))
                await WaitForRecoveryAsync(task, "执行发生系统故障，稍后自动核对原部署结果。", CancellationToken.None);
            else await FinishAsync(task, "NeedsAttention", "REMOTE_RESULT_UNKNOWN", "执行发生系统故障，结果未知；请核对远端，系统不会重复执行。", target, CancellationToken.None);
        }
        finally
        {
            heartbeatCts.Cancel();
            try { await heartbeat; } catch (OperationCanceledException) { }
            await RefreshBatchAsync(task.BatchId, CancellationToken.None);
        }
        return true;
    }
    private async Task ExecuteRollbackAsync(DeploymentTask task, DeploymentTargetContext target, CancellationToken ct)
    {
        var resolved = executors.Resolve(task.ExecutorKey);
        if (!resolved.Success || resolved.Data is not IRollbackDeploymentExecutor rollback || !resolved.Data.Descriptor.SupportsRollback ||
            resolved.Data.Descriptor.Revision != task.ExecutorRevision)
        { await FinishAsync(task, "Failed", "ROLLBACK_UNSUPPORTED", "任务固定的恢复执行器不可用。", target, ct); return; }
        var binding = await db.DeploymentBindings.SingleOrDefaultAsync(x => x.TargetId == task.TargetId && x.ResourceKey == task.ResourceKey, ct);
        if (binding is not null && binding.LastTaskId != task.SourceTaskId)
        { await FinishAsync(task, "Failed", "PLAN_STALE", "此资源已有后续部署，已阻止覆盖。", target, ct); return; }
        var snapshot = await db.DeploymentMaterialSnapshots.AsNoTracking().SingleOrDefaultAsync(x => x.Id == task.MaterialSnapshotId, ct);
        if (snapshot is null) { await FinishAsync(task, "Failed", "MATERIAL_UNAVAILABLE", "恢复元数据不存在。", target, ct); return; }
        var metadata = JsonSerializer.Deserialize<CertificateMaterialMetadata>(snapshot.MetadataJson, Json)!;
        var plan = ReadPlan(task);
        var recheck = await resolved.Data.PlanAsync(target, metadata, new(task.TargetId, plan.RemoteResourceId, plan.SiteIds), ct);
        if (!recheck.Success || recheck.Data is null || recheck.Data.ResourceKey != plan.ResourceKey || recheck.Data.PreconditionsJson != plan.PreconditionsJson)
        { await FinishAsync(task, "Failed", "PLAN_STALE", "恢复计划生成后远端资源已变化，请重新核对。", target, ct); return; }
        if (await db.DeploymentTasks.AsNoTracking().Where(x => x.Id == task.Id).Select(x => x.CancelRequested).SingleAsync(ct))
        { await FinishAsync(task, "Cancelled", "CANCELLED", "恢复任务在写入前取消。", target, ct); return; }
        await AddStepAsync(task.Id, "Rollback", "Running", "开始核对原任务产物及备份，恢复不执行服务命令。", ct);
        var result = await rollback.RollbackAsync(new(target, task.SourceTaskId, task.ReceiptJson), ct);
        if (result.Success && result.Data is not null)
        {
            task.VerificationLevel = "FilesRestored"; task.Fingerprint = "";
            await using var transaction = await db.Database.BeginTransactionAsync(ct);
            try
            {
                var owned = await FinishAsync(task, "RolledBack", "OK", result.Data.Message, target, ct);
                if (!owned) return;
                if (binding is not null)
                {
                    binding.LastTaskId = task.Id; binding.CertificateId = ""; binding.Fingerprint = ""; binding.MaterialDigest = "";
                    binding.UpdatedAtUtc = DateTime.UtcNow; await db.SaveChangesAsync(ct);
                }
                await transaction.CommitAsync(ct);
            }
            catch
            {
                if (binding is not null) db.Entry(binding).State = EntityState.Detached;
                throw;
            }
        }
        else await FinishAsync(task, IsUnknown(result.Code) ? "NeedsAttention" : "Failed", result.Code, result.Message, target, ct);
    }

    private async Task HeartbeatAsync(string taskId, string lease, CancellationTokenSource executionCts, CancellationToken ct)
    {
        if (scopes is null) return;
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(20));
        try
        {
        while (await timer.WaitForNextTickAsync(ct))
        {
            using var scope = scopes.CreateScope(); var heartbeatDb = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var row = await heartbeatDb.DeploymentTasks.AsNoTracking().SingleOrDefaultAsync(x => x.Id == taskId, ct);
            if (row is null || row.CancelRequested || row.Status != "Running" || row.LeaseId != lease) { executionCts.Cancel(); return; }
            var updated = await heartbeatDb.DeploymentTasks.Where(x => x.Id == taskId && x.Status == "Running" && x.LeaseId == lease)
                .ExecuteUpdateAsync(update => update.SetProperty(x => x.LeaseUntilUtc, DateTime.UtcNow.AddMinutes(2)), ct);
            if (updated == 0) { executionCts.Cancel(); return; }
        }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception) { executionCts.Cancel(); }
    }
    private DeploymentTargetContext ReadTarget(DeploymentTask task)
    {
        var target = JsonSerializer.Deserialize<DeploymentTargetContext>(task.TargetSnapshotJson, Json)!;
        return new() { Id = target.Id, Name = target.Name, ExecutorKey = target.ExecutorKey, ExecutorRevision = target.ExecutorRevision,
            Endpoint = target.Endpoint, Port = target.Port, Username = target.Username, AuthenticationMode = target.AuthenticationMode,
            TlsFingerprint = target.TlsFingerprint, ConfigRevision = target.ConfigRevision, Configuration = target.Configuration,
            Credentials = JsonSerializer.Deserialize<DeploymentCredentials>(CredentialProtector(task.Id).Unprotect(task.ProtectedCredentials), Json)! };
    }
    private static DeploymentTargetPlan ReadPlan(DeploymentTask task) => JsonSerializer.Deserialize<DeploymentTargetPlan>(task.PlanJson, Json)!;
    private async Task<bool> FinishAsync(DeploymentTask task, string status, string code, string message, DeploymentTargetContext? target, CancellationToken ct)
    {
        var finished = DateTime.UtcNow; var safeMessage = DeploymentSafeText.Redact(message, target?.Credentials);
        var id = task.Id; var lease = task.LeaseId; var verification = task.VerificationLevel;
        var remote = task.RemoteResourceId; var receipt = task.ReceiptJson; var fingerprint = task.Fingerprint;
        // 旧 Runner 失去租约或管理员处理后，不能通过 ChangeTracker 把结果覆盖回成功。
        db.Entry(task).State = EntityState.Detached;
        var changed = await db.DeploymentTasks.Where(x => x.Id == id && x.Status == "Running" && x.LeaseId == lease && x.LeaseUntilUtc > finished)
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, status).SetProperty(x => x.Phase, status)
                .SetProperty(x => x.Code, code).SetProperty(x => x.Message, safeMessage).SetProperty(x => x.FinishedAtUtc, finished)
                .SetProperty(x => x.LeaseUntilUtc, (DateTime?)null).SetProperty(x => x.VerificationLevel, verification)
                .SetProperty(x => x.RemoteResourceId, remote).SetProperty(x => x.ReceiptJson, receipt).SetProperty(x => x.Fingerprint, fingerprint), ct);
        if (changed == 0)
        {
            var latest = await db.DeploymentTasks.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
            task.Status = latest?.Status ?? "NeedsAttention";
            return false;
        }
        task.Status = status; task.Phase = status; task.Code = code; task.Message = safeMessage; task.FinishedAtUtc = finished;
        await db.DeploymentTargets.Where(x => x.Id == task.TargetId).ExecuteUpdateAsync(update => update
            .SetProperty(x => x.LastDeploymentAtUtc, finished).SetProperty(x => x.LastDeploymentStatus, status), ct);
        await AddStepAsync(task.Id, status, status, safeMessage, ct);
        return true;
    }
    private async Task AddStepAsync(string taskId, string phase, string status, string message, CancellationToken ct)
    {
        db.DeploymentTaskSteps.Add(new() { Id = ids.NewId(), TaskId = taskId, Phase = phase, Status = status,
            Message = message.Length > 4000 ? message[..4000] : message, CreatedAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync(ct);
    }
    private async Task RefreshBatchAsync(string batchId, CancellationToken ct)
    {
        var states = await db.DeploymentTasks.AsNoTracking().Where(x => x.BatchId == batchId).Select(x => x.Status).ToListAsync(ct);
        if (states.Count == 0) return;
        var status = states.Contains("Running") ? "Running" : states.Contains("Recovering") ? "Queued" : states.Contains("Queued") ? "Queued" : states.All(x => x == "Draft") ? "Draft"
            : states.Contains("NeedsAttention") ? "NeedsAttention" : states.All(x => x is "Succeeded" or "Skipped") ? "Succeeded"
            : states.All(x => x == "Cancelled") ? "Cancelled" : states.All(x => x == "Resolved") ? "Resolved" : states.All(x => x == "RolledBack") ? "RolledBack" : states.Any(x => x is "Succeeded" or "Skipped") ? "PartiallySucceeded" : "Failed";
        await db.DeploymentBatches.Where(x => x.Id == batchId).ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, status), ct);
    }
    private async Task<DeploymentBatchView> ToBatchAsync(DeploymentBatch batch, CancellationToken ct)
    {
        var tasks = await db.DeploymentTasks.AsNoTracking().Where(x => x.BatchId == batch.Id).OrderBy(x => x.CreatedAtUtc).ToListAsync(ct);
        return new(batch.Id, batch.CertificateId, batch.CertificateDomain, batch.Fingerprint, batch.Status, batch.PlanRevision,
            batch.CreatedAtUtc, batch.ExpiresAtUtc, tasks.Select(x => ToTask(x)).ToArray(), batch.OperationType);
    }
    private static DeploymentTaskView ToTask(DeploymentTask task, IReadOnlyList<DeploymentStepView>? steps = null) => new(task.Id,
        task.BatchId, task.TargetId, task.TargetName, task.ExecutorKey, task.Status, task.Phase, task.Message, task.Code,
        task.VerificationLevel, task.Fingerprint, task.RemoteResourceId, task.CancelRequested, task.CreatedAtUtc,
        task.StartedAtUtc, task.FinishedAtUtc, steps, task.SourceTaskId);
    private static bool IsUnknown(string code) => code.Contains("UNKNOWN", StringComparison.OrdinalIgnoreCase)
        || code.Contains("Timeout", StringComparison.OrdinalIgnoreCase) || code.Contains("Disconnect", StringComparison.OrdinalIgnoreCase);
    private static bool IsRecoveryTransient(string code) => IsUnknown(code) || code is "NETWORK_ERROR" or "REMOTE_READ_FAILED" or "REMOTE_WRITE_FAILED" or "CONNECTION_FAILED" or "HTTP_ERROR" or "SERVICE_UNAVAILABLE" or "RATE_LIMITED";
}
