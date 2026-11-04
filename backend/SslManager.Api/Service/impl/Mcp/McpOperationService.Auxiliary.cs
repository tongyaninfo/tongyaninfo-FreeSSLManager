using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Mcp;

public sealed partial class McpOperationService
{
    private sealed record AuxiliaryResource(McpResourceScope Scope, int ConfigRevision);
    public Task<ApiResult<McpOperationView>> InvokeTargetTestAsync(McpCallerContext caller, string targetId,
        string idempotencyKey, string? operationId, CancellationToken ct) =>
        InvokeAuxiliaryAsync(caller, targetId, idempotencyKey, operationId, false, ct);

    public Task<ApiResult<McpOperationView>> InvokeInspectionAsync(McpCallerContext caller, string taskId,
        string idempotencyKey, string? operationId, CancellationToken ct) =>
        InvokeAuxiliaryAsync(caller, taskId, idempotencyKey, operationId, true, ct);

    private async Task<ApiResult<McpOperationView>> InvokeAuxiliaryAsync(McpCallerContext caller, string resourceId,
        string key, string? operationId, bool inspect, CancellationToken ct)
    {
        var kind = inspect ? "TaskInspection" : "TargetTest";
        var tool = inspect ? "ssl_deployment_tasks_inspect" : "ssl_deployment_targets_test";
        McpOperation? operation;
        if (string.IsNullOrEmpty(operationId))
        {
            var resource = await AuxiliaryResourceAsync(resourceId, inspect, ct);
            if (!resource.Success || resource.Data is null) return Fail(resource.Code, resource.Message);
            var prepared = await PrepareAsync(caller, kind, tool, new AuxiliaryArguments(resourceId, resource.Data.ConfigRevision, resource.Data.Scope.TargetId), [resource.Data.Scope],
                JsonSerializer.Serialize(inspect ? new { taskId = resourceId, configRevision = resource.Data.ConfigRevision, operationSummary = "对原部署任务进行远端核对并记录步骤。" }
                    : (object)new { targetId = resourceId, configRevision = resource.Data.ConfigRevision, operationSummary = "只测试已保存目标；更新连接测试时间，不接受任意主机或凭据。" }, Json), key, ct);
            if (!prepared.Success || prepared.Data is null) return prepared;
            operation = await db.McpOperations.SingleAsync(row => row.Id == prepared.Data.Id, ct);
            if (operation.Status != "Approved" || operation.ConsumedAtUtc is not null)
                return await AuxiliaryResultAsync(operation, ct);
        }
        else
        {
            operation = await db.McpOperations.SingleOrDefaultAsync(row => row.Id == operationId, ct);
            if (operation is null || operation.Kind != kind ||
                JsonSerializer.Deserialize<AuxiliaryArguments>(operation.ArgumentsJson, Json)?.ResourceId != resourceId)
                return Fail("IDEMPOTENCY_CONFLICT", "原操作与当前测试/核对资源不一致。");
        }
        var valid = await ValidateConsumptionAsync(operation, caller, key, ct);
        if (valid is not null) return valid;
        if (operation.ConsumedAtUtc is not null) return await AuxiliaryResultAsync(operation, ct);
        var fixedArguments = JsonSerializer.Deserialize<AuxiliaryArguments>(operation.ArgumentsJson, Json)!;
        if (!await db.DeploymentTargets.AsNoTracking().AnyAsync(target => target.Id == fixedArguments.TargetId && target.Enabled && target.ConfigRevision == fixedArguments.ConfigRevision, ct))
            return Fail("MCP_APPROVAL_STALE", "原目标的连接配置或启用状态已改变，请重新准备。");
        var now = DateTime.UtcNow;
        operation.ConsumedAtUtc = now; operation.Status = "Executing"; operation.LeaseToken = ids.NewId();
        operation.LeaseUntilUtc = now.AddMinutes(5); operation.UpdatedAtUtc = now; operation.Version++;
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateConcurrencyException) { return Fail("CONFLICT", "此操作已被另一请求消费，请查询原操作。"); }
        var allowed = await AuthorizeResourcesAsync(Caller(operation), tool, ReadResources(operation).Resources, true, ct);
        if (!allowed.Success) return await FailedPreparationAsync(operation, allowed.Code, allowed.Message, ct);
        try
        {
            bool success;
            string code;
            string message;
            object result;
            if (inspect)
            {
                var inspected = await deployments.InspectAsync(resourceId, ct);
                success = inspected.Success; code = inspected.Code;
                message = success ? "任务核对已完成。" : "任务核对未完成，请在 Web 查看关联任务。";
                result = new { success, code, message, matchesExpected = inspected.Data?.MatchesExpected,
                    verificationLevel = inspected.Data?.VerificationLevel };
                operation.TaskId = resourceId;
            }
            else
            {
                var tested = await targets.TestAsync(resourceId, ct);
                success = tested.Success; code = tested.Code;
                message = success ? "目标连接测试已完成。" : "目标连接测试未通过，请在 Web 查看部署目标。";
                result = new { success, code, message };
            }
            var snapshot = ReadResources(operation);
            operation.ResourceJson = JsonSerializer.Serialize(snapshot with { SummaryJson = JsonSerializer.Serialize(new
                { resourceId, result }, Json) }, Json);
            operation.Status = success ? "Succeeded" : "Failed"; operation.Code = code; operation.Message = message;
        }
        catch (Exception)
        {
            operation.Status = "Unknown"; operation.Code = "RESULT_UNKNOWN";
            operation.Message = "连接测试或任务核对中断；保留原操作，不自动重新执行。";
        }
        operation.LeaseUntilUtc = null; operation.UpdatedAtUtc = DateTime.UtcNow; operation.Version++;
        await db.SaveChangesAsync(CancellationToken.None);
        return await AuxiliaryResultAsync(operation, CancellationToken.None);
    }

    private async Task<ApiResult<McpOperationView>> AuxiliaryResultAsync(McpOperation operation, CancellationToken ct)
    {
        var view = await ViewAsync(operation, ct);
        // 查询原结果成功不代表执行成功；失败/未知的幂等复用同样携带工具错误，保留原 operation ID。
        return view.Status is "Failed" or "Unknown" or "Blocked"
            ? new(false, string.IsNullOrEmpty(view.Code) ? "RESULT_UNKNOWN" : view.Code, view.Message, view)
            : ApiResult<McpOperationView>.Ok(view);
    }

    private async Task<ApiResult<AuxiliaryResource>> AuxiliaryResourceAsync(string id, bool inspect, CancellationToken ct)
    {
        if (inspect)
        {
            var task = await db.DeploymentTasks.AsNoTracking().SingleOrDefaultAsync(row => row.Id == id, ct);
            if (task is null) return ApiResult<AuxiliaryResource>.Fail("NOT_FOUND", "部署任务不存在。");
            var batch = await db.DeploymentBatches.AsNoTracking().SingleAsync(row => row.Id == task.BatchId, ct);
            var certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(row => row.Id == batch.CertificateId, ct);
            if (certificate is null) return ApiResult<AuxiliaryResource>.Fail("CERTIFICATE_UNAVAILABLE", "原任务证书范围无法核对。");
            var inspectionTarget = await db.DeploymentTargets.AsNoTracking().SingleOrDefaultAsync(row => row.Id == task.TargetId && row.Enabled, ct);
            if (inspectionTarget is null) return ApiResult<AuxiliaryResource>.Fail("TARGET_UNAVAILABLE", "原任务的目标已不存在或停用。");
            return ApiResult<AuxiliaryResource>.Ok(new(new(certificate.AccountId, NormalizeDomain(certificate.Domain), task.TargetId), inspectionTarget.ConfigRevision));
        }
        var target = await db.DeploymentTargets.AsNoTracking().SingleOrDefaultAsync(row => row.Id == id && row.Enabled, ct);
        if (target is null) return ApiResult<AuxiliaryResource>.Fail("NOT_FOUND", "已启用的部署目标不存在。");
        DeploymentTargetConfiguration? configuration;
        try { configuration = JsonSerializer.Deserialize<DeploymentTargetConfiguration>(target.ConfigurationJson, Json); }
        catch (JsonException) { return ApiResult<AuxiliaryResource>.Fail("TARGET_INVALID", "部署配置无法读取。"); }
        return ApiResult<AuxiliaryResource>.Ok(new(new(Domain: NormalizeDomain(configuration?.SourceDomain), TargetId: id), target.ConfigRevision));
    }
}
