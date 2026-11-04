using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Deployment;

public sealed partial class DeploymentService
{
    /// <summary>沿用原恢复计划校验，在同一事务内关联原 MCP 身份，避免孤立批次通过 Web 提交绕过原 Key 撤销。</summary>
    public async Task<ApiResult<DeploymentPlanView>> RollbackPlanForMcpAsync(string taskId, McpOperation operation, CancellationToken ct)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var result = await RollbackPlanAsync(taskId, operation.EffectiveUserId, ct);
        if (!result.Success || result.Data is null) return result;
        operation.BatchId = result.Data.BatchId;
        operation.CertificateId = result.Data.Certificate.CertificateId;
        operation.PlanRevision = result.Data.PlanRevision;
        operation.UpdatedAtUtc = DateTime.UtcNow;
        operation.Version++;
        await db.SaveChangesAsync(ct);
        await transaction.CommitAsync(ct);
        return result;
    }
}
