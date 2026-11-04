using SslManager.Api.Common;
using SslManager.Api.Models;
namespace SslManager.Api.Service;

/// <summary>执行器只处理目标系统差异，不读取云平台凭据。</summary>
public interface IDeploymentExecutor
{
    DeploymentExecutorDescriptor Descriptor { get; }
    Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct);
    Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target, CertificateMaterialMetadata material, DeploymentSelection selection, CancellationToken ct);
    Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct);
    Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct);
}
/// <summary>发现远端候选资源的执行器额外实现。</summary>
public interface IDeploymentDiscoveryExecutor
{
    Task<ApiResult<DeploymentDiscovery>> DiscoverAsync(DeploymentTargetContext target, CancellationToken ct);
}
/// <summary>恢复必须先核对远端，再继续缺少的步骤；不能把未知写入直接重新执行。</summary>
public interface IDeploymentRecoveryExecutor
{
    Task<ApiResult<DeploymentRecoveryResult>> RecoverAsync(DeploymentExecutionContext context, CancellationToken ct);
}
public interface IRollbackDeploymentExecutor
{
    Task<ApiResult<DeploymentRollbackResult>> RollbackAsync(DeploymentRollbackContext context, CancellationToken ct);
}
