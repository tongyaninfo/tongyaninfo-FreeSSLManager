using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl.Deployment.Executors;

/// <summary>Windows SSH 文件部署，显式指定 PowerShell 或 cmd，不能把 Windows 路径当成 Linux 路径。</summary>
public sealed class WindowsSshDeploymentExecutor(RemoteFileDeploymentService files) : IDeploymentExecutor, IRollbackDeploymentExecutor, IDeploymentRecoveryExecutor
{
    public DeploymentExecutorDescriptor Descriptor { get; } = new("windows.files.ssh.v1", "Windows SSH 文件部署", "ServerFiles", "Windows",
        "SSH", AuthenticationModes: ["Password", "PrivateKey"], MaterialFormats: ["Leaf", "Chain", "FullChain", "PrivateKey", "Pfx"], SupportsRollback: true);
    public Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct) => files.TestAsync(target, true, ct);
    public Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target, CertificateMaterialMetadata material, DeploymentSelection selection, CancellationToken ct) =>
        files.PlanAsync(target, material, true, ct);
    public Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct) => files.ExecuteAsync(context, true, ct);
    public Task<ApiResult<DeploymentRecoveryResult>> RecoverAsync(DeploymentExecutionContext context, CancellationToken ct) => files.RecoverAsync(context, true, ct);
    public Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct) => files.InspectAsync(context, true, ct);
    public Task<ApiResult<DeploymentRollbackResult>> RollbackAsync(DeploymentRollbackContext context, CancellationToken ct) => files.RollbackAsync(context, ct);
}
