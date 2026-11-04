using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl.Deployment.Executors;

/// <summary>Linux 路径和权限语义；文件编排与 Windows SSH 复用。</summary>
public sealed class LinuxSshDeploymentExecutor(RemoteFileDeploymentService files) : IDeploymentExecutor, IRollbackDeploymentExecutor, IDeploymentRecoveryExecutor
{
    public DeploymentExecutorDescriptor Descriptor { get; } = new("linux.files.ssh.v1", "Linux SSH 文件部署", "ServerFiles", "Linux",
        "SSH", AuthenticationModes: ["Password", "PrivateKey"], MaterialFormats: ["Leaf", "Chain", "FullChain", "PrivateKey", "Pfx"], SupportsRollback: true);
    public Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct) => files.TestAsync(target, false, ct);
    public Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target, CertificateMaterialMetadata material, DeploymentSelection selection, CancellationToken ct) =>
        files.PlanAsync(target, material, false, ct);
    public Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct) => files.ExecuteAsync(context, false, ct);
    public Task<ApiResult<DeploymentRecoveryResult>> RecoverAsync(DeploymentExecutionContext context, CancellationToken ct) => files.RecoverAsync(context, false, ct);
    public Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct) => files.InspectAsync(context, false, ct);
    public Task<ApiResult<DeploymentRollbackResult>> RollbackAsync(DeploymentRollbackContext context, CancellationToken ct) => files.RollbackAsync(context, ct);
}
