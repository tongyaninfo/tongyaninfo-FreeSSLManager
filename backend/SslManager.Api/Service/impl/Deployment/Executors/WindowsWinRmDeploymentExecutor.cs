using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl.Deployment.Executors;

/// <summary>显式保留 WinRM 能力门槛，不用明文 Basic 或未验证的本机 PowerShell 假装跨平台可用。</summary>
public sealed class WindowsWinRmDeploymentExecutor : IDeploymentExecutor
{
    private const string Reason = "WinRM 跨平台认证、消息加密和文件传输尚未完成兼容性验证；当前请选择已配置 SSH 的 Windows 目标。";
    public DeploymentExecutorDescriptor Descriptor { get; } = new("windows.files.winrm.v1", "Windows WinRM 文件部署", "ServerFiles", "Windows",
        "WinRM", Available: false, UnavailableReason: Reason, AuthenticationModes: ["Password"]);
    public Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct) => Unavailable<DeploymentConnectionTest>();
    public Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target, CertificateMaterialMetadata material, DeploymentSelection selection, CancellationToken ct) => Unavailable<DeploymentTargetPlan>();
    public Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct) => Unavailable<DeploymentExecutionResult>();
    public Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct) => Unavailable<DeploymentInspection>();
    private static Task<ApiResult<T>> Unavailable<T>() => Task.FromResult(ApiResult<T>.Fail("EXECUTOR_UNAVAILABLE", Reason));
}
