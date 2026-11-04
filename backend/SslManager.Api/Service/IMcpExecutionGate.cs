using SslManager.Api.Common;

namespace SslManager.Api.Service;

/// <summary>在外部写入前重新读取 MCP 授权；没有 MCP 来源的既有 Web 任务不受开关影响。</summary>
public interface IMcpExecutionGate
{
    Task<ApiResult<bool>> CheckOperationAsync(string operationId, CancellationToken ct);
    Task<ApiResult<bool>> CheckCertificateAsync(string certificateId, CancellationToken ct);
    Task<ApiResult<bool>> CheckDeploymentAsync(string batchId, CancellationToken ct);
}

/// <summary>撤销后保留现场，执行器不得把门禁拒绝当成可重试网络错误。</summary>
public sealed class McpExecutionDeniedException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
