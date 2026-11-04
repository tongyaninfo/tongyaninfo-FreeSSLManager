using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using System.Text.Json;

namespace SslManager.Api.Service;

/// <summary>MCP 受控操作只消费已持久化输入，Web 审批不能改变原有效调用身份。</summary>
public interface IMcpOperationService
{
    Task<ApiResult<McpOperationView>> PrepareApplicationAsync(McpCallerContext caller, CertificateApplyRequest request, string idempotencyKey, CancellationToken ct);
    Task<ApiResult<McpOperationView>> PrepareDeploymentAsync(McpCallerContext caller, string certificateId, DeploymentPlanRequest request, string idempotencyKey, CancellationToken ct);
    Task<ApiResult<McpOperationView>> SubmitAsync(McpCallerContext caller, string operationId, string idempotencyKey, CancellationToken ct);
    Task<ApiResult<McpOperationView>> GetAsync(McpCallerContext caller, string operationId, CancellationToken ct);
    Task<ApiResult<McpOperationView>> InvokeTargetTestAsync(McpCallerContext caller, string targetId, string idempotencyKey, string? operationId, CancellationToken ct);
    Task<ApiResult<McpOperationView>> InvokeInspectionAsync(McpCallerContext caller, string taskId, string idempotencyKey, string? operationId, CancellationToken ct);
    Task<ApiResult<McpOperationView>> InvokeBusinessAsync(McpCallerContext caller, string toolName, JsonElement input,
        string idempotencyKey, string? operationId, CancellationToken ct);
    Task<ApiResult<McpOperationView>> ApproveAsync(string operationId, string adminUserId, bool approve, int expectedVersion, CancellationToken ct);
    Task<ApiResult<PageResult<McpOperationView>>> ListForAdminAsync(int page, int pageSize, string? status, CancellationToken ct);
    Task<ApiResult<McpOperationView>> GetForAdminAsync(string operationId, CancellationToken ct);
}
