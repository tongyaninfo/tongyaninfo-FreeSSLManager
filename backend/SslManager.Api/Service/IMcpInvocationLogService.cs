using SslManager.Api.Common;
using SslManager.Api.Models.Mcp;
namespace SslManager.Api.Service;
public interface IMcpInvocationLogService
{
    Task<string> StartAsync(McpCallerContext caller, string method, string toolName, string requestId, string version, CancellationToken ct);
    Task CompleteAsync(string id, bool success, string code, bool unknown, CancellationToken ct);
    Task<ApiResult<PageResult<McpInvocationLog>>> ListAsync(McpInvocationQuery query, CancellationToken ct);
    Task<ApiResult<McpInvocationLog>> GetAsync(string id, CancellationToken ct);
    Task FinalizeHttpAsync(string id, McpHttpAuditCompletion result, CancellationToken ct);
    Task<ApiResult<McpAuditStatistics>> StatisticsAsync(DateTime? fromUtc, DateTime? toUtc, CancellationToken ct);
}
