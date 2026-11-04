using SslManager.Api.Common;
using SslManager.Api.Models.Mcp;
namespace SslManager.Api.Service;
public interface IMcpClientService
{
    Task<ApiResult<PageResult<McpClientView>>> ListAsync(int page, int pageSize, CancellationToken ct, string? search = null);
    Task<ApiResult<McpClientCreated>> CreateAsync(McpClientInput input, CancellationToken ct);
    Task<ApiResult<McpClientView>> UpdateAsync(string id, McpClientInput input, CancellationToken ct);
    Task<ApiResult<McpClientView>> SetStatusAsync(string id, McpStatusInput input, CancellationToken ct);
    Task<ApiResult<McpSecretView>> RotateSecretAsync(string id, CancellationToken ct);
    Task<ApiResult<bool>> RevokeAsync(string id, CancellationToken ct);
    Task<ApiResult<McpAllowRulesView>> GetRulesAsync(string id, CancellationToken ct);
    Task<ApiResult<McpAllowRulesView>> SaveRulesAsync(string id, McpAllowRulesInput input, CancellationToken ct);
    Task<ApiResult<McpConnectionProfile>> ProfileAsync(string id, CancellationToken ct);
}
