using SslManager.Api.Common;
using SslManager.Api.Models.Mcp;
namespace SslManager.Api.Service;
public interface IMcpConfigurationService
{
    Task<ApiResult<McpSettingsView>> GetAsync(CancellationToken ct);
    Task<ApiResult<McpSettingsView>> SaveAsync(McpSettingsInput input, CancellationToken ct);
    Task<ApiResult<McpStatusView>> StatusAsync(CancellationToken ct);
}
