using SslManager.Api.Common;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service;

public interface IMcpApiKeyService
{
    Task<ApiResult<McpApiKeyView[]>> ListAsync(string clientId, CancellationToken ct);
    Task<ApiResult<McpApiKeyCreated>> CreateAsync(string clientId, McpApiKeyInput input, CancellationToken ct);
    Task<ApiResult<McpApiKeyView>> SetStatusAsync(string id, McpStatusInput input, CancellationToken ct);
    Task<ApiResult<McpApiKeyCreated>> RotateAsync(string id, CancellationToken ct, int? configRevision = null);
    Task<ApiResult<McpApiKeyView>> RevokeAsync(string id, CancellationToken ct, int? configRevision = null);
    Task<McpApiKey?> ValidateAsync(string secret, CancellationToken ct);
}
