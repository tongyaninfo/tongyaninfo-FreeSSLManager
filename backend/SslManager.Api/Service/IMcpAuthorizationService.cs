using SslManager.Api.Common;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service;

/// <summary>请求与后台执行统一实时门禁；worker 使用已保存授权，不依赖旧 access token 时效。</summary>
public interface IMcpAuthorizationService
{
    Task<ApiResult<McpEffectivePermission>> AuthorizeAsync(McpCallerContext caller, string toolName,
        McpResourceScope? resource, bool worker, CancellationToken ct);
}
