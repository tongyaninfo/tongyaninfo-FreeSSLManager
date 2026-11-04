using System.Text.Json;
using SslManager.Api.Common;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service;

/// <summary>标准协议入口只负责传输；工具目录、资源过滤和业务操作由明确的适配器实现。</summary>
public interface IMcpToolDispatcher
{
    IReadOnlyList<McpToolDescriptor> Catalog { get; }
    Task<IReadOnlyList<McpToolDescriptor>> ListAsync(McpCallerContext caller, CancellationToken ct);
    Task<ApiResult<object>> CallAsync(McpCallerContext caller, string toolName, JsonElement arguments, CancellationToken ct);
}
