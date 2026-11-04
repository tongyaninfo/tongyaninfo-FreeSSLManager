using System.Text.Json;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;

namespace SslManager.Api.Common.Mcp;

/// <summary>SDK 2.3 的头校验会先将工具名读成字符串；极窄形状检查防止错误 JSON 类型触发 500。</summary>
public static class McpRequestShape
{
    public static async Task<bool> CheckAsync(HttpContext context)
    {
        if (!HttpMethods.IsPost(context.Request.Method) || context.Request.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) != true)
            return true;
        // 只使用有界内存，不启用可能落盘和自动删除临时文件的请求缓冲。
        var copy = new MemoryStream();
        var buffer = new byte[16384];
        while (true)
        {
            var read = await context.Request.Body.ReadAsync(buffer, context.RequestAborted);
            if (read == 0) break;
            if (copy.Length + read > 256 * 1024)
            {
                copy.Dispose(); context.Response.StatusCode = 413;
                await McpBoundaryMiddleware.RecordDeniedAsync(context, 413, "REQUEST_TOO_LARGE");
                return false;
            }
            copy.Write(buffer, 0, read);
        }
        copy.Position = 0; context.Request.Body = copy; context.Response.RegisterForDispose(copy);
        try
        {
            using var json = JsonDocument.Parse(copy.ToArray());
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("method", out var method)
                || method.ValueKind != JsonValueKind.String || method.GetString() != "tools/call") return true;
            var invalid = !root.TryGetProperty("params", out var parameters) || parameters.ValueKind != JsonValueKind.Object
                || !parameters.TryGetProperty("name", out var name) || name.ValueKind != JsonValueKind.String
                || parameters.TryGetProperty("arguments", out var arguments) && arguments.ValueKind is not (JsonValueKind.Object or JsonValueKind.Null);
            if (!invalid) return true;
            RequestId? id = null;
            if (root.TryGetProperty("id", out var value))
            {
                if (value.ValueKind == JsonValueKind.String) id = new RequestId(value.GetString()!);
                else if (value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out var number)) id = new RequestId(number);
            }
            // 仅使用 SDK 的标准错误 DTO；协议版本、生命周期、schema 和其余解析仍完全由 SDK 处理。
            context.Response.StatusCode = 400;
            await McpBoundaryMiddleware.RecordDeniedAsync(context, 400, "INVALID_ARGUMENTS");
            if (!id.HasValue) return false;
            await context.Response.WriteAsJsonAsync(new JsonRpcError
            {
                Id = id.Value, Error = new JsonRpcErrorDetail { Code = (int)McpErrorCode.InvalidParams, Message = "工具名称必须是字符串，参数必须是对象。" }
            }, context.RequestAborted);
            return false;
        }
        catch (JsonException) { return true; } // 完整 JSON 解析错误由 SDK 返回标准 ParseError。
    }
}
