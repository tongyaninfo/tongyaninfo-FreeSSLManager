using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Common.Mcp;

/// <summary>每个HTTP请求独立关联业务账本；不使用会话级静态状态，防止不同客户端上下文串用。</summary>
public static class McpAuditCapture
{
    private const string Key = "Mcp.AuditState";
    private static readonly HashSet<string> Methods = new(StringComparer.Ordinal)
    { "server/discover", "initialize", "notifications/initialized", "notifications/cancelled", "tools/list", "tools/call", "ping", "resources/list", "prompts/list" };
    public static McpAuditState State(HttpContext context)
    {
        if (context.Items.TryGetValue(Key, out var value) && value is McpAuditState state) return state;
        var created = new McpAuditState(); context.Items[Key] = created; return created;
    }
    public static bool HasInvocation(HttpContext context) => State(context).InvocationId is not null;
    public static void MarkInvocation(HttpContext context, string id) => State(context).InvocationId = id;
    public static void MarkPersisted(HttpContext context, string id)
    { var state = State(context); state.InvocationId = id; state.PersistedDenial = true; }
    public static string Snapshot(HttpContext context) => McpAuditPayloads.Write(State(context).Context);
    public static void SetInput(HttpContext context, string toolName, JsonElement input)
    {
        var state = State(context); var safe = McpAuditPayloads.Input(toolName, input);
        state.Context = state.Context with { Input = safe.Value, InputCaptured = true, InputTruncated = safe.Truncated,
            Truncated = state.Context.Truncated || safe.Truncated };
    }
    public static void SetOutput(HttpContext context, JsonElement output)
    {
        var state = State(context); var safe = McpAuditPayloads.Output(output);
        state.Context = state.Context with { Output = safe.Value, OutputCaptured = true, OutputTruncated = safe.Truncated,
            Truncated = state.Context.Truncated || safe.Truncated };
    }
    public static void SetResult(HttpContext context, bool success, string code, bool unknown = false)
    { var state = State(context); state.Success = success; state.Code = code; state.Unknown = unknown; }

    public static void ReadRequest(HttpContext context)
    {
        var state = State(context);
        if (state.RequestRead) return;
        state.RequestRead = true;
        state.ProtocolVersion = Version(context.Request.Headers["MCP-Protocol-Version"].FirstOrDefault());
        state.Context = state.Context with { UserAgent = McpAuditPayloads.ClientText(context.Request.Headers.UserAgent.FirstOrDefault(), 256) };
        // 边界层已将请求放入<=256KiB内存流；不二次读取网络或启用会自动删除文件的磁盘缓冲。
        if (context.Request.Body is not MemoryStream body || body.Length > 256 * 1024) return;
        try
        {
            using var document = JsonDocument.Parse(body.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return;
            var method = Text(root, "method"); state.Method = method is not null && Methods.Contains(method) ? method : "unknown";
            if (root.TryGetProperty("id", out var id) && id.ValueKind is JsonValueKind.String or JsonValueKind.Number)
                state.RequestId = id.ValueKind == JsonValueKind.String ? id.GetString() ?? "" : id.GetRawText();
            if (!root.TryGetProperty("params", out var parameters) || parameters.ValueKind != JsonValueKind.Object) return;
            // 2026客户端可逐请求自报身份；只读取注册的两个标量，绝不复制完整_meta。
            if (parameters.TryGetProperty("_meta", out var metadata) && metadata.ValueKind == JsonValueKind.Object)
            {
                if (metadata.TryGetProperty("io.modelcontextprotocol/clientInfo", out var clientInfo) && clientInfo.ValueKind == JsonValueKind.Object)
                    state.Context = state.Context with { ClientName = McpAuditPayloads.ClientText(Text(clientInfo, "name"), 128),
                        ClientVersion = McpAuditPayloads.ClientText(Text(clientInfo, "version"), 64) };
                var declaredVersion = Version(Text(metadata, "io.modelcontextprotocol/protocolVersion"));
                if (declaredVersion.Length > 0) state.ProtocolVersion = declaredVersion;
            }
            if (state.Method == "initialize")
            {
                state.ProtocolVersion = Version(Text(parameters, "protocolVersion"));
                state.Context = state.Context with { Input = JsonSerializer.SerializeToElement(new { protocolVersion = state.ProtocolVersion }), InputCaptured = true };
                if (parameters.TryGetProperty("clientInfo", out var client) && client.ValueKind == JsonValueKind.Object)
                    state.Context = state.Context with { ClientName = McpAuditPayloads.ClientText(Text(client, "name"), 128),
                        ClientVersion = McpAuditPayloads.ClientText(Text(client, "version"), 64) };
            }
            else if (state.Method == "tools/call")
            {
                var tool = Text(parameters, "name"); state.ToolName = McpToolCatalog.All.Any(x => x.Name == tool) ? tool! : "unknown";
                if (parameters.TryGetProperty("arguments", out var input)) SetInput(context, state.ToolName, input);
            }
        }
        catch (JsonException) { state.Code = "INVALID_JSON"; }
    }

    public static void ReadResponse(HttpContext context, ReadOnlyMemory<byte> bytes, bool truncated)
    {
        var state = State(context);
        if (state.Context.OutputCaptured) return;
        if (bytes.IsEmpty) return;
        try
        {
            var payload = bytes;
            if (context.Response.ContentType?.StartsWith("text/event-stream", StringComparison.OrdinalIgnoreCase) == true)
            {
                var data = Encoding.UTF8.GetString(bytes.Span).Split('\n').FirstOrDefault(line => line.StartsWith("data: ", StringComparison.Ordinal));
                if (data is null) return;
                payload = Encoding.UTF8.GetBytes(data[6..]);
            }
            using var document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 32 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return;
            if (root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object)
            {
                var number = error.TryGetProperty("code", out var code) && code.ValueKind == JsonValueKind.Number && code.TryGetInt32(out var rpc) ? rpc : -32603;
                SetResult(context, false, "RPC_" + number.ToString(System.Globalization.CultureInfo.InvariantCulture));
                SetOutput(context, JsonSerializer.SerializeToElement(new { code = number }));
            }
            else if (root.TryGetProperty("result", out var result) && result.ValueKind == JsonValueKind.Object)
            {
                var failed = result.TryGetProperty("isError", out var flag) && flag.ValueKind == JsonValueKind.True;
                if (state.Code is null) SetResult(context, !failed, failed ? "MCP_TOOL_ERROR" : "OK");
                if (state.Method == "initialize") SetOutput(context, JsonSerializer.SerializeToElement(new
                { protocolVersion = Version(Text(result, "protocolVersion")), service = "free-ssl-manager" }));
                else if (state.Method != "tools/call") SetOutput(context, JsonSerializer.SerializeToElement(new { success = !failed }));
            }
        }
        catch (JsonException) { /* 非JSON协议内容不采集，不能将格式屏蔽误报为预算超限。 */ }
        if (truncated) state.Context = state.Context with { OutputTruncated = true, Truncated = true };
    }
    private static string? Text(JsonElement value, string name) => value.TryGetProperty(name, out var item) && item.ValueKind == JsonValueKind.String ? item.GetString() : null;
    private static string Version(string? value) => value is { Length: 10 } && DateOnly.TryParseExact(value, "yyyy-MM-dd", out _) ? value : "";
}

public sealed class McpAuditState
{
    public string? InvocationId { get; set; }
    public bool PersistedDenial { get; set; }
    public bool RequestRead { get; set; }
    public string Method { get; set; } = "http";
    public string ToolName { get; set; } = "";
    public string RequestId { get; set; } = "";
    public string ProtocolVersion { get; set; } = "";
    public bool? Success { get; set; }
    public string? Code { get; set; }
    public bool Unknown { get; set; }
    public McpAuditContext Context { get; set; } = new();
}
