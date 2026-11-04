using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Common.Mcp;

/// <summary>证书业务采用字段白名单，不将云响应、DNS值、私钥、自由消息或任意JSON字符串写入审计。</summary>
public static partial class McpAuditPayloads
{
    public const int MaxInputBytes = 8 * 1024;
    public const int MaxOutputBytes = 32 * 1024;
    public const int MaxContextBytes = 48 * 1024;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { MaxDepth = 20 };
    private static readonly HashSet<string> InputFields = new(StringComparer.Ordinal)
    {
        "accountId", "zoneId", "certificateId", "batchId", "taskId", "scheduleId", "operationId", "targetId", "targetIds",
        "dnsZoneId", "instanceId", "systemInstanceId", "protocolVersion", "domain", "name", "provider", "type", "status", "page", "pageSize", "validationMode", "autoCleanup", "apiVersion"
    };
    private static readonly HashSet<string> OutputFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "items", "batch", "tasks", "steps", "certificate", "jobs", "validation", "runs", "checks", "id", "accountId", "zoneId", "dnsZoneId", "certificateId", "certificateJobId", "batchId", "taskId", "scheduleId", "operationId", "targetId", "targetIds",
        "domain", "certificateDomain", "primaryDomain", "provider", "type", "status", "phase", "code", "kind", "toolName", "executorKey", "operationType",
        "total", "page", "pageSize", "ttl", "mx", "enabled", "active", "success", "availableTools", "service", "protocolVersions",
        "version", "planRevision", "configRevision", "productVersion", "verificationLevel", "fingerprint", "validationMode", "autoCleanup", "revokeOldCertificates",
        "intervalValue", "intervalUnit", "lastTestSuccess", "lastDeploymentStatus", "cleanupStatus", "lastMailStatus", "canApprove",
        "tools", "protocolVersion", "instanceId", "systemInstanceId", "systemName", "isStaging", "canDeploy", "hasPrivateKey", "acmeReady", "acmeEnvironment"
    };
    private static readonly HashSet<string> DateFields = new(StringComparer.OrdinalIgnoreCase)
    {
        "createdAtUtc", "updatedAtUtc", "startedAtUtc", "finishedAtUtc", "expiresAtUtc", "notBeforeUtc", "notAfterUtc",
        "submittedAtUtc", "firstRunAtUtc", "nextRunAtUtc", "lastTestAtUtc", "lastDeploymentAtUtc", "firstDetectedAtUtc",
        "lastAttemptAtUtc", "nextReminderAtUtc", "scheduledForUtc", "nextCheckAtUtc", "consumedAtUtc", "approvedAtUtc", "approvalExpiresAtUtc"
    };

    public static (JsonElement Value, bool Truncated) Input(string toolName, JsonElement value)
    {
        var descriptor = McpToolCatalog.All.FirstOrDefault(x => x.Name == toolName);
        if (descriptor is null) return (JsonSerializer.SerializeToElement(new { }), false);
        var fields = descriptor.InputSchema.GetProperty("properties").EnumerateObject().Select(x => x.Name).ToHashSet(StringComparer.Ordinal);
        fields.IntersectWith(InputFields);
        return Project(value, MaxInputBytes, fields, input: true);
    }

    public static (JsonElement Value, bool Truncated) Output(JsonElement value) => Project(value, MaxOutputBytes, OutputFields, input: false);

    public static string Write(McpAuditContext value)
    {
        // 上下文只接受本模块已投影的入出参；读回也重新投影，防止旧/损坏记录绕过白名单。
        var clean = value with { ClientName = ClientText(value.ClientName, 128), ClientVersion = ClientText(value.ClientVersion, 64),
            SystemName = ClientText(value.SystemName, 100), InstanceId = ClientText(value.InstanceId, 80), UserAgent = ClientText(value.UserAgent, 256) };
        var json = JsonSerializer.Serialize(clean, Json);
        if (Encoding.UTF8.GetByteCount(json) <= MaxContextBytes) return json;
        return JsonSerializer.Serialize(clean with { Output = null, OutputCaptured = value.OutputCaptured, OutputTruncated = true, Truncated = true }, Json);
    }

    public static string Normalize(string? json)
    {
        if (string.IsNullOrEmpty(json) || Encoding.UTF8.GetByteCount(json) > MaxContextBytes) return "{}";
        try
        {
            var value = JsonSerializer.Deserialize<McpAuditContext>(json, Json);
            if (value is null) return "{}";
            var input = value.Input.HasValue ? Project(value.Input.Value, MaxInputBytes, InputFields, true) : default;
            var output = value.Output.HasValue ? Output(value.Output.Value) : default;
            return Write(value with { Input = value.Input.HasValue ? input.Value : null, Output = value.Output.HasValue ? output.Value : null,
                InputTruncated = value.InputTruncated || input.Truncated, OutputTruncated = value.OutputTruncated || output.Truncated,
                Truncated = value.Truncated || input.Truncated || output.Truncated });
        }
        catch (JsonException) { return "{}"; }
    }

    public static string? ClientText(string? value, int limit)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        // 客户端自报信息只允许单行标识，不记录URL、令牌前缀、PEM或序列化内容。
        if (value.Contains("://", StringComparison.Ordinal) || value.Contains("BEGIN", StringComparison.OrdinalIgnoreCase)
            || value.Contains("Bearer ", StringComparison.OrdinalIgnoreCase) || value.Contains("sslm_", StringComparison.Ordinal)
            || value.IndexOfAny(['{', '}', '[', ']', '\r', '\n']) >= 0) return null;
        return new string(value.Where(c => !char.IsControl(c)).Take(limit).ToArray());
    }

    private static (JsonElement Value, bool Truncated) Project(JsonElement source, int budget, HashSet<string> fields, bool input)
    {
        var state = new ProjectionState(fields, input);
        var result = Build(source, budget, 0, "", state);
        var json = result.Node?.ToJsonString(Json) ?? "null";
        return (JsonSerializer.Deserialize<JsonElement>(json), state.Truncated);
    }

    private static Built Build(JsonElement value, int budget, int depth, string property, ProjectionState state)
    {
        if (depth >= 12 || ++state.Nodes > 1024) { state.Truncated = true; return new(null, 4); }
        if (value.ValueKind == JsonValueKind.Object)
        {
            var result = new JsonObject(); var bytes = 2; var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var item in value.EnumerateObject())
            {
                // data 是唯一业务包装容器；message永远不用原文，summaryJson/响应快照不在白名单。
                // 正常白名单剔除/重复字段屏蔽不等同于预算截断，不能让短响应一直显示“超限”。
                if (!seen.Add(item.Name) || (!state.Fields.Contains(item.Name) && !(depth == 0 && !state.Input && item.Name == "data") && !IsDateField(item.Name)))
                    continue;
                if (result.Count >= 100) { state.Truncated = true; break; }
                var prefix = Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(item.Name)) + 1 + (result.Count == 0 ? 0 : 1);
                if (budget - bytes - prefix < 4) { state.Truncated = true; break; }
                var child = Build(item.Value, budget - bytes - prefix, depth + 1, item.Name, state);
                result[item.Name] = child.Node; bytes += prefix + child.Bytes;
            }
            return new(result, bytes);
        }
        if (value.ValueKind == JsonValueKind.Array)
        {
            var result = new JsonArray(); var bytes = 2;
            foreach (var item in value.EnumerateArray())
            {
                if (result.Count >= 100 || budget - bytes - (result.Count == 0 ? 0 : 1) < 4) { state.Truncated = true; break; }
                var prefix = result.Count == 0 ? 0 : 1;
                var child = Build(item, budget - bytes - prefix, depth + 1, property, state);
                result.Add(child.Node); bytes += prefix + child.Bytes;
            }
            return new(result, bytes);
        }
        if (value.ValueKind == JsonValueKind.String)
        {
            var text = value.GetString()!;
            var valid = IsDateField(property) ? text.Length <= 50 && DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out _)
                : property.EndsWith("Id", StringComparison.OrdinalIgnoreCase) || property is "id" or "targetIds" ? Identifier().IsMatch(text)
                : property.Contains("domain", StringComparison.OrdinalIgnoreCase) ? Domain(text)
                : property == "systemName" ? ClientText(text, 100) == text
                : text.Length <= 100 && SafeIdentifier().IsMatch(text);
            if (!valid) return new(null, 4);
            var size = Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(text));
            if (size > budget) { state.Truncated = true; return new(null, 4); }
            return new(JsonValue.Create(text), size);
        }
        if (value.ValueKind is JsonValueKind.True or JsonValueKind.False or JsonValueKind.Number or JsonValueKind.Null)
        {
            var raw = value.GetRawText();
            if (raw.Length > 64 || raw.Length > budget) { state.Truncated = true; return new(null, 4); }
            return new(JsonNode.Parse(raw), raw.Length);
        }
        return new(null, 4);
    }

    private static bool IsDateField(string name) => DateFields.Contains(name);
    private static bool Domain(string value) => value.Length <= 253 && Uri.CheckHostName(value.StartsWith("*.", StringComparison.Ordinal) ? value[2..] : value) == UriHostNameType.Dns;
    [GeneratedRegex("^[A-Za-z0-9_-]{1,80}$", RegexOptions.CultureInvariant)] private static partial Regex Identifier();
    [GeneratedRegex("^[A-Za-z0-9_.:+/* -]{0,100}$", RegexOptions.CultureInvariant)] private static partial Regex SafeIdentifier();
    private sealed class ProjectionState(HashSet<string> fields, bool input)
    { public HashSet<string> Fields { get; } = fields; public bool Input { get; } = input; public bool Truncated; public int Nodes; }
    private sealed record Built(JsonNode? Node, int Bytes);
}
