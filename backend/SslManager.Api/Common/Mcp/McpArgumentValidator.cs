using System.Text.Json;

namespace SslManager.Api.Common.Mcp;

/// <summary>固定工具 schema 的服务端校验，协议 SDK 之外的直接调用也不能绕过参数限制。</summary>
public static class McpArgumentValidator
{
    public static bool Validate(JsonElement value, JsonElement schema, out string error)
    {
        error = "工具参数不符合输入约束。";
        var type = schema.GetProperty("type").GetString();
        if (type == "object")
        {
            if (value.ValueKind != JsonValueKind.Object) return false;
            var properties = schema.GetProperty("properties");
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var field in value.EnumerateObject())
            {
                if (!names.Add(field.Name) || !properties.TryGetProperty(field.Name, out var rule) || !Validate(field.Value, rule, out _)) return false;
            }
            if (schema.TryGetProperty("required", out var required) && required.EnumerateArray().Any(item => !names.Contains(item.GetString()!))) return false;
        }
        else if (type == "string")
        {
            if (value.ValueKind != JsonValueKind.String) return false;
            var text = value.GetString()!;
            // 只有明确标记的凭据输入允许 PEM 换行，普通参数继续拒绝控制字符。
            var multiline = schema.TryGetProperty("x-mcp-multiline", out var flag) && flag.ValueKind == JsonValueKind.True;
            if (text.Any(character => char.IsControl(character) && !(multiline && character is '\r' or '\n' or '\t')) || schema.TryGetProperty("minLength", out var min) && text.Length < min.GetInt32() ||
                schema.TryGetProperty("maxLength", out var max) && text.Length > max.GetInt32()) return false;
            if (schema.TryGetProperty("enum", out var allowed) && !allowed.EnumerateArray().Any(item => item.GetString() == text)) return false;
        }
        else if (type == "integer")
        {
            if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt32(out var number) || schema.TryGetProperty("minimum", out var min) && number < min.GetInt32() ||
                schema.TryGetProperty("maximum", out var max) && number > max.GetInt32()) return false;
        }
        else if (type == "boolean")
        {
            if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return false;
        }
        else if (type == "array")
        {
            if (value.ValueKind != JsonValueKind.Array || schema.TryGetProperty("minItems", out var min) && value.GetArrayLength() < min.GetInt32() ||
                schema.TryGetProperty("maxItems", out var max) && value.GetArrayLength() > max.GetInt32()) return false;
            var distinct = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in value.EnumerateArray())
                if (!Validate(item, schema.GetProperty("items"), out _) || !distinct.Add(item.GetRawText())) return false;
        }
        else return false;
        error = ""; return true;
    }
}
