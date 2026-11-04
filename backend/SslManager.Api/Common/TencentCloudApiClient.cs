using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SslManager.Api.Models;

namespace SslManager.Api.Common;

/// <summary>复用原项目 TC3 签名，不记录凭据、签名、请求正文或云端任意错误正文。</summary>
public sealed class TencentCloudApiClient(IHttpClientFactory clients)
{
    public async Task<ApiResult<JsonElement>> CallAsync(CloudAccountCredentials account, string service, string action,
        object parameters, bool mutation, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(account.AccessKeyId) || string.IsNullOrWhiteSpace(account.AccessKeySecret))
            return ApiResult<JsonElement>.Fail("ConfigurationMissing", "尚未配置腾讯云密钥。");
        var host = service == "ssl" ? "ssl.tencentcloudapi.com" : "dnspod.tencentcloudapi.com";
        var body = JsonSerializer.Serialize(parameters);
        var now = DateTimeOffset.UtcNow;
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "https://" + host + "/");
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
            request.Headers.Host = host;
            request.Headers.TryAddWithoutValidation("X-TC-Action", action);
            request.Headers.TryAddWithoutValidation("X-TC-Version", service == "ssl" ? "2019-12-05" : "2021-03-23");
            request.Headers.TryAddWithoutValidation("X-TC-Timestamp", now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture));
            request.Headers.TryAddWithoutValidation("X-TC-Language", "zh-CN");
            request.Headers.TryAddWithoutValidation("Authorization", Sign(account.AccessKeyId, account.AccessKeySecret, service, host, body, now));
            if (mutation) await Mcp.McpCloudMutationGuard.CheckBeforeMutationAsync(ct);
            using var response = await clients.CreateClient("TencentCloudApi").SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var bytes = await CertificateDownloadHelper.ReadLimitedAsync(response.Content, 8 * 1024 * 1024, ct);
            if (!bytes.Success) return mutation ? CloudJson.TransportFailure<JsonElement>(true, "腾讯云", bytes.Code) : CloudJson.Fail<JsonElement, byte[]>(bytes);
            using var document = JsonDocument.Parse(bytes.Data!);
            if (!document.RootElement.TryGetProperty("Response", out var payload) || payload.ValueKind != JsonValueKind.Object)
                return CloudJson.TransportFailure<JsonElement>(mutation, "腾讯云", "CloudInvalidResponse");
            if (payload.TryGetProperty("Error", out var error) && error.ValueKind == JsonValueKind.Object)
            {
                var code = CloudJson.Token(CloudJson.Text(error, "Code"));
                var requestId = CloudJson.Token(CloudJson.Text(payload, "RequestId"));
                return ApiResult<JsonElement>.Fail("Tencent." + (code.Length == 0 ? "Unknown" : code),
                    $"腾讯云拒绝请求，请检查权限、额度和参数。云错误：{code}；RequestId：{requestId}");
            }
            return response.IsSuccessStatusCode ? ApiResult<JsonElement>.Ok(payload.Clone())
                : CloudJson.TransportFailure<JsonElement>(mutation, "腾讯云", "CloudHttpError");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { return CloudJson.TransportFailure<JsonElement>(mutation, "腾讯云", "CloudTimeout"); }
        catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException)
        { return CloudJson.TransportFailure<JsonElement>(mutation, "腾讯云", "CloudRequestFailed"); }
    }

    public static string Sign(string secretId, string secretKey, string service, string host, string body, DateTimeOffset now)
    {
        const string contentType = "application/json; charset=utf-8";
        var timestamp = now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture);
        var date = now.UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        var canonical = $"POST\n/\n\ncontent-type:{contentType}\nhost:{host}\n\ncontent-type;host\n{Hash(body)}";
        var scope = $"{date}/{service}/tc3_request";
        var toSign = $"TC3-HMAC-SHA256\n{timestamp}\n{scope}\n{Hash(canonical)}";
        var dateKey = Hmac(Encoding.UTF8.GetBytes("TC3" + secretKey), date);
        var serviceKey = Hmac(dateKey, service);
        var signingKey = Hmac(serviceKey, "tc3_request");
        try { return $"TC3-HMAC-SHA256 Credential={secretId}/{scope}, SignedHeaders=content-type;host, Signature={Convert.ToHexStringLower(Hmac(signingKey, toSign))}"; }
        finally { CryptographicOperations.ZeroMemory(dateKey); CryptographicOperations.ZeroMemory(serviceKey); CryptographicOperations.ZeroMemory(signingKey); }
    }
    private static byte[] Hmac(byte[] key, string value) => HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value));
    private static string Hash(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
}

/// <summary>云端数据只做显式映射；不认识的状态和免费属性保持未知。</summary>
internal static class CloudJson
{
    internal static string Text(JsonElement e, string key) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(key, out var v)
        && v.ValueKind is JsonValueKind.String or JsonValueKind.Number ? v.ToString() : "";
    internal static int? Number(JsonElement e, string key) => int.TryParse(Text(e, key), NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) ? n : null;
    internal static bool Array(JsonElement e, string key, out JsonElement v)
    { v = default; return e.ValueKind == JsonValueKind.Object && e.TryGetProperty(key, out v) && v.ValueKind == JsonValueKind.Array; }
    internal static JsonElement Object(JsonElement e, string key) => e.ValueKind == JsonValueKind.Object && e.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.Object ? v : default;
    internal static string Token(string value) => value.Length <= 160 && Regex.IsMatch(value, "^[a-zA-Z0-9_.:-]*$", RegexOptions.CultureInvariant) ? value : "";
    internal static bool Id(string? value) => !string.IsNullOrWhiteSpace(value) && Regex.IsMatch(value, "^[a-zA-Z0-9_-]{1,160}$", RegexOptions.CultureInvariant);
    internal static bool NumericId(string? value) => !string.IsNullOrWhiteSpace(value) && long.TryParse(value, out var n) && n > 0;
    internal static bool Domain(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 253 && Regex.IsMatch(value,
        @"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$", RegexOptions.CultureInvariant);
    internal static bool RecordInput(string zone, DnsRecordRequest r) => Domain(zone) && r.Name is { Length: > 0 and <= 253 }
        && !r.Name.Any(char.IsControl) && r.Type is "A" or "AAAA" or "CNAME" or "TXT" or "MX" or "NS" or "SRV" or "CAA"
        && !string.IsNullOrWhiteSpace(r.Value) && r.Value.Length <= 4096 && r.Ttl is >= 1 and <= 604800
        && r.Line is { Length: > 0 and <= 128 };
    internal static ApiResult<T> Fail<T, TSource>(ApiResult<TSource> r) => ApiResult<T>.Fail(r.Code, r.Message);
    internal static ApiResult<T> Invalid<T>(string message) => ApiResult<T>.Fail("InvalidInput", message);
    internal static ApiResult<T> Incomplete<T>() => ApiResult<T>.Fail("CloudPaginationIncomplete", "云端分页连续不稳定，已重试完整抓取仍未得到可信全量快照；未使用部分结果。");
    internal static ApiResult<T> TransportFailure<T>(bool mutation, string provider, string code) => ApiResult<T>.Fail(mutation ? "OutcomeUnknown" : code,
        mutation ? $"{provider}操作结果不确定，请核对云端状态后再决定是否重试。" : $"{provider}查询失败，请检查网络或稍后重试。");
    internal static DateTimeOffset? ChinaTime(string value) => DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.None, out var time)
        && time.Ticks >= TimeSpan.FromHours(8).Ticks
        ? new DateTimeOffset(DateTime.SpecifyKind(time, DateTimeKind.Unspecified), TimeSpan.FromHours(8)).ToUniversalTime() : null;
    internal static DateTimeOffset? UnixTime(string value)
    {
        if (!long.TryParse(value, out var n) || n <= 0) return null;
        // 官方样例存在秒/毫秒混用，按数量级归一化，并限制范围防止转换异常。
        var seconds = n > 100_000_000_000 ? n / 1000 : n;
        return seconds is >= -62135596800 and <= 253402300799 ? DateTimeOffset.FromUnixTimeSeconds(seconds) : null;
    }
}
