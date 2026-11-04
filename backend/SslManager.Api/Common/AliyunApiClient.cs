using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SslManager.Api.Models;

namespace SslManager.Api.Common;

/// <summary>阿里云 RPC 官方签名，使用 POST 表单；不自动重试写操作。</summary>
public sealed class AliyunApiClient(IHttpClientFactory clients)
{
    public async Task<ApiResult<JsonElement>> CallAsync(CloudAccountCredentials account, string service, string action,
        IReadOnlyDictionary<string, string> parameters, bool mutation, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(account.AccessKeyId) || string.IsNullOrWhiteSpace(account.AccessKeySecret))
            return ApiResult<JsonElement>.Fail("ConfigurationMissing", "尚未配置阿里云密钥。");
        var values = new SortedDictionary<string, string>(StringComparer.Ordinal)
        {
            ["Action"] = action, ["Version"] = service == "cas" ? "2020-04-07" : "2015-01-09",
            ["Format"] = "JSON", ["AccessKeyId"] = account.AccessKeyId, ["SignatureMethod"] = "HMAC-SHA1",
            ["SignatureVersion"] = "1.0", ["SignatureNonce"] = Guid.NewGuid().ToString("N"),
            ["Timestamp"] = DateTimeOffset.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)
        };
        foreach (var pair in parameters) values[pair.Key] = pair.Value;
        values["Signature"] = Sign(values, account.AccessKeySecret);
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, service == "cas" ? "https://cas.aliyuncs.com/" : "https://alidns.aliyuncs.com/");
            request.Content = new FormUrlEncodedContent(values);
            if (mutation) await Mcp.McpCloudMutationGuard.CheckBeforeMutationAsync(ct);
            using var response = await clients.CreateClient("AliyunApi").SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var bytes = await CertificateDownloadHelper.ReadLimitedAsync(response.Content, 8 * 1024 * 1024, ct);
            if (!bytes.Success) return mutation ? CloudJson.TransportFailure<JsonElement>(true, "阿里云", bytes.Code) : CloudJson.Fail<JsonElement, byte[]>(bytes);
            using var document = JsonDocument.Parse(bytes.Data!);
            var payload = document.RootElement;
            var errorCode = CloudJson.Token(CloudJson.Text(payload, "Code"));
            if (errorCode.Length > 0 && !string.Equals(errorCode, "Success", StringComparison.OrdinalIgnoreCase) && errorCode != "200")
                return ApiResult<JsonElement>.Fail("Aliyun." + errorCode,
                    $"阿里云拒绝请求，请检查权限、额度和参数。云错误：{errorCode}；RequestId：{CloudJson.Token(CloudJson.Text(payload, "RequestId"))}");
            return response.IsSuccessStatusCode && payload.ValueKind == JsonValueKind.Object ? ApiResult<JsonElement>.Ok(payload.Clone())
                : CloudJson.TransportFailure<JsonElement>(mutation, "阿里云", "CloudHttpError");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { return CloudJson.TransportFailure<JsonElement>(mutation, "阿里云", "CloudTimeout"); }
        catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException)
        { return CloudJson.TransportFailure<JsonElement>(mutation, "阿里云", "CloudRequestFailed"); }
    }
    public static string Sign(IReadOnlyDictionary<string, string> values, string secret)
    {
        var canonical = string.Join("&", values.Where(p => p.Key != "Signature").OrderBy(p => p.Key, StringComparer.Ordinal)
            .Select(p => Encode(p.Key) + "=" + Encode(p.Value)));
        var bytes = Encoding.UTF8.GetBytes(secret + "&");
        try { return Convert.ToBase64String(HMACSHA1.HashData(bytes, Encoding.UTF8.GetBytes("POST&%2F&" + Encode(canonical)))); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
    private static string Encode(string value) => Uri.EscapeDataString(value).Replace("!", "%21", StringComparison.Ordinal)
        .Replace("'", "%27", StringComparison.Ordinal).Replace("(", "%28", StringComparison.Ordinal).Replace(")", "%29", StringComparison.Ordinal).Replace("*", "%2A", StringComparison.Ordinal);
}
