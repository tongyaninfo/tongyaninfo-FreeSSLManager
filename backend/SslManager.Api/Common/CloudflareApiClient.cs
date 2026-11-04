using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using SslManager.Api.Models;

namespace SslManager.Api.Common;

/// <summary>只向固定 Cloudflare API 发送 Bearer Token；错误只输出代码，不回显远端正文和凭据。</summary>
public sealed class CloudflareApiClient(IHttpClientFactory clients)
{
    private static readonly Uri Endpoint = new("https://api.cloudflare.com/client/v4/");

    public async Task<ApiResult<JsonElement>> CallAsync(CloudAccountCredentials account, HttpMethod method,
        string path, object? parameters, bool mutation, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(account.AccessKeySecret) || account.AccessKeySecret.Any(char.IsWhiteSpace) ||
            account.AccessKeySecret.Any(char.IsControl))
            return ApiResult<JsonElement>.Fail("ConfigurationMissing", "尚未配置有效的 Cloudflare API Token。");
        if (!path.StartsWith('/') || path.StartsWith("//", StringComparison.Ordinal) || path.Contains('\\') ||
            path.Contains('#') || path.Any(char.IsControl))
            return CloudJson.Invalid<JsonElement>("Cloudflare API 路径无效。");
        var uri = new Uri(Endpoint, path[1..]);
        if (uri.Scheme != Uri.UriSchemeHttps || uri.Host != Endpoint.Host || uri.Port != 443 ||
            !uri.AbsolutePath.StartsWith(Endpoint.AbsolutePath, StringComparison.Ordinal))
            return CloudJson.Invalid<JsonElement>("Cloudflare API 路径超出固定服务边界。");
        try
        {
            using var request = new HttpRequestMessage(method, uri);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", account.AccessKeySecret);
            if (parameters is not null)
                request.Content = new StringContent(JsonSerializer.Serialize(parameters), Encoding.UTF8, "application/json");
            using var response = await clients.CreateClient("CloudflareApi").SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var bytes = await CertificateDownloadHelper.ReadLimitedAsync(response.Content, 8 * 1024 * 1024, ct);
            if (!bytes.Success) return CloudJson.TransportFailure<JsonElement>(mutation, "Cloudflare", bytes.Code);
            using var document = JsonDocument.Parse(bytes.Data!);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return CloudJson.TransportFailure<JsonElement>(mutation, "Cloudflare", "CloudInvalidResponse");
            // 5xx 和异常响应不能证明写操作未发生；绝不据此自动重发创建请求。
            if ((int)response.StatusCode >= 500)
                return CloudJson.TransportFailure<JsonElement>(mutation, "Cloudflare", "CloudHttpError");
            var success = root.TryGetProperty("success", out var flag) && flag.ValueKind == JsonValueKind.True;
            if (!response.IsSuccessStatusCode || !success)
            {
                var codes = CloudJson.Array(root, "errors", out var errors)
                    ? errors.EnumerateArray().Select(error => CloudJson.Token(CloudJson.Text(error, "code"))).Where(code => code.Length > 0).Take(4).ToArray()
                    : [];
                if (response.StatusCode == HttpStatusCode.NotFound)
                    return ApiResult<JsonElement>.Fail("Cloudflare.NotFound", "Cloudflare 未找到指定资源。");
                if (codes.Length == 0)
                    return CloudJson.TransportFailure<JsonElement>(mutation, "Cloudflare", "CloudInvalidResponse");
                return ApiResult<JsonElement>.Fail("Cloudflare." + codes[0],
                    "Cloudflare 拒绝请求，请核对 Token 权限、资源范围和参数。错误代码：" + string.Join(",", codes));
            }
            if (!root.TryGetProperty("result", out _))
                return CloudJson.TransportFailure<JsonElement>(mutation, "Cloudflare", "CloudInvalidResponse");
            return ApiResult<JsonElement>.Ok(root.Clone());
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { return CloudJson.TransportFailure<JsonElement>(mutation, "Cloudflare", "CloudTimeout"); }
        catch (Exception exception) when (exception is HttpRequestException or IOException or JsonException)
        { return CloudJson.TransportFailure<JsonElement>(mutation, "Cloudflare", "CloudRequestFailed"); }
    }
}
