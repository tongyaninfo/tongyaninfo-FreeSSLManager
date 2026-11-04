using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>雷池社区版 9.x 客户端；登录加密协议来自目标后台实际使用的契约。</summary>
public sealed class SafeLineCe9ApiClient(Func<DeploymentTargetContext, HttpClient>? clientFactory = null)
{
    public static Uri BaseUri(DeploymentTargetContext target)
    {
        if (!Uri.TryCreate(target.Endpoint, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme != "https" || !string.IsNullOrEmpty(endpoint.UserInfo) ||
            !string.IsNullOrEmpty(endpoint.Query) || !string.IsNullOrEmpty(endpoint.Fragment))
            throw new ArgumentException("雷池管理地址必须是无用户信息的 HTTPS 地址。");
        var builder = new UriBuilder(endpoint) { Path = "/", Query = "", Fragment = "" };
        if (target.Port > 0) builder.Port = target.Port;
        return builder.Uri;
    }

    public async Task<ApiResult<SafeLineCe9Session>> OpenAsync(DeploymentTargetContext target, CancellationToken ct)
    {
        HttpClient? client = null;
        try
        {
            var endpoint = BaseUri(target);
            client = clientFactory?.Invoke(target) ?? DeploymentManagementHttpClient.Create();
            client.BaseAddress = endpoint;
            client.Timeout = TimeSpan.FromSeconds(Math.Clamp(target.Configuration.OperationTimeoutSeconds, 10, 600));
            var session = new SafeLineCe9Session(client);
            if (target.AuthenticationMode == "ApiToken")
            {
                if (string.IsNullOrWhiteSpace(target.Credentials.ApiToken)) return Missing(client);
                client.DefaultRequestHeaders.Add("X-SLCE-API-TOKEN", target.Credentials.ApiToken);
            }
            else if (target.AuthenticationMode == "Password")
            {
                if (string.IsNullOrWhiteSpace(target.Username) || string.IsNullOrEmpty(target.Credentials.Password))
                    return Missing(client);
                var key = await session.SendAsync(HttpMethod.Get, "api/open/system/key", null, false, ct);
                var csrf = await session.SendAsync(HttpMethod.Get, "api/open/auth/csrf", null, false, ct);
                if (!key.Success || !csrf.Success)
                {
                    client.Dispose();
                    return ApiResult<SafeLineCe9Session>.Fail(!key.Success ? key.Code : csrf.Code,
                        !key.Success ? key.Message : csrf.Message);
                }
                if (key.Data.ValueKind != JsonValueKind.String ||
                    Encoding.UTF8.GetByteCount(key.Data.GetString() ?? "") is not (16 or 24 or 32) ||
                    !csrf.Data.TryGetProperty("csrf_token", out var token))
                {
                    client.Dispose();
                    return ApiResult<SafeLineCe9Session>.Fail("SAFELINE_PROTOCOL_UNSUPPORTED", "雷池登录加密契约不兼容。");
                }
                var login = await session.SendAsync(HttpMethod.Post, "api/open/auth/login", new
                {
                    username = target.Username.Trim(),
                    password = EncryptPassword(target.Credentials.Password, key.Data.GetString()!),
                    csrf_token = token.GetString()
                }, false, ct);
                if (!login.Success || !login.Data.TryGetProperty("jwt", out var jwt) ||
                    string.IsNullOrEmpty(jwt.GetString()))
                {
                    client.Dispose();
                    return ApiResult<SafeLineCe9Session>.Fail("AUTHENTICATION_FAILED", "雷池登录失败，请核对账号、密码及登录方式。");
                }
                if (login.Data.TryGetProperty("tfa_enabled", out var tfa) && tfa.ValueKind == JsonValueKind.True)
                {
                    client.Dispose();
                    return ApiResult<SafeLineCe9Session>.Fail("TWO_FACTOR_REQUIRED", "该雷池账号启用了二次验证，请改用已有 API Token。");
                }
                client.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt.GetString());
            }
            else
            {
                client.Dispose();
                return ApiResult<SafeLineCe9Session>.Fail("AUTHENTICATION_UNSUPPORTED", "该执行器仅支持用户名密码或 API Token。");
            }
            var system = await session.SendAsync(HttpMethod.Get, "api/open/system", null, false, ct);
            if (!system.Success)
            {
                client.Dispose();
                return ApiResult<SafeLineCe9Session>.Fail(system.Code, system.Message);
            }
            var version = system.Data.TryGetProperty("version", out var value) ? value.GetString() ?? "" : "";
            if (!Regex.IsMatch(version, @"^v?9\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$"))
            {
                client.Dispose();
                return ApiResult<SafeLineCe9Session>.Fail("PRODUCT_VERSION_UNSUPPORTED", "当前执行器仅适配雷池社区版 9.x.x。");
            }
            session.ProductVersion = version;
            return ApiResult<SafeLineCe9Session>.Ok(session);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or ArgumentException or CryptographicException or InvalidOperationException or KeyNotFoundException)
        {
            client?.Dispose();
            return ApiResult<SafeLineCe9Session>.Fail("CONNECTION_FAILED", "连接雷池失败，请核对地址、网络和服务状态。");
        }
    }

    public static string EncryptPassword(string password, string key)
    {
        // 9.x 页面使用 8 字节随机数的十六进制文本作为 16 字节 IV，并前缀到密文。
        var iv = Encoding.ASCII.GetBytes(Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant());
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(key);
        var encrypted = aes.EncryptCbc(Encoding.UTF8.GetBytes(password.Trim()), iv, PaddingMode.PKCS7);
        return Convert.ToBase64String(iv.Concat(encrypted).ToArray());
    }

    private static ApiResult<SafeLineCe9Session> Missing(HttpClient client)
    {
        client.Dispose();
        return ApiResult<SafeLineCe9Session>.Fail("CONFIGURATION_MISSING", "雷池认证配置不完整。");
    }
}

/// <summary>会话仅存在于操作生命周期内，JWT、响应材料和请求正文不进入日志。</summary>
public sealed class SafeLineCe9Session(HttpClient client) : IDisposable
{
    public string ProductVersion { get; internal set; } = "";
    public async Task<ApiResult<JsonElement>> SendAsync(HttpMethod method, string path, object? body,
        bool mutation, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(method, path);
            if (body is not null) request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var bytes = await CertificateDownloadHelper.ReadLimitedAsync(response.Content, 8 * 1024 * 1024, ct);
            if (!bytes.Success) return ApiResult<JsonElement>.Fail(mutation ? "REMOTE_RESULT_UNKNOWN" : bytes.Code,
                mutation ? "雷池变更响应无法完整读取，请先核对远端结果。" : bytes.Message);
            using var json = JsonDocument.Parse(bytes.Data!);
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return ApiResult<JsonElement>.Fail(mutation ? "REMOTE_RESULT_UNKNOWN" : "SAFELINE_PROTOCOL_UNSUPPORTED",
                    "雷池响应格式不兼容，请核对目标状态。");
            var error = root.TryGetProperty("err", out var err) && err.ValueKind is not (JsonValueKind.Null or JsonValueKind.False) &&
                !(err.ValueKind == JsonValueKind.String && string.IsNullOrEmpty(err.GetString())) &&
                !(err.ValueKind == JsonValueKind.Number && err.TryGetInt32(out var number) && number == 0);
            var hasData = root.TryGetProperty("data", out var data);
            if (!response.IsSuccessStatusCode || error || !hasData)
            {
                if (mutation && ((int)response.StatusCode >= 500 ||
                    ((int)response.StatusCode >= 300 && (int)response.StatusCode < 400) ||
                    (response.IsSuccessStatusCode && !error && !hasData)))
                    return ApiResult<JsonElement>.Fail("REMOTE_RESULT_UNKNOWN", "雷池返回服务端错误，变更结果未知，请先核对。");
                return ApiResult<JsonElement>.Fail(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden
                    ? "AUTHENTICATION_FAILED" : "SAFELINE_API_ERROR", "雷池接口未成功完成请求，请核对权限和目标版本。");
            }
            return ApiResult<JsonElement>.Ok(data.Clone());
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException or TaskCanceledException)
        {
            return ApiResult<JsonElement>.Fail(mutation ? "REMOTE_RESULT_UNKNOWN" : "CONNECTION_FAILED",
                mutation ? "请求中断，雷池可能已完成变更，请先核对远端结果。" : "读取雷池失败，请检查连接或接口响应。");
        }
    }
    public void Dispose() => client.Dispose();
}
