using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SslManager.Api.Common;

public sealed record AcmeDirectory(string Url, string NewNonce, string NewOrder, string RevokeCertificate, string NewAccount = "");
public sealed record AcmeProtocolResponse(JsonElement Json, string Location, string Body);

/// <summary>
/// 受限 Let’s Encrypt ACME v2 传输。普通签发只使用既有账号的 kid；
/// JWK 注册仅向独立显式注册服务开放，不允许 CA URL 把签名请求转发到任意主机。
/// </summary>
public sealed class AcmeProtocolClient(IHttpClientFactory clients)
{
    public const string ProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory";
    public const string StagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory";
    public static bool IsAllowedDirectory(string? directory) => directory is ProductionDirectory or StagingDirectory;

    public Task<ApiResult<AcmeDirectory>> DirectoryAsync(string directory, CancellationToken ct = default) => ReadDirectoryAsync(directory, false, ct);

    /// <summary>只有显式注册服务读取注册端点；证书申请和账号测试不使用此入口。</summary>
    public Task<ApiResult<AcmeDirectory>> RegistrationDirectoryAsync(string directory, CancellationToken ct = default) => ReadDirectoryAsync(directory, true, ct);

    private async Task<ApiResult<AcmeDirectory>> ReadDirectoryAsync(string directory, bool registration, CancellationToken ct)
    {
        if (!IsAllowedDirectory(directory)) return ApiResult<AcmeDirectory>.Fail("ACME_DIRECTORY_NOT_ALLOWED", "仅支持 Let’s Encrypt 正式或测试 ACME 目录。");
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, directory);
            using var response = await clients.CreateClient("AcmeProtocol").SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var content = await ReadAsync(response, ct);
            if (!content.Success || content.Data is null) return ApiResult<AcmeDirectory>.Fail(content.Code, content.Message);
            var root = content.Data.Json;
            var result = new AcmeDirectory(directory, Text(root, "newNonce"), Text(root, "newOrder"), Text(root, "revokeCert"), registration ? Text(root, "newAccount") : "");
            if (!new[] { result.NewNonce, result.NewOrder, result.RevokeCertificate }.All(url => IsAllowedResource(directory, url)) ||
                registration && !IsAllowedResource(directory, result.NewAccount))
                return ApiResult<AcmeDirectory>.Fail("ACME_UNSAFE_RESOURCE", "ACME 目录返回了不受信任的资源地址。");
            return ApiResult<AcmeDirectory>.Ok(result);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException || ex is OperationCanceledException && !ct.IsCancellationRequested)
        { return ApiResult<AcmeDirectory>.Fail("ACME_CONNECTION_FAILED", "无法读取 ACME 目录，请检查网络后重试。"); }
    }

    public Task<ApiResult<AcmeProtocolResponse>> PostAsync(AcmeDirectory directory, string url, string privateKeyPem,
        string? accountUrl, object? payload, CancellationToken ct = default) => PostSignedAsync(directory, url, privateKeyPem, accountUrl, payload, false, ct);

    /// <summary>显式恢复同一账号公钥对应的远端账户，不创建账户。</summary>
    public Task<ApiResult<AcmeProtocolResponse>> FindExistingAccountAsync(AcmeDirectory directory, string privateKeyPem, CancellationToken ct = default)
        => PostSignedAsync(directory, directory.NewAccount, privateKeyPem, null, new { onlyReturnExisting = true }, true, ct);

    /// <summary>仅供独立显式注册服务调用，普通申请链路绝不调用此方法。</summary>
    public Task<ApiResult<AcmeProtocolResponse>> CreateAccountAsync(AcmeDirectory directory, string privateKeyPem, string email, CancellationToken ct = default)
        => PostSignedAsync(directory, directory.NewAccount, privateKeyPem, null,
            new { contact = new[] { "mailto:" + email }, termsOfServiceAgreed = true }, true, ct);

    private async Task<ApiResult<AcmeProtocolResponse>> PostSignedAsync(AcmeDirectory directory, string url, string privateKeyPem,
        string? accountUrl, object? payload, bool registration, CancellationToken ct)
    {
        if (!IsAllowedDirectory(directory.Url) || !IsAllowedResource(directory.Url, url) || !IsAllowedResource(directory.Url, directory.NewNonce) ||
            (registration ? url != directory.NewAccount || !IsAllowedResource(directory.Url, directory.NewAccount) || accountUrl is not null
                : accountUrl is null || !IsAllowedResource(directory.Url, accountUrl)))
            return ApiResult<AcmeProtocolResponse>.Fail("ACME_UNSAFE_RESOURCE", "已阻止向非当前 CA 的地址发送签名请求。");
        if (new Uri(url).AbsolutePath.StartsWith("/acme/acct/", StringComparison.Ordinal) && payload is not null)
            return ApiResult<AcmeProtocolResponse>.Fail("ACME_ACCOUNT_READ_ONLY", "系统仅允许读取用户既有 ACME 账户，不提供账户维护操作。");
        try
        {
            using var key = AccountSigningKey.Read(privateKeyPem);
            var client = clients.CreateClient("AcmeProtocol");
            var nonce = "";
            for (var attempt = 0; attempt < 2; attempt++)
            {
                if (string.IsNullOrEmpty(nonce))
                {
                    using var nonceRequest = new HttpRequestMessage(HttpMethod.Head, directory.NewNonce);
                    using var nonceResponse = await client.SendAsync(nonceRequest, HttpCompletionOption.ResponseHeadersRead, ct);
                    if (!nonceResponse.IsSuccessStatusCode) return ApiResult<AcmeProtocolResponse>.Fail("ACME_NONCE_FAILED", "无法取得 ACME 防重放随机数。");
                    nonce = Nonce(nonceResponse);
                }
                if (string.IsNullOrEmpty(nonce)) return ApiResult<AcmeProtocolResponse>.Fail("ACME_NONCE_MISSING", "CA 未返回有效的 ACME 防重放随机数。");
                // 普通申请始终使用 kid；JWK 只对显式注册专用的 newAccount 端点开放。
                var header = new Dictionary<string, object> { ["alg"] = key.Algorithm, ["nonce"] = nonce, ["url"] = url };
                if (registration)
                { using var jwk = JsonDocument.Parse(key.PublicJwkJson); header["jwk"] = jwk.RootElement.Clone(); }
                else header["kid"] = accountUrl!;
                var encodedHeader = Encode(JsonSerializer.SerializeToUtf8Bytes(header));
                // null 代表 RFC 8555 的空载荷 POST-as-GET，不是 JSON 字面量 null。
                var encodedPayload = payload is null ? "" : Encode(JsonSerializer.SerializeToUtf8Bytes(payload));
                var signature = key.Sign(Encoding.ASCII.GetBytes(encodedHeader + "." + encodedPayload));
                var body = JsonSerializer.Serialize(new Dictionary<string, string> { ["protected"] = encodedHeader, ["payload"] = encodedPayload, ["signature"] = Encode(signature) });
                // Boulder 严格比对完整 Content-Type；StringContent 默认添加的 charset 会导致所有签名 POST 被拒绝。
                using var content = new StringContent(body, Encoding.UTF8);
                content.Headers.ContentType = new MediaTypeHeaderValue("application/jose+json");
                using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };
                using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
                nonce = Nonce(response);
                var parsed = await ReadAsync(response, ct, registration);
                if (!parsed.Success && parsed.Code == "ACME_BAD_NONCE" && attempt == 0) continue;
                return parsed;
            }
            return ApiResult<AcmeProtocolResponse>.Fail("ACME_BAD_NONCE", "CA 拒绝 ACME 防重放随机数，请稍后重试。");
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException || ex is OperationCanceledException && !ct.IsCancellationRequested)
        {
            // 接受挑战/下单/finalize 的传输错误不能被解释为 CA 拒绝；上层按已保存资源核对结果。
            return ApiResult<AcmeProtocolResponse>.Fail(payload is null ? "ACME_CONNECTION_FAILED" : "OutcomeUnknown",
                payload is null ? "ACME 查询失败，请稍后重试。" : "ACME 提交结果未知，已保留原私钥和订单台账，请先核对，不能重新下单。");
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or JsonException)
        { return ApiResult<AcmeProtocolResponse>.Fail("ACME_KEY_OR_RESPONSE_INVALID", "ACME 账号密钥或响应格式异常。"); }
    }

    public static string Thumbprint(string privateKeyPem)
    {
        using var key = AccountSigningKey.Read(privateKeyPem);
        return Encode(SHA256.HashData(Encoding.UTF8.GetBytes(key.PublicJwkJson)));
    }

    /// <summary>仅接受 Let’s Encrypt 支持的 RSA 或 NIST EC 既有账号私钥，不接受网站密码或 API token。</summary>
    public static bool IsValidAccountKey(string pem)
    {
        try { using var key = AccountSigningKey.Read(pem); return true; }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException) { return false; }
    }

    public static string Encode(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    public static bool IsAllowedResource(string directory, string resource) => Uri.TryCreate(directory, UriKind.Absolute, out var origin) &&
        Uri.TryCreate(resource, UriKind.Absolute, out var uri) && uri.Scheme == "https" && uri.Port == 443 &&
        uri.IdnHost.Equals(origin.IdnHost, StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(uri.UserInfo) && string.IsNullOrEmpty(uri.Fragment);

    private sealed class AccountSigningKey(AsymmetricAlgorithm key, string algorithm, HashAlgorithmName hash, string jwk) : IDisposable
    {
        public string Algorithm => algorithm;
        public string PublicJwkJson => jwk;
        public byte[] Sign(byte[] value) => key is RSA rsa ? rsa.SignData(value, hash, RSASignaturePadding.Pkcs1)
            : ((ECDsa)key).SignData(value, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        public void Dispose() => key.Dispose();
        public static AccountSigningKey Read(string pem)
        {
            if (string.IsNullOrWhiteSpace(pem) || pem.Length > 16384 || !pem.Contains("PRIVATE KEY", StringComparison.Ordinal))
                throw new CryptographicException("Account private key required.");
            var rsa = RSA.Create();
            try
            {
                rsa.ImportFromPem(pem);
                if (rsa.KeySize is not (2048 or 3072 or 4096)) throw new CryptographicException("Unsupported RSA key size.");
                var p = rsa.ExportParameters(true);
                if (p.D is null) throw new CryptographicException("RSA private key required.");
                // RFC 7638 的 JWK thumbprint 必须使用字典序的最小公钥成员。
                return new(rsa, "RS256", HashAlgorithmName.SHA256, JsonSerializer.Serialize(new { e = Encode(p.Exponent!), kty = "RSA", n = Encode(p.Modulus!) }));
            }
            catch (Exception ex) when (ex is CryptographicException or ArgumentException) { rsa.Dispose(); }
            var ec = ECDsa.Create();
            try
            {
                ec.ImportFromPem(pem); var p = ec.ExportParameters(true);
                var curve = p.Curve.Oid.Value;
                if (p.D is null || curve is not ("1.2.840.10045.3.1.7" or "1.3.132.0.34")) throw new CryptographicException("Unsupported EC curve.");
                var p384 = curve == "1.3.132.0.34";
                return new(ec, p384 ? "ES384" : "ES256", p384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256,
                    JsonSerializer.Serialize(new { crv = p384 ? "P-384" : "P-256", kty = "EC", x = Encode(p.Q.X!), y = Encode(p.Q.Y!) }));
            }
            catch { ec.Dispose(); throw; }
        }
    }
    private static string Nonce(HttpResponseMessage response)
    {
        var value = response.Headers.TryGetValues("Replay-Nonce", out var values) ? values.FirstOrDefault() ?? "" : "";
        return value.Length is > 0 and <= 512 && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_') ? value : "";
    }
    private static string Text(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var item) && item.ValueKind == JsonValueKind.String ? item.GetString() ?? "" : "";

    private static async Task<ApiResult<AcmeProtocolResponse>> ReadAsync(HttpResponseMessage response, CancellationToken ct, bool registration = false)
    {
        var limited = await CertificateDownloadHelper.ReadLimitedAsync(response.Content, 2 * 1024 * 1024, ct);
        if (!limited.Success) return ApiResult<AcmeProtocolResponse>.Fail(response.IsSuccessStatusCode ? "OutcomeUnknown" : limited.Code,
            response.IsSuccessStatusCode ? "CA 成功响应超出安全体积，提交结果需按原申请核对，不能重新下单。" : limited.Message);
        var body = Encoding.UTF8.GetString(limited.Data!);
        JsonElement json;
        try
        {
            using var document = JsonDocument.Parse(body.TrimStart().StartsWith("{") || body.TrimStart().StartsWith("[") ? body : "{}");
            json = document.RootElement.Clone();
        }
        catch (JsonException)
        {
            // 成功 HTTP 响应可能对应已受理订单；无法解析也不能被当作可安全重发的拒绝。
            return ApiResult<AcmeProtocolResponse>.Fail("OutcomeUnknown", "CA 响应格式损坏，保留原申请台账核对，不能重复下单。");
        }
        if (!response.IsSuccessStatusCode)
        {
            var type = Text(json, "type");
            var code = (int)response.StatusCode >= 500 ? "OutcomeUnknown" :
                response.StatusCode == HttpStatusCode.TooManyRequests ? "ACME_RATE_LIMITED" : type switch
                {
                    "urn:ietf:params:acme:error:badNonce" => "ACME_BAD_NONCE",
                    "urn:ietf:params:acme:error:rateLimited" => "ACME_RATE_LIMITED",
                    "urn:ietf:params:acme:error:alreadyRevoked" => "ACME_ALREADY_REVOKED",
                    "urn:ietf:params:acme:error:accountDoesNotExist" => "ACME_ACCOUNT_NOT_FOUND",
                    "urn:ietf:params:acme:error:invalidContact" => "ACME_INVALID_CONTACT",
                    "urn:ietf:params:acme:error:unsupportedContact" => "ACME_UNSUPPORTED_CONTACT",
                    "urn:ietf:params:acme:error:malformed" => "ACME_MALFORMED",
                    "urn:ietf:params:acme:error:badPublicKey" => "ACME_BAD_PUBLIC_KEY",
                    "urn:ietf:params:acme:error:badSignatureAlgorithm" => "ACME_BAD_SIGNATURE_ALGORITHM",
                    "urn:ietf:params:acme:error:unauthorized" => "ACME_UNAUTHORIZED",
                    "urn:ietf:params:acme:error:userActionRequired" => "ACME_USER_ACTION_REQUIRED",
                    _ => "ACME_REJECTED"
                };
            // 仅对白名单 problem type 给固定提示，不把 CA 的任意 detail 字段透传到日志或公开响应。
            return ApiResult<AcmeProtocolResponse>.Fail(code, code switch
            {
                "ACME_RATE_LIMITED" => "CA 请求频率受限，请等待限额恢复；测试请使用测试目录。",
                "ACME_ACCOUNT_NOT_FOUND" => "当前原始账号私钥尚未注册到此 CA 目录。",
                "ACME_BAD_NONCE" => "CA 拒绝防重放随机数。",
                "ACME_INVALID_CONTACT" => "CA 拒绝联系邮箱，请核对已保存邮箱的格式及 CA 的邮箱要求。",
                "ACME_UNSUPPORTED_CONTACT" => "CA 不支持提交的联系方式，请使用有效的联系邮箱。",
                "ACME_MALFORMED" => "CA 拒绝 ACME 请求格式，请核对客户端协议实现与请求参数。",
                "ACME_BAD_PUBLIC_KEY" => "CA 不接受当前账户公钥，请核对密钥类型与强度；保留原密钥，不要另建账户。",
                "ACME_BAD_SIGNATURE_ALGORITHM" => "CA 不支持当前签名算法，请核对客户端协议实现与账户密钥类型。",
                "ACME_UNAUTHORIZED" => "CA 拒绝账户授权，请核对账户状态与当前 CA 目录。",
                "ACME_USER_ACTION_REQUIRED" => "CA 要求先完成人工确认，请核对当前服务条款与账户状态。",
                "OutcomeUnknown" => "CA 暂时故障且提交结果未知，请保留原申请核对，不能重新下单。",
                _ when registration => $"CA 拒绝 ACME 账户注册或核对请求（HTTP {(int)response.StatusCode}），请核对联系邮箱、CA 条款和账户状态。",
                _ => "CA 拒绝请求，请核对域名、CAA、账号状态和申请参数。"
            });
        }
        return ApiResult<AcmeProtocolResponse>.Ok(new(json, response.Headers.Location is { IsAbsoluteUri: true } location ? location.AbsoluteUri : "", body));
    }
}
