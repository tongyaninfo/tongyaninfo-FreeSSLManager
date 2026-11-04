using System.Formats.Tar;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>DSM 7.x HTTPS 客户端；发现 API 路径后登录，凭据和证书包仅在内存中处理。</summary>
public sealed class SynologyDsmApiClient(Func<DeploymentTargetContext, HttpClient>? clientFactory = null)
{
    public static Uri BaseUri(DeploymentTargetContext target)
    {
        if (!Uri.TryCreate(target.Endpoint, UriKind.Absolute, out var endpoint) || endpoint.Scheme != "https" ||
            !string.IsNullOrEmpty(endpoint.UserInfo) || !string.IsNullOrEmpty(endpoint.Query) || !string.IsNullOrEmpty(endpoint.Fragment))
            throw new ArgumentException("群晖管理地址必须是无用户信息的 HTTPS 地址。");
        // Uri 会把显式 :443 规范化为默认端口，需保留用户原始地址中的端口选择。
        var authority = target.Endpoint[(target.Endpoint.IndexOf("://", StringComparison.Ordinal) + 3)..].Split('/')[0];
        var port = target.Port > 0 ? target.Port : Regex.IsMatch(authority, @":\d+$") ? endpoint.Port : 5001;
        return new UriBuilder(endpoint) { Port = port, Path = endpoint.AbsolutePath.TrimEnd('/') + "/" }.Uri;
    }

    public async Task<ApiResult<SynologyDsmSession>> OpenAsync(DeploymentTargetContext target, CancellationToken ct)
    {
        SynologyDsmSession? session = null;
        HttpClient? client = null;
        try
        {
            if (target.AuthenticationMode != "Password")
                return ApiResult<SynologyDsmSession>.Fail("AUTHENTICATION_UNSUPPORTED", "群晖 DSM 7.x 当前仅支持账号密码登录。");
            if (string.IsNullOrWhiteSpace(target.Username) || string.IsNullOrEmpty(target.Credentials.Password))
                return ApiResult<SynologyDsmSession>.Fail("CONFIGURATION_MISSING", "请配置群晖管理员账号和密码。");
            var endpoint = BaseUri(target);
            client = clientFactory?.Invoke(target) ?? DeploymentManagementHttpClient.Create();
            client.BaseAddress = endpoint;
            client.Timeout = TimeSpan.FromSeconds(Math.Clamp(target.Configuration.OperationTimeoutSeconds, 10, 600));
            session = new SynologyDsmSession(client);
            var initialized = await session.InitializeAsync(target.Username, target.Credentials.Password, ct);
            if (initialized.Success) return ApiResult<SynologyDsmSession>.Ok(session);
            await session.DisposeAsync();
            return ApiResult<SynologyDsmSession>.Fail(initialized.Code, initialized.Message);
        }
        catch (Exception ex) when (ex is ArgumentException or HttpRequestException or IOException or OperationCanceledException or InvalidOperationException)
        {
            if (session is not null) await session.DisposeAsync(); else client?.Dispose();
            return ApiResult<SynologyDsmSession>.Fail("CONNECTION_FAILED", "连接群晖失败，请核对地址、网络和服务状态。");
        }
    }

}

/// <summary>只包含公有证书读回结果；DSM 导出包中的私钥不会返回给执行器。</summary>
public sealed record SynologyCertificateReadback(string CertificatePem, string ChainPem, string Fingerprint,
    string[] Domains, string MaterialDigest);

/// <summary>独立 DSM 会话；SID、CSRF 令牌和密码不写入日志、文件或业务错误。</summary>
public sealed class SynologyDsmSession : IAsyncDisposable
{
    private const int ResponseLimit = 8 * 1024 * 1024;
    private const string Auth = "SYNO.API.Auth", SystemApi = "SYNO.Core.System",
        CertificateApi = "SYNO.Core.Certificate", CertificateListApi = "SYNO.Core.Certificate.CRT";
    private readonly HttpClient client;
    private readonly Dictionary<string, string> paths = new(StringComparer.Ordinal);
    private readonly HashSet<string> jsonParameterApis = new(StringComparer.Ordinal);
    private string sid = "", token = "";
    private bool disposed;
    public string ProductVersion { get; private set; } = "";

    internal SynologyDsmSession(HttpClient client) => this.client = client;

    internal async Task<ApiResult<bool>> InitializeAsync(string username, string password, CancellationToken ct)
    {
        var info = await SendJsonAsync("webapi/query.cgi", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["api"] = "SYNO.API.Info", ["method"] = "query", ["version"] = "1",
            ["query"] = string.Join(',', Auth, SystemApi, CertificateApi, CertificateListApi)
        }), false, false, ct);
        if (!info.Success) return Fail<bool>(info);
        foreach (var api in new[] { Auth, SystemApi, CertificateApi, CertificateListApi })
        {
            var version = api == Auth ? 6 : 1;
            if (info.Data.ValueKind != JsonValueKind.Object || !info.Data.TryGetProperty(api, out var definition) ||
                definition.ValueKind != JsonValueKind.Object || !definition.TryGetProperty("path", out var path) ||
                path.ValueKind != JsonValueKind.String || !SafePath(path.GetString() ?? "") ||
                !definition.TryGetProperty("minVersion", out var min) || !min.TryGetInt32(out var minimum) || minimum > version ||
                !definition.TryGetProperty("maxVersion", out var max) || !max.TryGetInt32(out var maximum) || maximum < version)
                return Protocol<bool>();
            paths[api] = "webapi/" + path.GetString();
            if (api != Auth && definition.TryGetProperty("requestFormat", out var format) &&
                format.ValueKind == JsonValueKind.String && format.GetString() == "JSON")
                jsonParameterApis.Add(api);
        }
        var login = await CallAsync(Auth, "login", new()
        {
            ["account"] = username.Trim(), ["passwd"] = password, ["session"] = "DSM",
            ["format"] = "sid", ["enable_syno_token"] = "yes"
        }, false, true, ct);
        if (!login.Success) return Fail<bool>(login);
        if (!StringProperty(login.Data, "sid", out sid)) return Protocol<bool>();
        if (!StringProperty(login.Data, "synotoken", out token)) return Protocol<bool>();
        client.DefaultRequestHeaders.TryAddWithoutValidation("X-SYNO-TOKEN", token);
        // System/info 的 firmware 查询返回 firmware_ver，而不是猜测 version.major。
        var system = await CallAsync(SystemApi, "info", new() { ["type"] = "firmware" }, false, false, ct);
        if (!system.Success) return Fail<bool>(system);
        if (!StringProperty(system.Data, "firmware_ver", out var versionText)) return Protocol<bool>();
        var match = Regex.Match(versionText, @"^(?:DSM\s+)?(?<major>\d+)\.\d+(?:\.\d+)?(?:[-\s][A-Za-z0-9 ._-]+)?$", RegexOptions.CultureInvariant);
        if (!match.Success || match.Groups["major"].Value != "7")
            return ApiResult<bool>.Fail("PRODUCT_VERSION_UNSUPPORTED", "当前群晖执行器仅支持 DSM 7.x。");
        ProductVersion = versionText;
        return ApiResult<bool>.Ok(true);
    }

    public Task<ApiResult<JsonElement>> ListCertificatesAsync(CancellationToken ct) =>
        CallAsync(CertificateListApi, "list", new(), false, false, ct);

    public async Task<ApiResult<JsonElement>> ImportCertificateAsync(CertificateMaterial material, string remoteId,
        string description, bool isDefault, CancellationToken ct)
    {
        var boundary = "--------------------------" + Guid.NewGuid().ToString("N");
        using var content = new MultipartFormDataContent(boundary);
        // 与 DSM 浏览器及常用客户端的传统上传格式保持一致，减少不同解析器的兼容差异。
        // boundary 不加引号，字段/文件名显式加引号，不额外生成 filename*。
        content.Headers.ContentType!.Parameters.Single(parameter => parameter.Name == "boundary").Value = boundary;
        AddFile(content, "key", "privkey.pem", material.PrivateKeyPem);
        AddFile(content, "cert", "cert.pem", material.CertificatePem);
        AddFile(content, "inter_cert", "chain.pem", material.ChainPem);
        AddField(content, "id", remoteId);
        AddField(content, "desc", description);
        if (isDefault) AddField(content, "as_default", "true");
        // multipart 控制参数按 DSM import 协议放在查询串；认证字段不交给日志组件。
        var query = Fields(CertificateApi, "import", new());
        var path = paths[CertificateApi] + "?" + Encode(query);
        return await SendJsonAsync(path, content, true, false, ct);
    }

    public async Task<ApiResult<SynologyCertificateReadback>> ExportCertificateAsync(string id, CancellationToken ct)
    {
        byte[]? bytes = null;
        try
        {
            var values = new Dictionary<string, string> { ["file"] = "archive", ["id"] = id };
            // JSON 格式按发现结果编码一次；旧导出契约也要求 file 使用 JSON 字符串。
            if (!jsonParameterApis.Contains(CertificateApi)) values["file"] = JsonSerializer.Serialize("archive");
            var fields = Fields(CertificateApi, "export", EncodeParameters(CertificateApi, values));
            using var request = new HttpRequestMessage(HttpMethod.Get, paths[CertificateApi] + "?" + Encode(fields));
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            var read = await CertificateDownloadHelper.ReadLimitedAsync(response.Content, ResponseLimit, ct);
            if (!read.Success) return ApiResult<SynologyCertificateReadback>.Fail("SYNOLOGY_RESPONSE_TOO_LARGE", "群晖证书导出包超出体积限制。");
            bytes = read.Data!;
            if (!response.IsSuccessStatusCode) return ApiResult<SynologyCertificateReadback>.Fail("SYNOLOGY_EXPORT_FAILED", "群晖证书导出失败，请核对权限和目标状态。");
            // 有些错误以 HTTP 200 JSON 返回，不能把错误内容当作证书包。
            if (response.Content.Headers.ContentType?.MediaType?.Contains("json", StringComparison.OrdinalIgnoreCase) == true ||
                bytes.AsSpan().TrimStart((byte)' ').StartsWith("{"u8))
                return ApiResult<SynologyCertificateReadback>.Fail("SYNOLOGY_EXPORT_FAILED", "群晖未返回可核对的证书包，请核对管理员权限。");
            return ReadArchive(bytes);
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException or OperationCanceledException or InvalidDataException or CryptographicException or ArgumentException)
        { return ApiResult<SynologyCertificateReadback>.Fail("SYNOLOGY_EXPORT_FAILED", "群晖证书读回失败或证书包格式不兼容。"); }
        finally { if (bytes is not null) CryptographicOperations.ZeroMemory(bytes); }
    }

    private async Task<ApiResult<JsonElement>> CallAsync(string api, string method, Dictionary<string, string> values,
        bool mutation, bool login, CancellationToken ct) =>
        await SendJsonAsync(paths[api], new FormUrlEncodedContent(Fields(api, method, EncodeParameters(api, values))), mutation, login, ct);

    private Dictionary<string, string> EncodeParameters(string api, Dictionary<string, string> values)
    {
        // DSM JSON API 的业务参数必须 JSON 编码；路由、版本和会话控制字段随后按原始值添加。
        // Auth 使用官方账号密码表单契约，multipart import 使用独立上传契约，均不进入这里的 JSON 分支。
        if (!jsonParameterApis.Contains(api)) return values;
        return values.ToDictionary(pair => pair.Key, pair => JsonSerializer.Serialize(pair.Value), StringComparer.Ordinal);
    }

    private Dictionary<string, string> Fields(string api, string method, Dictionary<string, string> values)
    {
        values["api"] = api; values["method"] = method; values["version"] = api == Auth ? "6" : "1";
        if (sid.Length > 0) values["_sid"] = sid;
        if (token.Length > 0) values["SynoToken"] = token;
        return values;
    }

    private async Task<ApiResult<JsonElement>> SendJsonAsync(string path, HttpContent content, bool mutation,
        bool login, CancellationToken ct)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, path) { Content = content };
            using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (mutation && ((int)response.StatusCode >= 500 || (int)response.StatusCode is >= 300 and < 400))
                return Unknown();
            var bytes = await CertificateDownloadHelper.ReadLimitedAsync(response.Content, ResponseLimit, ct);
            if (!bytes.Success) return mutation ? Unknown() : Protocol<JsonElement>();
            using var json = JsonDocument.Parse(bytes.Data!);
            var root = json.RootElement;
            if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("success", out var success) ||
                success.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
                return mutation ? Unknown() : Protocol<JsonElement>();
            if (!success.GetBoolean())
            {
                var code = root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object &&
                    error.TryGetProperty("code", out var number) && number.TryGetInt32(out var value) ? value : 0;
                if (login && code is 403 or 404 or 406)
                    return ApiResult<JsonElement>.Fail("TWO_FACTOR_REQUIRED", "该群晖账号需要两步验证，当前执行器仅支持账号密码登录。");
                if (login || code is 106 or 107 or 119)
                    return ApiResult<JsonElement>.Fail("AUTHENTICATION_FAILED", "群晖认证失败，请核对账号密码、账号状态及登录策略。");
                if (code == 105) return ApiResult<JsonElement>.Fail("PERMISSION_DENIED", "群晖账号没有证书管理权限，请使用具备权限的管理员账号。");
                // 只返回数字错误码，便于核对 DSM 契约；绝不回显可能包含凭据或材料的远端错误正文。
                return ApiResult<JsonElement>.Fail("SYNOLOGY_API_ERROR", $"群晖接口未完成请求（DSM 错误码 {code}），请核对目标状态和版本兼容性。");
            }
            if (!response.IsSuccessStatusCode) return mutation ? Unknown() : Protocol<JsonElement>();
            return ApiResult<JsonElement>.Ok(root.TryGetProperty("data", out var data) ? data.Clone() : JsonSerializer.SerializeToElement(new { }));
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException or OperationCanceledException or InvalidOperationException)
        { return mutation ? Unknown() : ApiResult<JsonElement>.Fail("CONNECTION_FAILED", "读取群晖失败，请检查连接或接口响应。"); }
    }

    private static ApiResult<SynologyCertificateReadback> ReadArchive(byte[] bytes)
    {
        var files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (bytes.AsSpan().StartsWith("PK"u8))
        {
            if (!CertificateDownloadHelper.ValidateZip(bytes).Success) return Protocol<SynologyCertificateReadback>();
            using var archive = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
            foreach (var entry in archive.Entries)
            {
                var name = Path.GetFileName(entry.FullName);
                if (name is not ("cert.pem" or "chain.pem")) continue;
                using var reader = new StreamReader(entry.Open(), Encoding.UTF8);
                if (!files.TryAdd(name, reader.ReadToEnd())) return Protocol<SynologyCertificateReadback>();
            }
        }
        else if (bytes.Length > 2 && bytes[0] == 0x1f && bytes[1] == 0x8b)
        {
            using var compressed = new GZipStream(new MemoryStream(bytes), CompressionMode.Decompress);
            using var expanded = new MemoryStream();
            var buffer = new byte[16384]; int read;
            while ((read = compressed.Read(buffer)) > 0)
            {
                if (expanded.Length + read > ResponseLimit) return Protocol<SynologyCertificateReadback>();
                expanded.Write(buffer, 0, read);
            }
            expanded.Position = 0;
            try
            {
                using var tar = new TarReader(expanded, leaveOpen: true);
                TarEntry? entry; var count = 0;
                while ((entry = tar.GetNextEntry()) is not null)
                {
                    if (++count > 64 || entry.Length > 2 * 1024 * 1024 ||
                        entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile or TarEntryType.Directory))
                        return Protocol<SynologyCertificateReadback>();
                    var path = entry.Name.Replace('\\', '/');
                    if (path.StartsWith('/') || path.Contains(':') || path.Split('/').Any(part => part == ".."))
                        return Protocol<SynologyCertificateReadback>();
                    var name = Path.GetFileName(path);
                    if (name is not ("cert.pem" or "chain.pem") || entry.DataStream is null) continue;
                    using var reader = new StreamReader(entry.DataStream, Encoding.UTF8, leaveOpen: true);
                    if (!files.TryAdd(name, reader.ReadToEnd())) return Protocol<SynologyCertificateReadback>();
                }
            }
            finally { CryptographicOperations.ZeroMemory(expanded.GetBuffer().AsSpan(0, (int)expanded.Length)); }
        }
        else return Protocol<SynologyCertificateReadback>();
        if (!files.TryGetValue("cert.pem", out var leafPem)) return Protocol<SynologyCertificateReadback>();
        var certificates = new X509Certificate2Collection();
        try
        {
            certificates.ImportFromPem(leafPem);
            // DSM 7.4 的 cert.pem 已包含完整链；较早版本可能把链放在独立 chain.pem。
            // 只提取证书块，丢弃原始 PEM 中任何私钥文本，并保持叶子证书在第一位。
            if (certificates.Count == 0) return Protocol<SynologyCertificateReadback>();
            if (files.TryGetValue("chain.pem", out var chain)) certificates.ImportFromPem(chain);
            if (certificates.Count > 64) return Protocol<SynologyCertificateReadback>();
            var ordered = new List<X509Certificate2>();
            foreach (var certificate in certificates)
            {
                if (ordered.Any(existing => existing.RawData.AsSpan().SequenceEqual(certificate.RawData))) continue;
                ordered.Add(certificate);
                if (ordered.Count > 17) return Protocol<SynologyCertificateReadback>();
            }
            var leaf = ordered[0];
            if (IsCertificateAuthority(leaf) || ordered.Skip(1).Any(certificate => !IsCertificateAuthority(certificate)))
                return Protocol<SynologyCertificateReadback>();
            var normalized = string.Concat(ordered.Select(cert => cert.ExportCertificatePem() + "\n"));
            var domains = leaf.Extensions.OfType<X509SubjectAlternativeNameExtension>()
                .SelectMany(extension => extension.EnumerateDnsNames()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            return ApiResult<SynologyCertificateReadback>.Ok(new(leaf.ExportCertificatePem(),
                string.Concat(ordered.Skip(1).Select(cert => cert.ExportCertificatePem() + "\n")),
                leaf.GetCertHashString(HashAlgorithmName.SHA256), domains,
                Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized)))));
        }
        finally { foreach (var certificate in certificates) certificate.Dispose(); }
    }

    private static bool IsCertificateAuthority(X509Certificate2 certificate) =>
        certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(extension => extension.CertificateAuthority);

    public async ValueTask DisposeAsync()
    {
        if (disposed) return;
        disposed = true;
        try
        {
            if (sid.Length > 0 && paths.ContainsKey(Auth))
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                await CallAsync(Auth, "logout", new() { ["session"] = "DSM" }, false, false, timeout.Token);
            }
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException or ObjectDisposedException) { }
        finally { sid = ""; token = ""; client.Dispose(); }
    }

    private static bool SafePath(string path) => Regex.IsMatch(path, @"^[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*\.cgi$", RegexOptions.CultureInvariant);
    private static bool StringProperty(JsonElement element, string name, out string value)
    {
        value = "";
        if (element.ValueKind != JsonValueKind.Object || !element.TryGetProperty(name, out var property) || property.ValueKind != JsonValueKind.String) return false;
        value = property.GetString() ?? "";
        return value.Length > 0;
    }
    private static string Encode(Dictionary<string, string> fields) => string.Join('&', fields.Select(pair => Uri.EscapeDataString(pair.Key) + "=" + Uri.EscapeDataString(pair.Value)));
    private static void AddFile(MultipartFormDataContent content, string name, string file, string value)
    {
        var part = new ByteArrayContent(Encoding.UTF8.GetBytes(value));
        // DSM 7.4 的上传解析器先从分段首行读取 name；实测 CT 在前会返回 108。
        // 必须先加入 Content-Disposition，再加入 Content-Type，不能仅校验头字段是否存在。
        part.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
        { Name = $"\"{name}\"", FileName = $"\"{file}\"" };
        part.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");
        content.Add(part);
    }
    private static void AddField(MultipartFormDataContent content, string name, string value)
    {
        var part = new ByteArrayContent(Encoding.UTF8.GetBytes(value));
        part.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data") { Name = $"\"{name}\"" };
        content.Add(part);
    }
    private static ApiResult<JsonElement> Unknown() => ApiResult<JsonElement>.Fail("REMOTE_RESULT_UNKNOWN", "群晖导入请求的结果未知，请先核对远端证书，勿直接重复提交。");
    private static ApiResult<T> Protocol<T>() => ApiResult<T>.Fail("SYNOLOGY_PROTOCOL_UNSUPPORTED", "群晖接口或证书包格式不兼容，无法安全核对部署结果。");
    private static ApiResult<T> Fail<T>(ApiResult<JsonElement> result) => ApiResult<T>.Fail(result.Code, result.Message);
}
