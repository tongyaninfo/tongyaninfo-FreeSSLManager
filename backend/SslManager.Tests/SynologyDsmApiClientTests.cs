using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SslManager.Api.Models;
using SslManager.Api.Service.impl;

namespace SslManager.Tests;

/// <summary>群晖协议假服务测试：覆盖凭据传输、版本限制、包读回和不确定写入结果。</summary>
public sealed class SynologyDsmApiClientTests
{
    [Theory]
    [InlineData("https://nas.example.com", 0, 5001)]
    [InlineData("https://nas.example.com:5001", 0, 5001)]
    [InlineData("https://nas.example.com:443", 0, 443)]
    [InlineData("https://nas.example.com:5001", 8443, 8443)]
    [InlineData("https://[::1]", 0, 5001)]
    [InlineData("https://[::1]:443", 0, 443)]
    public void ManagementAddressPreservesExplicitPort(string endpoint, int port, int expected)
    {
        var uri = SynologyDsmApiClient.BaseUri(new() { Endpoint = endpoint, Port = port });
        Assert.Equal(expected, uri.Port);
    }

    [Theory]
    [InlineData("http://nas.example.com")]
    [InlineData("https://admin:password@nas.example.com")]
    [InlineData("https://nas.example.com?token=secret")]
    [InlineData("https://nas.example.com/#secret")]
    public void UnsafeManagementAddressIsRejected(string endpoint) =>
        Assert.Throws<ArgumentException>(() => SynologyDsmApiClient.BaseUri(new() { Endpoint = endpoint }));

    [Fact]
    public async Task PasswordLoginUsesPostAndSessionIsLoggedOut()
    {
        using var fixture = new Fixture();
        var opened = await fixture.Client.OpenAsync(fixture.Target, default);
        Assert.True(opened.Success, opened.Message);
        await using (var session = opened.Data!)
        {
            Assert.Equal("DSM 7.2.2-72806", session.ProductVersion);
            var certificates = await session.ListCertificatesAsync(default);
            Assert.True(certificates.Success);
            Assert.Equal("p &+%中文", fixture.Handler.Password);
            Assert.False(fixture.Handler.CredentialsInUri);
            Assert.True(fixture.Handler.AuthenticatedRequestsHaveToken);
        }
        Assert.Equal(1, fixture.Handler.Logouts);
        Assert.Equal(0, fixture.Handler.ImportCount);
    }

    [Theory]
    [InlineData(403)]
    [InlineData(404)]
    [InlineData(406)]
    public async Task TwoFactorLoginFailsWithExplicitUnsupportedResult(int code)
    {
        using var fixture = new Fixture();
        fixture.Handler.LoginError = code;
        var opened = await fixture.Client.OpenAsync(fixture.Target, default);
        Assert.Equal("TWO_FACTOR_REQUIRED", opened.Code);
        Assert.Equal(0, fixture.Handler.ImportCount);
    }

    [Fact]
    public async Task OtherDsmMajorIsRejectedAndAuthenticatedSessionClosed()
    {
        using var fixture = new Fixture();
        fixture.Handler.Version = "DSM 6.2.4-25556";
        var result = await fixture.Client.OpenAsync(fixture.Target, default);
        Assert.Equal("PRODUCT_VERSION_UNSUPPORTED", result.Code);
        Assert.Equal(1, fixture.Handler.Logouts);
    }

    [Theory]
    [InlineData("https://attacker.example.com/entry.cgi")]
    [InlineData("//attacker.example.com/entry.cgi")]
    [InlineData("../entry.cgi")]
    [InlineData("entry.cgi?forward=1")]
    [InlineData("%2e%2e/entry.cgi")]
    public async Task ApiDiscoveryCannotRedirectCredentials(string path)
    {
        using var fixture = new Fixture();
        fixture.Handler.AuthPath = path;
        var result = await fixture.Client.OpenAsync(fixture.Target, default);
        Assert.Equal("SYNOLOGY_PROTOCOL_UNSUPPORTED", result.Code);
        Assert.Null(fixture.Handler.Password);
    }

    [Fact]
    public async Task ImportUsesSeparateLeafKeyAndChainAndPreservesDefaultOnlyWhenRequested()
    {
        using var fixture = new Fixture();
        var opened = await fixture.Client.OpenAsync(fixture.Target, default);
        await using var session = opened.Data!;
        var result = await session.ImportCertificateAsync(fixture.Material, "abc", "现有证书", true, default);
        Assert.True(result.Success);
        Assert.Equal("abc", fixture.Handler.ImportFields["id"]);
        Assert.Equal("现有证书", fixture.Handler.ImportFields["desc"]);
        Assert.Equal("true", fixture.Handler.ImportFields["as_default"]);
        Assert.Equal(fixture.Material.CertificatePem, fixture.Handler.ImportFields["cert"]);
        Assert.Equal(fixture.Material.PrivateKeyPem, fixture.Handler.ImportFields["key"]);
        Assert.Equal(fixture.Material.ChainPem, fixture.Handler.ImportFields["inter_cert"]);
        await session.ImportCertificateAsync(fixture.Material, "", "新增证书", false, default);
        Assert.False(fixture.Handler.ImportFields.ContainsKey("as_default"));
        Assert.Equal(2, fixture.Handler.ImportCount);
    }

    [Fact]
    public async Task ImportWireUsesBrowserCompatibleMultipartHeaders()
    {
        using var fixture = new Fixture();
        var opened = await fixture.Client.OpenAsync(fixture.Target, default);
        await using var session = opened.Data!;
        var result = await session.ImportCertificateAsync(fixture.Material, "abc", "现有证书", true, default);
        Assert.True(result.Success);
        // 检查实际序列化字节，不能只枚举 .NET 内容对象而漏掉 DSM 对上传头的兼容要求。
        var type = fixture.Handler.ImportContentType;
        Assert.StartsWith("multipart/form-data; boundary=", type);
        Assert.DoesNotContain("\"", type);
        var boundary = type[(type.IndexOf("boundary=", StringComparison.Ordinal) + "boundary=".Length)..];
        var wire = Encoding.UTF8.GetString(fixture.Handler.ImportWire);
        Assert.StartsWith("--" + boundary + "\r\n", wire);
        Assert.EndsWith("--" + boundary + "--\r\n", wire);
        Assert.DoesNotContain("filename*=", wire);
        // DSM 上传解析器要求每段首行为 Content-Disposition；仅断言头存在无法捕获顺序错误。
        foreach (var (name, file) in new[] { ("key", "privkey.pem"), ("cert", "cert.pem"), ("inter_cert", "chain.pem") })
            Assert.Contains($"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{file}\"\r\n" +
                "Content-Type: application/octet-stream\r\n\r\n", wire);
        foreach (var name in new[] { "id", "desc", "as_default" })
            Assert.Contains($"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n", wire);
    }

    [Fact]
    public async Task ImportApiErrorIncludesOnlyNumericDsmCode()
    {
        using var fixture = new Fixture();
        fixture.Handler.ImportBehavior = "api-error";
        var opened = await fixture.Client.OpenAsync(fixture.Target, default);
        await using var session = opened.Data!;
        var result = await session.ImportCertificateAsync(fixture.Material, "abc", "existing", true, default);
        Assert.False(result.Success);
        Assert.Equal("SYNOLOGY_API_ERROR", result.Code);
        Assert.Contains("5510", result.Message);
        Assert.DoesNotContain("never-return-remote-secret", result.Message);
        Assert.Equal(JsonValueKind.Undefined, result.Data.ValueKind);
        Assert.Equal(1, fixture.Handler.ImportCount);
    }

    [Theory]
    [InlineData("500")]
    [InlineData("302")]
    [InlineData("malformed")]
    [InlineData("timeout")]
    [InlineData("missing-success")]
    public async Task UncertainImportNeverRetriesOrClaimsSuccess(string behavior)
    {
        using var fixture = new Fixture();
        fixture.Handler.ImportBehavior = behavior;
        var opened = await fixture.Client.OpenAsync(fixture.Target, default);
        await using var session = opened.Data!;
        var result = await session.ImportCertificateAsync(fixture.Material, "abc", "existing", true, default);
        Assert.Equal("REMOTE_RESULT_UNKNOWN", result.Code);
        Assert.Equal(1, fixture.Handler.ImportCount);
    }

    [Fact]
    public async Task ExportReadsOnlyPublicCertificateAndComputesMaterialDigest()
    {
        using var fixture = new Fixture();
        var opened = await fixture.Client.OpenAsync(fixture.Target, default);
        await using var session = opened.Data!;
        var read = await session.ExportCertificateAsync("id with + &", default);
        Assert.True(read.Success, read.Message);
        Assert.Equal("id with + &", fixture.Handler.ExportId);
        Assert.Equal("\"archive\"", fixture.Handler.ExportFile);
        Assert.Equal(fixture.Material.Metadata.Fingerprint, read.Data!.Fingerprint);
        Assert.Equal(fixture.Material.Metadata.MaterialDigest, read.Data.MaterialDigest);
        Assert.Equal(["nas.example.com"], read.Data.Domains);
        Assert.DoesNotContain("PRIVATE KEY", JsonSerializer.Serialize(read.Data));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task ApiRequestFormatControlsBusinessParameterEncodingWithoutChangingAuthentication(bool jsonFormat)
    {
        using var fixture = new Fixture();
        fixture.Handler.JsonRequestFormat = jsonFormat;
        var opened = await fixture.Client.OpenAsync(fixture.Target, default);
        Assert.True(opened.Success, opened.Message);
        await using var session = opened.Data!;
        var result = await session.ExportCertificateAsync("id with \"quotes\" & symbols", default);
        Assert.True(result.Success, result.Message);
        Assert.Equal(jsonFormat ? "\"firmware\"" : "firmware", fixture.Handler.SystemTypeWire);
        Assert.Equal(jsonFormat ? JsonSerializer.Serialize("id with \"quotes\" & symbols") : "id with \"quotes\" & symbols", fixture.Handler.ExportIdWire);
        Assert.Equal("\"archive\"", fixture.Handler.ExportFile);
        Assert.Equal("p &+%中文", fixture.Handler.Password);
        Assert.True(fixture.Handler.AuthenticatedRequestsHaveToken);
    }

    [Theory]
    [InlineData("embedded")]
    [InlineData("separate")]
    [InlineData("overlap")]
    [InlineData("repeated-leaf")]
    [InlineData("embedded-key")]
    public async Task DsmExportNormalizesEmbeddedAndSeparateChainsWithoutDuplicatesOrPrivateKeys(string shape)
    {
        using var fixture = new Fixture(withChain: true);
        fixture.Handler.ExportCertificatePem = shape == "separate" ? fixture.Material.CertificatePem : fixture.Material.FullChainPem;
        fixture.Handler.ExportChainPem = shape is "separate" or "overlap" ? fixture.Material.ChainPem : null;
        if (shape == "repeated-leaf")
            fixture.Handler.ExportChainPem = fixture.Material.FullChainPem + fixture.Material.ChainPem;
        if (shape == "embedded-key")
            fixture.Handler.ExportCertificatePem += fixture.Material.PrivateKeyPem;
        var opened = await fixture.Client.OpenAsync(fixture.Target, default);
        await using var session = opened.Data!;
        var read = await session.ExportCertificateAsync("abc", default);
        Assert.True(read.Success, read.Message);
        Assert.Equal(fixture.Material.CertificatePem, read.Data!.CertificatePem);
        Assert.Equal(fixture.Material.ChainPem, read.Data.ChainPem);
        Assert.Equal(fixture.Material.Metadata.Fingerprint, read.Data.Fingerprint);
        Assert.Equal(fixture.Material.Metadata.MaterialDigest, read.Data.MaterialDigest);
        Assert.Equal(["nas.example.com"], read.Data.Domains);
        Assert.DoesNotContain("PRIVATE KEY", JsonSerializer.Serialize(read.Data));
    }

    [Theory]
    [InlineData("too-many")]
    [InlineData("ca-first")]
    [InlineData("two-leaves")]
    public async Task AmbiguousOrExcessiveExportedCertificateSequenceIsRejected(string shape)
    {
        using var fixture = new Fixture(withChain: true);
        using var other = new Fixture();
        fixture.Handler.ExportCertificatePem = shape switch
        {
            "too-many" => string.Concat(Enumerable.Repeat(fixture.Material.CertificatePem + "\n", 65)),
            "ca-first" => fixture.Material.ChainPem + fixture.Material.CertificatePem,
            _ => fixture.Material.FullChainPem + other.Material.CertificatePem
        };
        var opened = await fixture.Client.OpenAsync(fixture.Target, default);
        await using var session = opened.Data!;
        var read = await session.ExportCertificateAsync("abc", default);
        Assert.False(read.Success);
        Assert.Equal("SYNOLOGY_PROTOCOL_UNSUPPORTED", read.Code);
    }

    [Theory]
    [InlineData("../cert.pem")]
    [InlineData("/cert.pem")]
    [InlineData("duplicate")]
    [InlineData("missing")]
    public async Task UnexpectedCertificateArchiveIsRejected(string path)
    {
        using var fixture = new Fixture();
        fixture.Handler.ArchivePath = path;
        var opened = await fixture.Client.OpenAsync(fixture.Target, default);
        await using var session = opened.Data!;
        var read = await session.ExportCertificateAsync("abc", default);
        Assert.False(read.Success);
    }

    [Fact]
    public async Task RemoteErrorDetailsNeverExposeSecrets()
    {
        using var fixture = new Fixture();
        fixture.Handler.LoginError = 400;
        var result = await fixture.Client.OpenAsync(fixture.Target, default);
        Assert.Equal("AUTHENTICATION_FAILED", result.Code);
        Assert.DoesNotContain("never-return-remote-secret", JsonSerializer.Serialize(result));
        Assert.DoesNotContain("p &+%中文", JsonSerializer.Serialize(result));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly RSA key = RSA.Create(2048);
        private readonly X509Certificate2 certificate;
        private readonly RSA? issuerKey;
        private readonly X509Certificate2? issuer;
        public Handler Handler { get; }
        public SynologyDsmApiClient Client { get; }
        public DeploymentTargetContext Target { get; } = new()
        {
            Endpoint = "https://nas.example.com:5001", Username = "admin", AuthenticationMode = "Password",
            Credentials = new() { Password = "p &+%中文" }
        };
        public CertificateMaterial Material { get; }
        public Fixture(bool withChain = false)
        {
            var request = new CertificateRequest("CN=nas.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("nas.example.com"); request.CertificateExtensions.Add(san.Build());
            var chainPem = "";
            if (withChain)
            {
                issuerKey = RSA.Create(2048);
                var issuerRequest = new CertificateRequest("CN=Test Root", issuerKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
                issuerRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
                issuer = issuerRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(60));
                certificate = request.Create(issuer, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), RandomNumberGenerator.GetBytes(16));
                chainPem = issuer.ExportCertificatePem() + "\n";
            }
            else certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            var pem = certificate.ExportCertificatePem();
            Material = new()
            {
                CertificatePem = pem, ChainPem = chainPem, FullChainPem = pem + "\n" + chainPem, PrivateKeyPem = key.ExportPkcs8PrivateKeyPem(),
                Metadata = new("local-id", "nas.example.com", ["nas.example.com"], certificate.GetCertHashString(HashAlgorithmName.SHA256),
                    Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pem + "\n" + chainPem))), DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30))
            };
            Handler = new(Material);
            Client = new(_ => new HttpClient(Handler, disposeHandler: false));
        }
        public void Dispose() { Handler.Dispose(); certificate.Dispose(); key.Dispose(); issuer?.Dispose(); issuerKey?.Dispose(); }
    }

    private sealed class Handler(CertificateMaterial material) : HttpMessageHandler
    {
        public string Version { get; set; } = "DSM 7.2.2-72806";
        public int LoginError { get; set; }
        public string AuthPath { get; set; } = "entry.cgi";
        public string ImportBehavior { get; set; } = "ok";
        public string ArchivePath { get; set; } = "cert.pem";
        public string? ExportCertificatePem { get; set; }
        public string? ExportChainPem { get; set; }
        public bool JsonRequestFormat { get; set; } = true;
        public string? Password { get; private set; }
        public bool CredentialsInUri { get; private set; }
        public bool AuthenticatedRequestsHaveToken { get; private set; } = true;
        public int Logouts { get; private set; }
        public int ImportCount { get; private set; }
        public string ExportId { get; private set; } = "";
        public string ExportFile { get; private set; } = "";
        public string ExportIdWire { get; private set; } = "";
        public string SystemTypeWire { get; private set; } = "";
        public string ImportContentType { get; private set; } = "";
        public byte[] ImportWire { get; private set; } = [];
        public Dictionary<string, string> ImportFields { get; } = new();
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var values = Parse(request.RequestUri!.Query.TrimStart('?'));
            if (request.Content?.Headers.ContentType?.MediaType == "application/x-www-form-urlencoded")
                foreach (var pair in Parse(await request.Content.ReadAsStringAsync(ct))) values[pair.Key] = pair.Value;
            var api = values["api"];
            var method = values["method"];
            if (api == "SYNO.API.Info")
                return Json(new { success = true, data = new Dictionary<string, object>
                {
                    ["SYNO.API.Auth"] = new { path = AuthPath, minVersion = 1, maxVersion = 7 },
                    ["SYNO.Core.System"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 3, requestFormat = JsonRequestFormat ? "JSON" : "" },
                    ["SYNO.Core.Certificate"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 1, requestFormat = JsonRequestFormat ? "JSON" : "" },
                    ["SYNO.Core.Certificate.CRT"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 1, requestFormat = JsonRequestFormat ? "JSON" : "" }
                } });
            if (method == "login")
            {
                Assert.Equal(HttpMethod.Post, request.Method);
                Password = values["passwd"];
                CredentialsInUri = request.RequestUri.Query.Contains("passwd", StringComparison.Ordinal);
                return LoginError == 0 ? Json(new { success = true, data = new { sid = "session-secret", synotoken = "csrf-secret" } }) :
                    Json(new { success = false, error = new { code = LoginError, message = "never-return-remote-secret" } });
            }
            Assert.Equal("session-secret", values["_sid"]);
            AuthenticatedRequestsHaveToken &= request.Headers.TryGetValues("X-SYNO-TOKEN", out var tokens) && tokens.Single() == "csrf-secret";
            if (method == "logout") { Logouts++; return Json(new { success = true }); }
            if (api == "SYNO.Core.System")
            {
                SystemTypeWire = values["type"];
                Assert.Equal(JsonRequestFormat ? "\"firmware\"" : "firmware", SystemTypeWire);
                return Json(new { success = true, data = new { firmware_ver = Version } });
            }
            if (method == "list") return Json(new { success = true, data = new { certificates = Array.Empty<object>() } });
            if (method == "import")
            {
                ImportCount++;
                ImportContentType = request.Content!.Headers.ContentType!.ToString();
                ImportWire = await request.Content.ReadAsByteArrayAsync(ct);
                ImportFields.Clear();
                foreach (var field in (MultipartFormDataContent)request.Content!)
                    ImportFields[field.Headers.ContentDisposition!.Name!.Trim('"')] = await field.ReadAsStringAsync(ct);
                return ImportBehavior switch
                {
                    "500" => new(HttpStatusCode.InternalServerError),
                    "302" => new(HttpStatusCode.Redirect),
                    "malformed" => new(HttpStatusCode.OK) { Content = new StringContent("<html>updating</html>") },
                    "missing-success" => Json(new { data = new { id = "abc" } }),
                    "api-error" => Json(new { success = false, error = new { code = 5510, message = "never-return-remote-secret" } }),
                    "timeout" => throw new TaskCanceledException("private remote message"),
                    _ => Json(new { success = true, data = new { id = "abc", restart_httpd = true } })
                };
            }
            if (method == "export")
            {
                ExportIdWire = values["id"];
                ExportId = JsonRequestFormat ? JsonSerializer.Deserialize<string>(ExportIdWire)! : ExportIdWire;
                ExportFile = values["file"];
                using var stream = new MemoryStream();
                using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
                {
                    Write(zip, ArchivePath is "duplicate" ? "cert.pem" : ArchivePath, ExportCertificatePem ?? material.CertificatePem);
                    if (ArchivePath == "duplicate") Write(zip, "other/cert.pem", material.CertificatePem);
                    if (ExportChainPem is not null) Write(zip, "chain.pem", ExportChainPem);
                    Write(zip, "privkey.pem", material.PrivateKeyPem);
                }
                return new(HttpStatusCode.OK) { Content = new ByteArrayContent(stream.ToArray()) };
            }
            throw new InvalidOperationException("Unexpected fake request.");
        }
        private static void Write(ZipArchive zip, string path, string value)
        { using var writer = new StreamWriter(zip.CreateEntry(path).Open()); writer.Write(value); }
        private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK) { Content = JsonContent.Create(value) };
        private static Dictionary<string, string> Parse(string text) => text.Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(value => value.Split('=', 2)).ToDictionary(parts => WebUtility.UrlDecode(parts[0]), parts => WebUtility.UrlDecode(parts.ElementAtOrDefault(1) ?? ""));
    }
}
