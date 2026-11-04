using System.IO.Compression;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;

namespace SslManager.Tests;

/// <summary>使用内存 HTTP 协议目标验证雷池、群晖的写后响应丢失与逐项恢复，不访问真实平台。</summary>
public sealed class PlatformDeploymentRecoveryTests
{
    [Theory]
    [InlineData("safeline")]
    [InlineData("synology")]
    public async Task AcceptedUploadWithLostResponseIsReadBackWithoutAnotherUpload(string platform)
    {
        using var fixture = new Fixture(platform);
        var plan = await fixture.PlanAsync();
        fixture.Handler.LoseUploadResponse = true;
        var interrupted = await fixture.Executor.ExecuteAsync(fixture.Context(plan), default);
        Assert.False(interrupted.Success);
        Assert.Equal(1, fixture.Handler.Uploads);

        var result = await fixture.NewRecoveryExecutor().RecoverAsync(fixture.Context(plan, true), default);

        Assert.True(result.Success, result.Message);
        Assert.Equal("Completed", result.Data!.Disposition);
        Assert.Equal("PlatformReadback", result.Data.Result!.VerificationLevel);
        Assert.Equal(1, fixture.Handler.Uploads);
        Assert.Equal(fixture.Material.Metadata.Fingerprint, result.Data.Result.Fingerprint);
    }

    [Theory]
    [InlineData("safeline")]
    [InlineData("synology")]
    public async Task ProcessExitBeforeSavingUploadCompletionUsesTheEarlierIntentAndRemoteReadback(string platform)
    {
        using var fixture = new Fixture(platform);
        var plan = await fixture.PlanAsync();
        fixture.CrashBeforeCheckpointPhase = "Uploaded";
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Executor.ExecuteAsync(fixture.Context(plan), default));
        using (var checkpoint = JsonDocument.Parse(fixture.Checkpoint))
        {
            Assert.True(checkpoint.RootElement.GetProperty("uploadStarted").GetBoolean());
            Assert.False(checkpoint.RootElement.GetProperty("uploadCompleted").GetBoolean());
        }
        fixture.CrashBeforeCheckpointPhase = "";

        var result = await fixture.NewRecoveryExecutor().RecoverAsync(fixture.Context(plan, true), default);

        Assert.True(result.Success, result.Message);
        Assert.Equal(1, fixture.Handler.Uploads);
        Assert.DoesNotContain(fixture.Material.PrivateKeyPem, fixture.Checkpoint);
    }

    [Theory]
    [InlineData("safeline")]
    [InlineData("synology")]
    public async Task UnknownCreateThatIsNotVisibleYetOnlyRetriesReadback(string platform)
    {
        using var fixture = new Fixture(platform);
        var plan = await fixture.PlanAsync();
        fixture.Checkpoint = "{\"schemaVersion\":1,\"submissionState\":\"Submitting\",\"action\":\"Create\",\"uploadStarted\":true}";

        var first = await fixture.NewRecoveryExecutor().RecoverAsync(fixture.Context(plan, true), default);
        var second = await fixture.NewRecoveryExecutor().RecoverAsync(fixture.Context(plan, true), default);

        Assert.False(first.Success);
        Assert.Equal("Retry", first.Data!.Disposition);
        Assert.Equal("Retry", second.Data!.Disposition);
        Assert.Equal(0, fixture.Handler.Uploads);
        Assert.Empty(fixture.Handler.BindingWrites);
    }

    [Theory]
    [InlineData("safeline")]
    [InlineData("synology")]
    public async Task ForeignChangeToTheOriginalResourceBlocksRecoveryBeforeUpload(string platform)
    {
        using var fixture = new Fixture(platform);
        using var oldMaterial = new MaterialSet();
        fixture.UseExisting(oldMaterial.Material);
        var plan = await fixture.PlanAsync();
        Assert.Equal("Update", plan.Action);
        if (platform == "safeline")
        {
            fixture.Handler.SiteBindings[15] = 10;
            // 新增原计划之外的关联站点，不能通过重新取前置条件自动接管。
        }
        else fixture.Handler.IsDefault = true;

        var result = await fixture.NewRecoveryExecutor().RecoverAsync(fixture.Context(plan, true), default);

        Assert.False(result.Success);
        Assert.Equal("Blocked", result.Data!.Disposition);
        Assert.Equal(0, fixture.Handler.Uploads);
    }

    [Fact]
    public async Task SafeLineRecoversTheMissingSiteBindingWithoutReuploadingOrRebindingTheCompletedSite()
    {
        using var fixture = new Fixture("safeline");
        fixture.Target.Configuration.BindSites = true;
        fixture.Target.Configuration.SiteIds = ["15", "16"];
        fixture.Handler.SiteBindings[15] = 0; fixture.Handler.SiteBindings[16] = 0;
        var plan = await fixture.PlanAsync();
        fixture.Handler.LoseBindingResponseAt = 1;
        var interrupted = await fixture.Executor.ExecuteAsync(fixture.Context(plan), default);
        Assert.False(interrupted.Success);
        Assert.Equal(10, fixture.Handler.SiteBindings[15]);
        Assert.Equal(0, fixture.Handler.SiteBindings[16]);

        var result = await fixture.NewRecoveryExecutor().RecoverAsync(fixture.Context(plan, true), default);

        Assert.True(result.Success, result.Message);
        Assert.Equal(1, fixture.Handler.Uploads);
        Assert.Equal(new[] { 15, 16 }, fixture.Handler.BindingWrites);
        Assert.All(fixture.Handler.SiteBindings.Values, id => Assert.Equal(10, id));
    }

    [Fact]
    public async Task SafeLineUnfinishedBindingWithAForeignSiteConfigurationIsBlocked()
    {
        using var fixture = new Fixture("safeline");
        fixture.Target.Configuration.BindSites = true;
        fixture.Target.Configuration.SiteIds = ["15", "16"];
        fixture.Handler.SiteBindings[15] = 0; fixture.Handler.SiteBindings[16] = 0;
        var plan = await fixture.PlanAsync();
        fixture.Handler.LoseBindingResponseAt = 1;
        Assert.False((await fixture.Executor.ExecuteAsync(fixture.Context(plan), default)).Success);
        fixture.Handler.SiteComments[16] = "changed by another administrator";

        var result = await fixture.NewRecoveryExecutor().RecoverAsync(fixture.Context(plan, true), default);

        Assert.False(result.Success);
        Assert.Equal("Blocked", result.Data!.Disposition);
        Assert.Equal(1, fixture.Handler.Uploads);
        Assert.Equal(new[] { 15 }, fixture.Handler.BindingWrites);
        Assert.Equal(0, fixture.Handler.SiteBindings[16]);
    }

    [Fact]
    public async Task SynologyUploadedCertificateWithForeignDefaultStateIsBlocked()
    {
        using var fixture = new Fixture("synology");
        var plan = await fixture.PlanAsync();
        fixture.Handler.LoseUploadResponse = true;
        Assert.False((await fixture.Executor.ExecuteAsync(fixture.Context(plan), default)).Success);
        fixture.Handler.IsDefault = true;

        var result = await fixture.NewRecoveryExecutor().RecoverAsync(fixture.Context(plan, true), default);

        Assert.False(result.Success);
        Assert.Equal("Blocked", result.Data!.Disposition);
        Assert.Equal(1, fixture.Handler.Uploads);
    }

    [Theory]
    [InlineData("safeline", "{")]
    [InlineData("synology", "{")]
    [InlineData("safeline", "{\"schemaVersion\":99}")]
    [InlineData("synology", "{\"schemaVersion\":99}")]
    [InlineData("safeline", "{\"schemaVersion\":\"broken\"}")]
    [InlineData("synology", "{\"schemaVersion\":\"broken\"}")]
    public async Task CorruptOrUnsupportedReceiptBlocksBeforeAnyWrite(string platform, string receipt)
    {
        using var fixture = new Fixture(platform);
        var plan = await fixture.PlanAsync(); fixture.Checkpoint = receipt;
        var result = await fixture.NewRecoveryExecutor().RecoverAsync(fixture.Context(plan, true), default);
        Assert.False(result.Success);
        Assert.Equal("Blocked", result.Data!.Disposition);
        Assert.Equal("RECOVERY_RECEIPT_INVALID", result.Code);
        Assert.Equal(0, fixture.Handler.Uploads);
    }

    [Theory]
    [InlineData("safeline")]
    [InlineData("synology")]
    public async Task LegacyEmptyCreateReceiptCannotBeTreatedAsNeverSubmitted(string platform)
    {
        using var fixture = new Fixture(platform);
        var plan = await fixture.PlanAsync(); fixture.Checkpoint = "{}";
        var result = await fixture.NewRecoveryExecutor().RecoverAsync(fixture.Context(plan, true), default);
        Assert.False(result.Success);
        Assert.Equal("Blocked", result.Data!.Disposition);
        Assert.Equal(0, fixture.Handler.Uploads);
    }

    [Theory]
    [InlineData("safeline")]
    [InlineData("synology")]
    public async Task KnownUnsubmittedCheckpointCanStartTheOriginalCreate(string platform)
    {
        using var fixture = new Fixture(platform);
        var plan = await fixture.PlanAsync();
        var result = await fixture.NewRecoveryExecutor().RecoverAsync(fixture.Context(plan, true), default);
        Assert.True(result.Success, result.Message);
        Assert.Equal(1, fixture.Handler.Uploads);
    }

    [Fact]
    public async Task SafeLineAlreadyBoundSiteWithChangedDomainsIsNotSuccessfulRecovery()
    {
        using var fixture = new Fixture("safeline");
        fixture.Target.Configuration.BindSites = true; fixture.Target.Configuration.SiteIds = ["15", "16"];
        fixture.Handler.SiteBindings[15] = 0; fixture.Handler.SiteBindings[16] = 0;
        var plan = await fixture.PlanAsync();
        fixture.Handler.LoseBindingResponseAt = 1;
        Assert.False((await fixture.Executor.ExecuteAsync(fixture.Context(plan), default)).Success);
        fixture.Handler.SiteDomains[15] = "operator-changed.example.net";
        var recovered = await fixture.NewRecoveryExecutor().RecoverAsync(fixture.Context(plan, true), default);
        Assert.False(recovered.Success);
        Assert.Equal("Blocked", recovered.Data!.Disposition);
        Assert.Equal(1, fixture.Handler.Uploads);
        Assert.Equal(new[] { 15 }, fixture.Handler.BindingWrites);
        var inspected = await fixture.Executor.InspectAsync(new(fixture.Target, plan with { RemoteResourceId = "10" }, fixture.Material.Metadata), default);
        Assert.True(inspected.Success);
        Assert.False(inspected.Data!.MatchesExpected);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly string platform;
        private readonly MaterialSet materials = new();
        public PlatformHandler Handler { get; }
        public IDeploymentExecutor Executor { get; }
        public CertificateMaterial Material => materials.Material;
        public DeploymentTargetContext Target { get; }
        public string Checkpoint { get; set; } = "{}";
        public string CrashBeforeCheckpointPhase { get; set; } = "";
        public Fixture(string platform)
        {
            this.platform = platform;
            Handler = new(platform);
            Target = new()
            {
                Id = "target", Endpoint = platform == "safeline" ? "https://safeline.example.test:9443" : "https://dsm.example.test:5001",
                Port = platform == "safeline" ? 9443 : 5001, ExecutorKey = platform == "safeline" ? "safeline.ce.9.x" : "synology.dsm.7.x",
                Username = "test-user", AuthenticationMode = platform == "safeline" ? "ApiToken" : "Password",
                Credentials = new() { ApiToken = "fake-token", Password = "fake-password" }
            };
            Executor = NewExecutor();
        }
        private IDeploymentExecutor NewExecutor() => platform == "safeline"
            ? new SafeLineCe9DeploymentExecutor(new SafeLineCe9ApiClient(_ => new HttpClient(Handler, false)))
            : new SynologyDsm7DeploymentExecutor(new SynologyDsmApiClient(_ => new HttpClient(Handler, false)));
        public IDeploymentRecoveryExecutor NewRecoveryExecutor() => (IDeploymentRecoveryExecutor)NewExecutor();
        public void UseExisting(CertificateMaterial material)
        {
            Handler.Id = platform == "safeline" ? "10" : "existing-cert";
            Handler.Description = "existing-certificate";
            Handler.CertificatePem = platform == "safeline" ? material.FullChainPem : material.CertificatePem;
            Handler.ChainPem = material.ChainPem;
            Target.Configuration.RemoteCertificateId = Handler.Id;
        }
        public async Task<DeploymentTargetPlan> PlanAsync()
        {
            var result = await Executor.PlanAsync(Target, Material.Metadata, new(Target.Id), default);
            Assert.True(result.Success, result.Message);
            // 与部署服务同次保存草稿时的正面未提交哨兵保持一致。
            Checkpoint = JsonSerializer.Serialize(new { schemaVersion = 1, submissionState = "NotStarted", action = result.Data!.Action,
                remoteId = result.Data.RemoteResourceId, uploadStarted = false, uploadCompleted = false });
            return result.Data!;
        }
        public DeploymentExecutionContext Context(DeploymentTargetPlan plan, bool recovery = false) => new()
        {
            TaskId = "task", Target = Target, Material = Material, Plan = plan, IsRecovery = recovery, ReceiptJson = Checkpoint,
            ReportProgressAsync = (_, _, _) => Task.CompletedTask,
            SaveCheckpointAsync = (phase, receipt, _) =>
            {
                if (CrashBeforeCheckpointPhase == phase) throw new ProcessExit();
                Checkpoint = receipt; return Task.CompletedTask;
            }
        };
        public void Dispose() { materials.Dispose(); Handler.Dispose(); }
    }

    private sealed class MaterialSet : IDisposable
    {
        private readonly RSA key = RSA.Create(2048);
        private readonly X509Certificate2 certificate;
        public CertificateMaterial Material { get; }
        public MaterialSet()
        {
            var request = new CertificateRequest("CN=one.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("one.example.test"); request.CertificateExtensions.Add(san.Build());
            certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            var parsed = CertificateMaterialHelper.FromPem([certificate.ExportCertificatePem()], [key.ExportPkcs8PrivateKeyPem()], "certificate", "one.example.test");
            Assert.True(parsed.Success, parsed.Message); Material = parsed.Data!;
        }
        public void Dispose() { certificate.Dispose(); key.Dispose(); }
    }

    private sealed class ProcessExit : Exception;

    /// <summary>只模拟执行器真正使用的协议路由，写入先改变远端状态，再按场景丢失响应。</summary>
    private sealed class PlatformHandler(string platform) : HttpMessageHandler
    {
        public string Id { get; set; } = "";
        public string Description { get; set; } = "";
        public string CertificatePem { get; set; } = "";
        public string ChainPem { get; set; } = "";
        public bool IsDefault { get; set; }
        public Dictionary<int, int> SiteBindings { get; } = [];
        public Dictionary<int, string> SiteComments { get; } = [];
        public Dictionary<int, string> SiteDomains { get; } = [];
        public List<int> BindingWrites { get; } = [];
        public int Uploads { get; private set; }
        public bool LoseUploadResponse { get; set; }
        public int LoseBindingResponseAt { get; set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) =>
            platform == "safeline" ? SafeLineAsync(request, ct) : SynologyAsync(request, ct);

        private async Task<HttpResponseMessage> SafeLineAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/system")) return SafeLineResponse(new { version = "9.3.9" });
            if (path.EndsWith("/cert") && request.Method == HttpMethod.Post)
            {
                using var json = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
                CertificatePem = json.RootElement.GetProperty("manual").GetProperty("crt").GetString()!;
                Id = "10"; Uploads++;
                if (LoseUploadResponse) throw new HttpRequestException("Upload response lost after commit");
                return SafeLineResponse(new { id = 10 });
            }
            if (path.EndsWith("/cert"))
            {
                var nodes = new List<object>();
                if (Id.Length > 0) nodes.Add(new { id = 10, type = 2, domains = new[] { "one.example.test" } });
                return SafeLineResponse(new { nodes, total = nodes.Count });
            }
            if (path.EndsWith("/cert/10")) return SafeLineResponse(new { type = 2, manual = new { crt = CertificatePem } });
            if (path.EndsWith("/site") && request.Method == HttpMethod.Put)
            {
                using var json = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
                var id = json.RootElement.GetProperty("id").GetInt32();
                SiteBindings[id] = json.RootElement.GetProperty("cert_id").GetInt32(); BindingWrites.Add(id);
                if (LoseBindingResponseAt == BindingWrites.Count) throw new HttpRequestException("Site response lost after commit");
                return SafeLineResponse(new { });
            }
            if (path.EndsWith("/site"))
                return SafeLineResponse(new { data = SiteBindings.Select(pair => new { id = pair.Key, server_names = new[] { SiteDomains.GetValueOrDefault(pair.Key, "one.example.test") }, cert_id = pair.Value }).ToArray(), total = SiteBindings.Count });
            if (path.Contains("/site/", StringComparison.Ordinal))
            {
                var id = int.Parse(path.Split('/')[^1]);
                return SafeLineResponse(new { id, server_names = new[] { SiteDomains.GetValueOrDefault(id, "one.example.test") }, cert_id = SiteBindings[id],
                    comment = SiteComments.GetValueOrDefault(id, ""), ports = new[] { "443_ssl" }, upstreams = new[] { "127.0.0.1:80" } });
            }
            throw new InvalidOperationException("Unexpected SafeLine test route: " + path);
        }

        private async Task<HttpResponseMessage> SynologyAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var fields = Query(request.RequestUri!.Query);
            if (request.Content is FormUrlEncodedContent)
                foreach (var pair in Query(await request.Content.ReadAsStringAsync(ct))) fields[pair.Key] = pair.Value;
            var api = fields.GetValueOrDefault("api", ""); var method = fields.GetValueOrDefault("method", "");
            if (api == "SYNO.API.Info") return DsmResponse(new Dictionary<string, object>
            {
                ["SYNO.API.Auth"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 7 },
                ["SYNO.Core.System"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 3, requestFormat = "JSON" },
                ["SYNO.Core.Certificate"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 1, requestFormat = "JSON" },
                ["SYNO.Core.Certificate.CRT"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 1, requestFormat = "JSON" }
            });
            if (api == "SYNO.API.Auth") return DsmResponse(method == "login" ? new { sid = "fake-session", synotoken = "fake-token" } : new object());
            if (api == "SYNO.Core.System") return DsmResponse(new { firmware_ver = "DSM 7.2.2-72806" });
            if (api == "SYNO.Core.Certificate.CRT" && method == "list")
            {
                var certificates = new List<object>();
                if (Id.Length > 0) certificates.Add(new { id = Id, desc = Description, is_default = IsDefault,
                    services = Array.Empty<object>(), subject = new { common_name = "one.example.test" }, subject_alt_name = new[] { "one.example.test" } });
                return DsmResponse(new { certificates });
            }
            if (api == "SYNO.Core.Certificate" && method == "import")
            {
                var form = Assert.IsType<MultipartFormDataContent>(request.Content);
                var parts = new Dictionary<string, string>();
                foreach (var part in form) parts[part.Headers.ContentDisposition!.Name!.Trim('"')] = await part.ReadAsStringAsync(ct);
                Id = parts["id"].Length > 0 ? parts["id"] : "new-cert";
                Description = parts["desc"]; CertificatePem = parts["cert"]; ChainPem = parts["inter_cert"];
                IsDefault = parts.GetValueOrDefault("as_default") == "true"; Uploads++;
                if (LoseUploadResponse) throw new HttpRequestException("DSM response lost after commit");
                return DsmResponse(new { id = Id });
            }
            if (api == "SYNO.Core.Certificate" && method == "export")
            {
                Assert.Equal(Id, JsonSerializer.Deserialize<string>(fields["id"]));
                using var stream = new MemoryStream();
                using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, true))
                {
                    Write(zip, "cert.pem", CertificatePem);
                    if (ChainPem.Length > 0) Write(zip, "chain.pem", ChainPem);
                }
                return new(HttpStatusCode.OK) { Content = new ByteArrayContent(stream.ToArray()) };
            }
            throw new InvalidOperationException($"Unexpected DSM test API: {api}/{method}");
        }
        private static Dictionary<string, string> Query(string text) => text.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(pair => pair.Split('=', 2)).ToDictionary(pair => Decode(pair[0]), pair => pair.Length > 1 ? Decode(pair[1]) : "");
        private static string Decode(string text) => Uri.UnescapeDataString(text.Replace('+', ' '));
        private static HttpResponseMessage SafeLineResponse(object data) => new(HttpStatusCode.OK) { Content = JsonContent.Create(new { data, err = (string?)null, msg = "" }) };
        private static HttpResponseMessage DsmResponse(object data) => new(HttpStatusCode.OK) { Content = JsonContent.Create(new { success = true, data }) };
        private static void Write(ZipArchive zip, string name, string content)
        {
            using var writer = new StreamWriter(zip.CreateEntry(name).Open(), new UTF8Encoding(false)); writer.Write(content);
        }
    }
}
