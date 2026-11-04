using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;

namespace SslManager.Tests;

/// <summary>使用协议假目标验证写入契约和并发前置条件，不连接真实 WAF。</summary>
public sealed class SafeLineDeploymentTests
{
    [Fact]
    public void LoginEncryptionMatchesTheObservedCe9Envelope()
    {
        const string key = "0123456789abcdef";
        var encoded = Convert.FromBase64String(SafeLineCe9ApiClient.EncryptPassword("test-password", key));
        using var aes = Aes.Create();
        aes.Key = Encoding.UTF8.GetBytes(key);
        var plaintext = aes.DecryptCbc(encoded.AsSpan(16), encoded.AsSpan(0, 16), PaddingMode.PKCS7);
        Assert.Equal("test-password", Encoding.UTF8.GetString(plaintext));
    }

    [Fact]
    public async Task PasswordSessionUsesEncryptedLoginAndRejectsOtherMajorVersion()
    {
        using var fixture = new Fixture();
        var read = await fixture.Executor.TestAsync(fixture.Target, default);
        Assert.True(read.Success);
        Assert.Equal("9.3.9", read.Data!.ProductVersion);
        Assert.Equal("test-password", fixture.Handler.DecryptedPassword);
        Assert.DoesNotContain("test-password", fixture.Handler.LoginBody);
        Assert.Equal(0, fixture.Handler.CertificateWrites);
        fixture.Handler.Version = "10.0.0";
        Assert.Equal("PRODUCT_VERSION_UNSUPPORTED", (await fixture.Executor.TestAsync(fixture.Target, default)).Code);
    }

    [Fact]
    public async Task NewCertificateIsCreatedOnceAndReadBackBeforeSuccess()
    {
        using var fixture = new Fixture();
        var planned = await fixture.Plan();
        Assert.True(planned.Success);
        Assert.Equal("Create", planned.Data!.Action);
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(planned.Data), default);
        Assert.True(result.Success);
        Assert.Equal("10", result.Data!.RemoteResourceId);
        Assert.Equal("PlatformReadback", result.Data.VerificationLevel);
        Assert.Equal(1, fixture.Handler.CertificateWrites);
        Assert.Equal(fixture.Material.FullChainPem, fixture.Handler.StoredCertificate);
        Assert.False((object)fixture.Executor is IRollbackDeploymentExecutor);
        Assert.False(fixture.Executor.Descriptor.SupportsRollback);
    }

    [Fact]
    public async Task ExistingSameMaterialIsSkippedAndRelatedSitesAreMappedToIds()
    {
        using var fixture = new Fixture();
        fixture.Handler.StoredCertificate = fixture.Material.FullChainPem;
        fixture.Handler.HasSite = true;
        var planned = await fixture.Plan();
        Assert.True(planned.Success);
        Assert.Equal("Skip", planned.Data!.Action);
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(planned.Data), default);
        Assert.True(result.Success);
        Assert.True(result.Data!.Skipped);
        Assert.Equal(0, fixture.Handler.CertificateWrites);
        var discovery = await fixture.Executor.DiscoverAsync(fixture.Target, default);
        Assert.Equal(new[] { "15" }, discovery.Data!.Certificates[0].RelatedSiteIds);
    }

    [Theory]
    [InlineData("Create")]
    [InlineData("Update")]
    [InlineData("Skip")]
    public async Task BusinessTlsFailureIsOnlyInformationalAfterSuccessfulPlatformReadback(string action)
    {
        using var fixture = new Fixture();
        using var previous = new Fixture();
        if (action != "Create")
        {
            fixture.Handler.StoredCertificate = action == "Skip" ? fixture.Material.FullChainPem : previous.Material.FullChainPem;
            fixture.Handler.HasSite = true;
        }
        // 接受后立即断开，模拟未提供本次证书的 HTTPS 端点，避免依赖连接超时或外部服务。
        await using var endpoint = new RejectingTlsEndpoint();
        fixture.Target.Configuration.VerificationHost = "127.0.0.1";
        fixture.Target.Configuration.VerificationPort = endpoint.Port;
        fixture.Target.Configuration.VerificationServerName = fixture.Material.Metadata.Domain;
        fixture.Target.Configuration.ConnectionTimeoutSeconds = 5;
        var tls = await DeploymentTlsVerification.VerifyAsync(fixture.Target.Configuration, fixture.Material.Metadata, default);
        Assert.False(tls.Success);
        Assert.Equal("VERIFICATION_FAILED", tls.Code);

        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        Assert.Equal(action, plan.Data!.Action);
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data), default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("PlatformReadback", result.Data!.VerificationLevel);
        Assert.Equal("10", result.Data.RemoteResourceId);
        Assert.Equal(fixture.Material.Metadata.Fingerprint, result.Data.Fingerprint);
        Assert.Equal(action == "Skip", result.Data.Skipped);
        Assert.Contains("HTTPS", result.Data.Message);
        Assert.Contains("未通过", result.Data.Message);
        Assert.Equal(action == "Skip" ? 0 : 1, fixture.Handler.CertificateWrites);

        // 手动核对与执行采用同一成功依据，HTTPS 观察失败不能推翻材料和关联已一致的结论。
        var inspection = await fixture.Executor.InspectAsync(new(fixture.Target, plan.Data,
            fixture.Material.Metadata, result.Data.ReceiptJson), default);
        Assert.True(inspection.Success, inspection.Message);
        Assert.True(inspection.Data!.MatchesExpected);
        Assert.Equal("PlatformReadback", inspection.Data.VerificationLevel);
        Assert.Equal(fixture.Material.Metadata.Fingerprint, inspection.Data.Fingerprint);
        Assert.Contains("HTTPS", inspection.Data.Message);
        Assert.Contains("未通过", inspection.Data.Message);
        Assert.Equal(action == "Skip" ? 0 : 1, fixture.Handler.CertificateWrites);
    }

    [Fact]
    public async Task DifferentReadbackAfterUploadCannotReportSuccessfulDeployment()
    {
        using var fixture = new Fixture();
        using var previous = new Fixture();
        fixture.Handler.ReadbackReplacement = previous.Material.FullChainPem;
        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data!), default);
        Assert.False(result.Success);
        Assert.Equal("REMOTE_RESULT_UNKNOWN", result.Code);
        Assert.Equal(1, fixture.Handler.CertificateWrites);
    }

    [Fact]
    public async Task UpdatingSharedResourceRequiresCoverageForEveryRelatedSite()
    {
        using var fixture = new Fixture();
        fixture.Handler.StoredCertificate = fixture.Material.FullChainPem;
        fixture.Handler.HasSite = true;
        fixture.Handler.SiteDomain = "uncovered.example.com";
        var plan = await fixture.Plan();
        Assert.Equal("DOMAIN_MISMATCH", plan.Code);
        Assert.Equal(0, fixture.Handler.CertificateWrites);
    }

    [Fact]
    public async Task SiteChangedAfterPreviewIsRejectedBeforeCertificateWrite()
    {
        using var fixture = new Fixture();
        fixture.Handler.StoredCertificate = fixture.Material.FullChainPem;
        fixture.Handler.HasSite = true;
        var planned = await fixture.Plan();
        fixture.Handler.SiteComment = "changed by another administrator";
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(planned.Data!), default);
        Assert.Equal("PLAN_STALE", result.Code);
        Assert.Equal(0, fixture.Handler.CertificateWrites);
    }

    [Fact]
    public async Task FailedMutationIsUnknownAndNeverAutomaticallyRetried()
    {
        using var fixture = new Fixture();
        var plan = await fixture.Plan();
        fixture.Handler.FailMutation = true;
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data!), default);
        Assert.Equal("REMOTE_RESULT_UNKNOWN", result.Code);
        Assert.Equal(1, fixture.Handler.CertificateWrites);
    }

    [Fact]
    public async Task NewlyAssociatedSiteInvalidatesAnExistingPlan()
    {
        using var fixture = new Fixture();
        fixture.Handler.StoredCertificate = fixture.Material.FullChainPem;
        var planned = await fixture.Plan();
        Assert.True(planned.Success);
        fixture.Handler.HasSite = true;
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(planned.Data!), default);
        Assert.Equal("PLAN_STALE", result.Code);
        Assert.Equal(0, fixture.Handler.CertificateWrites);
    }

    [Fact]
    public async Task EmptySiteScopeCannotBeAutomaticallyBound()
    {
        using var fixture = new Fixture();
        fixture.Handler.HasSite = true;
        fixture.Handler.EmptySiteDomains = true;
        fixture.Target.Configuration.BindSites = true;
        fixture.Target.Configuration.SiteIds = ["15"];
        Assert.Equal("DOMAIN_MISMATCH", (await fixture.Plan()).Code);
        Assert.Equal(0, fixture.Handler.CertificateWrites);
    }

    [Fact]
    public async Task SuccessfulHttpWithoutWriteReceiptIsStillUnknown()
    {
        using var fixture = new Fixture();
        var plan = await fixture.Plan();
        fixture.Handler.MissingMutationReceipt = true;
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data!), default);
        Assert.Equal("REMOTE_RESULT_UNKNOWN", result.Code);
        Assert.NotNull(result.Data);
        Assert.Equal(1, fixture.Handler.CertificateWrites);
    }

    [Fact]
    public async Task AcmeAndIncompleteListsCannotBeSilentlyTakenOver()
    {
        using var fixture = new Fixture();
        fixture.Handler.StoredCertificate = fixture.Material.FullChainPem;
        fixture.Handler.CertificateType = 3;
        Assert.Equal("MANAGED_CERTIFICATE", (await fixture.Plan()).Code);
        fixture.Handler.Incomplete = true;
        Assert.Equal("INCOMPLETE_RESPONSE", (await fixture.Plan()).Code);
    }

    /// <summary>真实 TCP 握手后主动断开，使 HTTPS 检查快速失败而不依赖端口占用竞态。</summary>
    private sealed class RejectingTlsEndpoint : IAsyncDisposable
    {
        private readonly TcpListener listener = new(IPAddress.Loopback, 0);
        private readonly CancellationTokenSource stopping = new();
        private readonly Task rejecting;
        public int Port => ((IPEndPoint)listener.LocalEndpoint).Port;

        public RejectingTlsEndpoint()
        {
            listener.Start();
            rejecting = RejectConnectionsAsync();
        }

        private async Task RejectConnectionsAsync()
        {
            try
            {
                while (true)
                {
                    using var client = await listener.AcceptTcpClientAsync(stopping.Token);
                }
            }
            catch (OperationCanceledException) when (stopping.IsCancellationRequested) { }
            catch (SocketException) when (stopping.IsCancellationRequested) { }
            catch (ObjectDisposedException) when (stopping.IsCancellationRequested) { }
        }

        public async ValueTask DisposeAsync()
        {
            stopping.Cancel();
            listener.Stop();
            await rejecting;
            stopping.Dispose();
        }
    }

    private sealed class Fixture : IDisposable
    {
        private readonly RSA key = RSA.Create(2048);
        private readonly X509Certificate2 certificate;
        public FakeSafeLine Handler { get; } = new();
        public SafeLineCe9DeploymentExecutor Executor { get; }
        public CertificateMaterial Material { get; }
        public DeploymentTargetContext Target { get; } = new()
        {
            Id = "target", Endpoint = "https://safeline.test:9443/system", Port = 9443,
            ExecutorKey = "safeline.ce.9.x", Username = "admin", AuthenticationMode = "Password",
            Credentials = new() { Password = "test-password" }
        };
        public Fixture()
        {
            var request = new CertificateRequest("CN=one.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var sans = new SubjectAlternativeNameBuilder();
            sans.AddDnsName("one.example.com");
            request.CertificateExtensions.Add(sans.Build());
            certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
            Material = CertificateMaterialHelper.FromPem([certificate.ExportCertificatePem()], [key.ExportPkcs8PrivateKeyPem()],
                "certificate", "one.example.com").Data!;
            Executor = new(new SafeLineCe9ApiClient(_ => new HttpClient(Handler, disposeHandler: false)));
        }
        public Task<ApiResult<DeploymentTargetPlan>> Plan() =>
            Executor.PlanAsync(Target, Material.Metadata, new("target"), default);
        public DeploymentExecutionContext Execution(DeploymentTargetPlan plan) => new()
        {
            TaskId = "task", Target = Target, Material = Material, Plan = plan,
            ReportProgressAsync = (_, _, _) => Task.CompletedTask
        };
        public void Dispose() { certificate.Dispose(); key.Dispose(); Handler.Dispose(); }
    }

    private sealed class FakeSafeLine : HttpMessageHandler
    {
        public string Version { get; set; } = "9.3.9";
        public string StoredCertificate { get; set; } = "";
        public string ReadbackReplacement { get; set; } = "";
        public int CertificateType { get; set; } = 2;
        public bool HasSite { get; set; }
        public bool EmptySiteDomains { get; set; }
        public bool MissingMutationReceipt { get; set; }
        public string SiteDomain { get; set; } = "one.example.com";
        public string SiteComment { get; set; } = "";
        public bool FailMutation { get; set; }
        public bool Incomplete { get; set; }
        public int CertificateWrites { get; private set; }
        public string DecryptedPassword { get; private set; } = "";
        public string LoginBody { get; private set; } = "";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var path = request.RequestUri!.AbsolutePath;
            if (path.EndsWith("/system/key")) return Response("0123456789abcdef");
            if (path.EndsWith("/auth/csrf")) return Response(new { csrf_token = "test-csrf" });
            if (path.EndsWith("/auth/login"))
            {
                LoginBody = await request.Content!.ReadAsStringAsync(ct);
                using var login = JsonDocument.Parse(LoginBody);
                var encrypted = Convert.FromBase64String(login.RootElement.GetProperty("password").GetString()!);
                using var aes = Aes.Create();
                aes.Key = Encoding.UTF8.GetBytes("0123456789abcdef");
                DecryptedPassword = Encoding.UTF8.GetString(aes.DecryptCbc(encrypted.AsSpan(16), encrypted.AsSpan(0, 16), PaddingMode.PKCS7));
                return Response(new { jwt = "test-session", tfa_enabled = false });
            }
            if (path.EndsWith("/system")) return Response(new { version = Version });
            if (path.EndsWith("/cert") && request.Method == HttpMethod.Post)
            {
                CertificateWrites++;
                if (FailMutation) throw new HttpRequestException("Response lost after commit");
                using var body = JsonDocument.Parse(await request.Content!.ReadAsStringAsync(ct));
                StoredCertificate = body.RootElement.GetProperty("manual").GetProperty("crt").GetString()!;
                if (MissingMutationReceipt) return new(HttpStatusCode.OK) { Content = JsonContent.Create(new { msg = "" }) };
                return Response(new { id = 10 });
            }
            if (path.EndsWith("/cert"))
                return Response(new
                {
                    nodes = string.IsNullOrEmpty(StoredCertificate) ? [] : new[] { new { id = 10, type = CertificateType,
                        domains = new[] { "one.example.com" }, related_sites = HasSite ? new[] { "one.example.com" } : [] } },
                    total = Incomplete ? 999 : string.IsNullOrEmpty(StoredCertificate) ? 0 : 1
                });
            if (path.EndsWith("/cert/10")) return Response(new { type = 2, manual = new
            {
                crt = CertificateWrites > 0 && !string.IsNullOrEmpty(ReadbackReplacement) ? ReadbackReplacement : StoredCertificate
            } });
            if (path.EndsWith("/site"))
                return Response(new { data = HasSite ? new[] { new { id = 15, server_names = EmptySiteDomains ? [] : new[] { SiteDomain }, cert_id = 10 } } : [], total = HasSite ? 1 : 0 });
            if (path.EndsWith("/site/15"))
                return Response(new { cert_id = 10, server_names = new[] { SiteDomain }, comment = SiteComment, ports = new[] { "443_ssl" }, upstreams = new[] { "127.0.0.1:80" } });
            throw new InvalidOperationException("Unexpected fake request: " + path);
        }
        private static HttpResponseMessage Response(object? data) => new(HttpStatusCode.OK)
        { Content = JsonContent.Create(new { data, err = (string?)null, msg = "" }) };
    }
}
