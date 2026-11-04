using System.IO.Compression;
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

/// <summary>协议假目标验证群晖的证书新增、原位替换与结果核对，不访问真实 NAS。</summary>
public sealed class SynologyDeploymentTests
{
    [Fact]
    public async Task ConnectionAndDiscoveryDoNotImportOrChangeServiceAssignments()
    {
        using var fixture = new Fixture();
        fixture.UseExisting(fixture.OldMaterial);
        var tested = await fixture.Executor.TestAsync(fixture.Target, default);
        Assert.True(tested.Success, tested.Message);
        var discovered = await fixture.Executor.DiscoverAsync(fixture.Target, default);
        Assert.True(discovered.Success, discovered.Message);
        var certificate = Assert.Single(discovered.Data!.Certificates);
        Assert.Equal("existing-cert", certificate.Id);
        Assert.Equal("Existing certificate", certificate.Name);
        Assert.NotEmpty(certificate.RelatedSiteIds!);
        Assert.Equal(0, fixture.Handler.CertificateWrites);
        Assert.Equal(0, fixture.Handler.ServiceWrites);
        Assert.True(fixture.Handler.Logouts >= 2);
    }

    [Fact]
    public async Task NewCertificateIsImportedOnceAndPublicMaterialIsReadBack()
    {
        using var fixture = new Fixture();
        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        Assert.Equal("Create", plan.Data!.Action);
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data), default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("new-cert", result.Data!.RemoteResourceId);
        Assert.Equal("PlatformReadback", result.Data.VerificationLevel);
        Assert.Equal(fixture.Material.Metadata.Fingerprint, result.Data.Fingerprint);
        Assert.Equal(fixture.Material.CertificatePem, fixture.Handler.CertificatePem);
        Assert.Equal(fixture.Material.ChainPem, fixture.Handler.ChainPem);
        Assert.Equal(fixture.Material.PrivateKeyPem, fixture.Handler.UploadedKey);
        Assert.Equal(1, fixture.Handler.CertificateWrites);
        Assert.True(fixture.Handler.Exports > 0);
        Assert.False(fixture.Handler.IsDefault);
        Assert.Equal(0, fixture.Handler.ServiceWrites);
        Assert.False(fixture.Executor.Descriptor.SupportsRollback);
        Assert.False((object)fixture.Executor is IRollbackDeploymentExecutor);

        var inspection = await fixture.Executor.InspectAsync(new(fixture.Target, plan.Data,
            fixture.Material.Metadata, result.Data.ReceiptJson), default);
        Assert.True(inspection.Success, inspection.Message);
        Assert.True(inspection.Data!.MatchesExpected);
    }

    [Fact]
    public async Task SelectedCertificateIsReplacedWithoutChangingDefaultOrServices()
    {
        using var fixture = new Fixture();
        fixture.UseExisting(fixture.OldMaterial);
        fixture.Handler.IsDefault = true;
        var servicesBefore = fixture.Handler.Services.ToArray();
        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        Assert.Equal("Update", plan.Data!.Action);
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data), default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("existing-cert", result.Data!.RemoteResourceId);
        Assert.Equal("existing-cert", fixture.Handler.LastImportId);
        Assert.Equal("Existing certificate", fixture.Handler.LastImportDescription);
        Assert.True(fixture.Handler.LastImportAsDefault);
        Assert.Equal(servicesBefore, fixture.Handler.Services);
        Assert.Equal(0, fixture.Handler.ServiceWrites);
        Assert.Equal(1, fixture.Handler.CertificateWrites);
    }

    [Fact]
    public async Task IdenticalLeafAndChainAreSkippedAfterVerification()
    {
        using var fixture = new Fixture();
        fixture.UseExisting(fixture.Material);
        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        Assert.Equal("Skip", plan.Data!.Action);
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data), default);
        Assert.True(result.Success, result.Message);
        Assert.True(result.Data!.Skipped);
        Assert.Equal(0, fixture.Handler.CertificateWrites);
    }

    [Theory]
    [InlineData("Create")]
    [InlineData("Update")]
    [InlineData("Skip")]
    public async Task BusinessTlsFailureIsOnlyInformationalAfterSuccessfulPlatformReadback(string action)
    {
        using var fixture = new Fixture();
        if (action != "Create")
            fixture.UseExisting(action == "Skip" ? fixture.Material : fixture.OldMaterial);
        // 保留一个未监听的本地端口，稳定模拟尚未分配证书或不可访问的业务 HTTPS 服务。
        using var verificationSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        verificationSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        fixture.Target.Configuration.VerificationHost = "127.0.0.1";
        fixture.Target.Configuration.VerificationPort = ((IPEndPoint)verificationSocket.LocalEndPoint!).Port;
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
        Assert.Equal(fixture.Material.Metadata.Fingerprint, result.Data.Fingerprint);
        Assert.Equal(action == "Skip", result.Data.Skipped);
        Assert.Contains("HTTPS", result.Data.Message);
        Assert.Contains("未通过", result.Data.Message);
        Assert.Equal(action == "Skip" ? 0 : 1, fixture.Handler.CertificateWrites);
        Assert.Equal(0, fixture.Handler.ServiceWrites);

        // 手动核对也依据平台材料读回判定，不能因同一业务 HTTPS 检查失败改回不一致。
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
    public async Task WorkerReplanPreservesPreviewForACertificateWithAssignedServices()
    {
        using var fixture = new Fixture();
        fixture.UseExisting(fixture.OldMaterial);
        var preview = await fixture.Plan();
        Assert.True(preview.Success, preview.Message);
        var plan = preview.Data!;
        // 后台队列把预览中的资源和 SiteIds 交回执行器，保留服务不能变成重新绑定请求。
        var replanned = await fixture.Executor.PlanAsync(fixture.Target, fixture.Material.Metadata,
            new(fixture.Target.Id, plan.RemoteResourceId, plan.SiteIds) { UseConfiguredRemoteCertificateId = false }, default);
        Assert.True(replanned.Success, replanned.Message);
        Assert.Equal(plan.PreconditionsJson, replanned.Data!.PreconditionsJson);
        Assert.Equal(plan.Action, replanned.Data.Action);
        Assert.Equal(0, fixture.Handler.CertificateWrites);
    }

    [Fact]
    public async Task SameLeafWithDifferentChainStillRequiresAnUpdate()
    {
        using var fixture = new Fixture();
        fixture.UseExisting(fixture.Material);
        fixture.Handler.ChainPem = "";
        Assert.NotEmpty(fixture.Material.ChainPem);
        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        Assert.Equal("Update", plan.Data!.Action);
    }

    [Theory]
    [InlineData("services")]
    [InlineData("default")]
    [InlineData("certificate")]
    [InlineData("description")]
    [InlineData("deleted")]
    public async Task RemoteChangesAfterPreviewPreventImport(string changedField)
    {
        using var fixture = new Fixture();
        fixture.UseExisting(fixture.OldMaterial);
        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        switch (changedField)
        {
            case "services": fixture.Handler.Services.Add(FakeDsm.Service("Mail", "mail", "MailServer")); break;
            case "default": fixture.Handler.IsDefault = !fixture.Handler.IsDefault; break;
            case "certificate": fixture.Handler.CertificatePem = fixture.Material.CertificatePem; break;
            case "description": fixture.Handler.Description = "Changed by another administrator"; break;
            case "deleted": fixture.Handler.Id = ""; break;
        }
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data!), default);
        Assert.False(result.Success);
        Assert.Equal("PLAN_STALE", result.Code);
        Assert.Equal(0, fixture.Handler.CertificateWrites);
    }

    [Theory]
    [InlineData("", "")]
    [InlineData("deleted-cert", "")]
    [InlineData("", "deleted-selection")]
    public async Task MissingCertificateCreatesAndSubsequentDeploymentFindsIt(string configuredId, string selectedId)
    {
        using var fixture = new Fixture();
        fixture.Target.Configuration.RemoteCertificateId = configuredId;
        var preview = await fixture.Plan(selectedId);
        Assert.True(preview.Success, preview.Message);
        var plan = preview.Data!;
        Assert.Equal("Create", plan.Action);
        Assert.Empty(plan.RemoteResourceId);

        // 队列只复核预览已解析的 ID，新增的空 ID 不能回退到配置值。
        var replanned = await fixture.Executor.PlanAsync(fixture.Target, fixture.Material.Metadata,
            new(fixture.Target.Id, plan.RemoteResourceId, plan.SiteIds) { UseConfiguredRemoteCertificateId = false }, default);
        Assert.True(replanned.Success, replanned.Message);
        Assert.Equal(plan.Action, replanned.Data!.Action);
        Assert.Equal(plan.ResourceKey, replanned.Data.ResourceKey);
        Assert.Equal(plan.PreconditionsJson, replanned.Data.PreconditionsJson);

        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan), default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("new-cert", result.Data!.RemoteResourceId);
        Assert.Empty(fixture.Handler.LastImportId);
        Assert.Equal(fixture.Material.Metadata.Domain, fixture.Handler.LastImportDescription);
        Assert.Equal(configuredId, fixture.Target.Configuration.RemoteCertificateId);

        // 不依赖回写配置 ID，下一次部署通过精确描述找回刚新增的证书，避免重复新增。
        var subsequent = await fixture.Plan(selectedId);
        Assert.True(subsequent.Success, subsequent.Message);
        Assert.Equal("Skip", subsequent.Data!.Action);
        Assert.Equal("new-cert", subsequent.Data.RemoteResourceId);
        var skipped = await fixture.Executor.ExecuteAsync(fixture.Execution(subsequent.Data), default);
        Assert.True(skipped.Success, skipped.Message);
        Assert.True(skipped.Data!.Skipped);
        Assert.Equal(1, fixture.Handler.CertificateWrites);
        Assert.Equal(0, fixture.Handler.ServiceWrites);
    }

    [Fact]
    public async Task WorkerReplanDoesNotReplaceAMissingExplicitSelectionWithAnExistingConfiguredCertificate()
    {
        using var fixture = new Fixture();
        fixture.Target.Configuration.RemoteCertificateId = "configured-cert";
        fixture.Handler.AdditionalCertificates.Add(FakeDsm.Certificate("configured-cert", "Configured certificate"));
        var preview = await fixture.Plan("deleted-selection");
        Assert.True(preview.Success, preview.Message);
        var plan = preview.Data!;
        Assert.Equal("Create", plan.Action);
        Assert.Empty(plan.RemoteResourceId);

        // 显式选择已删除时预览决定新增；后台不能擅自改成更新仍存在的配置证书。
        var replanned = await fixture.Executor.PlanAsync(fixture.Target, fixture.Material.Metadata,
            new(fixture.Target.Id, plan.RemoteResourceId, plan.SiteIds) { UseConfiguredRemoteCertificateId = false }, default);
        Assert.True(replanned.Success, replanned.Message);
        Assert.Equal(plan.Action, replanned.Data!.Action);
        Assert.Equal(plan.RemoteResourceId, replanned.Data.RemoteResourceId);
        Assert.Equal(plan.ResourceKey, replanned.Data.ResourceKey);
        Assert.Equal(plan.PreconditionsJson, replanned.Data.PreconditionsJson);
        Assert.Equal("configured-cert", fixture.Target.Configuration.RemoteCertificateId);
        Assert.Equal(0, fixture.Handler.Exports);
        Assert.Equal(0, fixture.Handler.CertificateWrites);
    }

    [Fact]
    public async Task CreatingForADeletedCertificatePreservesOtherCertificatesDefaultAndServices()
    {
        using var fixture = new Fixture();
        fixture.Target.Configuration.RemoteCertificateId = "deleted-cert";
        var existingServices = Enumerable.Range(1, 6)
            .Select(index => FakeDsm.Service($"Existing service {index}", $"service-{index}", "system")).ToArray();
        fixture.Handler.AdditionalCertificates.Add(FakeDsm.Certificate("default-cert", "Existing DSM default", true, existingServices));
        fixture.Handler.AdditionalCertificates.Add(FakeDsm.Certificate("other-cert-1", "Other certificate 1"));
        fixture.Handler.AdditionalCertificates.Add(FakeDsm.Certificate("other-cert-2", "Other certificate 2"));
        var existingBefore = JsonSerializer.Serialize(fixture.Handler.AdditionalCertificates);

        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        Assert.Equal("Create", plan.Data!.Action);
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data), default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("new-cert", result.Data!.RemoteResourceId);
        Assert.Equal("PlatformReadback", result.Data.VerificationLevel);
        Assert.Empty(fixture.Handler.LastImportId);
        Assert.False(fixture.Handler.IsDefault);
        Assert.Empty(fixture.Handler.Services);
        // 新增证书不能接管删除前转移到其他证书上的默认状态或服务。
        Assert.Equal(existingBefore, JsonSerializer.Serialize(fixture.Handler.AdditionalCertificates));
        Assert.Equal(1, fixture.Handler.CertificateWrites);
        Assert.Equal(0, fixture.Handler.ServiceWrites);
        var discovered = await fixture.Executor.DiscoverAsync(fixture.Target, default);
        Assert.True(discovered.Success, discovered.Message);
        Assert.Equal(4, discovered.Data!.Certificates.Count);
        Assert.Equal(6, discovered.Data.Sites.Count);
        Assert.All(discovered.Data.Sites, service => Assert.Equal("default-cert", service.CertificateId));
    }

    [Theory]
    [InlineData("")]
    [InlineData("deleted-cert")]
    public async Task MissingCertificateIdUpdatesTheUniqueDescriptionMatchAndPreservesAssociations(string configuredId)
    {
        using var fixture = new Fixture();
        fixture.UseExisting(fixture.OldMaterial);
        fixture.Target.Configuration.RemoteCertificateId = configuredId;
        fixture.Target.Configuration.CertificateDescription = fixture.Handler.Description;
        fixture.Handler.IsDefault = true;
        var servicesBefore = fixture.Handler.Services.ToArray();
        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        Assert.Equal("Update", plan.Data!.Action);
        Assert.Equal("existing-cert", plan.Data.RemoteResourceId);

        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data), default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("existing-cert", fixture.Handler.LastImportId);
        Assert.Equal("Existing certificate", fixture.Handler.LastImportDescription);
        Assert.True(fixture.Handler.LastImportAsDefault);
        Assert.Equal(servicesBefore, fixture.Handler.Services);
        Assert.Equal(1, fixture.Handler.CertificateWrites);
        Assert.Equal(0, fixture.Handler.ServiceWrites);
    }

    [Theory]
    [InlineData("")]
    [InlineData("deleted-cert")]
    public async Task MultipleDescriptionMatchesRequireAnExplicitCertificateId(string configuredId)
    {
        using var fixture = new Fixture();
        fixture.UseExisting(fixture.OldMaterial);
        fixture.Target.Configuration.RemoteCertificateId = configuredId;
        fixture.Target.Configuration.CertificateDescription = fixture.Handler.Description;
        fixture.Handler.AdditionalCertificates.Add(FakeDsm.Certificate("other-cert", fixture.Handler.Description));
        var plan = await fixture.Plan();
        Assert.False(plan.Success);
        Assert.Equal("RESOURCE_AMBIGUOUS", plan.Code);
        Assert.Equal(0, fixture.Handler.Exports);
        Assert.Equal(0, fixture.Handler.CertificateWrites);
    }

    [Theory]
    [InlineData("Existing certificate")]
    [InlineData("Other certificate")]
    public async Task ExistingCertificateIdTakesPrecedenceOverDescriptionFallback(string description)
    {
        using var fixture = new Fixture();
        fixture.UseExisting(fixture.OldMaterial);
        fixture.Target.Configuration.CertificateDescription = description;
        fixture.Handler.AdditionalCertificates.Add(FakeDsm.Certificate("other-cert", description));
        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        Assert.Equal("Update", plan.Data!.Action);
        Assert.Equal("existing-cert", plan.Data.RemoteResourceId);
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data), default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("existing-cert", fixture.Handler.LastImportId);
        Assert.Equal("Existing certificate", fixture.Handler.LastImportDescription);
    }

    [Theory]
    [InlineData("existing certificate")]
    [InlineData("Existing")]
    public async Task DescriptionFallbackRequiresAnExactOrdinalMatch(string description)
    {
        using var fixture = new Fixture();
        fixture.UseExisting(fixture.OldMaterial);
        fixture.Target.Configuration.RemoteCertificateId = "deleted-cert";
        fixture.Target.Configuration.CertificateDescription = description;
        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        Assert.Equal("Create", plan.Data!.Action);
        Assert.Empty(plan.Data.RemoteResourceId);
        Assert.Equal(0, fixture.Handler.Exports);
        Assert.Equal(0, fixture.Handler.CertificateWrites);
    }

    [Fact]
    public async Task LostImportResponseIsUnknownAndNeverAutomaticallyRetried()
    {
        using var fixture = new Fixture();
        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        fixture.Handler.LoseImportResponse = true;
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data!), default);
        Assert.False(result.Success);
        Assert.Equal("REMOTE_RESULT_UNKNOWN", result.Code);
        Assert.Equal(1, fixture.Handler.CertificateWrites);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FailedOrMismatchedReadbackCannotReportSuccessfulDeployment(bool mismatch)
    {
        using var fixture = new Fixture();
        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        if (mismatch) fixture.Handler.ReadbackReplacement = fixture.OldMaterial.CertificatePem;
        else fixture.Handler.FailExportAfterImport = true;
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data!), default);
        Assert.False(result.Success);
        Assert.Equal("REMOTE_RESULT_UNKNOWN", result.Code);
        Assert.Equal(1, fixture.Handler.CertificateWrites);
    }

    [Fact]
    public async Task ImportThatChangesExistingServiceAssignmentsIsNotConsideredSuccessful()
    {
        using var fixture = new Fixture();
        fixture.UseExisting(fixture.OldMaterial);
        var plan = await fixture.Plan();
        Assert.True(plan.Success, plan.Message);
        fixture.Handler.RemoveServicesAfterImport = true;
        var result = await fixture.Executor.ExecuteAsync(fixture.Execution(plan.Data!), default);
        Assert.False(result.Success);
        Assert.Equal("REMOTE_RESULT_UNKNOWN", result.Code);
        Assert.Equal(1, fixture.Handler.CertificateWrites);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly RSA caKey = RSA.Create(2048);
        private readonly RSA key = RSA.Create(2048);
        private readonly RSA oldKey = RSA.Create(2048);
        private readonly X509Certificate2 ca;
        private readonly X509Certificate2 certificate;
        private readonly X509Certificate2 oldCertificate;
        public FakeDsm Handler { get; } = new();
        public SynologyDsm7DeploymentExecutor Executor { get; }
        public CertificateMaterial Material { get; }
        public CertificateMaterial OldMaterial { get; }
        public DeploymentTargetContext Target { get; } = new()
        {
            Id = "target", Name = "Test DSM", Endpoint = "https://dsm.example.test:5001", Port = 5001,
            ExecutorKey = "synology.dsm.7.x", Username = "deployment-user", AuthenticationMode = "Password",
            Credentials = new() { Password = "fake-password" }
        };

        public Fixture()
        {
            var caRequest = new CertificateRequest("CN=Test CA", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            ca = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(90));
            var request = Request(key);
            certificate = request.Create(ca, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), RandomNumberGenerator.GetBytes(16));
            oldCertificate = Request(oldKey).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(10));
            var material = CertificateMaterialHelper.FromPem([certificate.ExportCertificatePem(), ca.ExportCertificatePem()],
                [key.ExportPkcs8PrivateKeyPem()], "certificate", "nas.example.test");
            Assert.True(material.Success, material.Message);
            Material = material.Data!;
            OldMaterial = CertificateMaterialHelper.FromPem([oldCertificate.ExportCertificatePem()],
                [oldKey.ExportPkcs8PrivateKeyPem()], "old-certificate", "nas.example.test").Data!;
            Executor = new(new SynologyDsmApiClient(_ => new HttpClient(Handler, disposeHandler: false)));
        }

        private static CertificateRequest Request(RSA key)
        {
            var request = new CertificateRequest("CN=nas.example.test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var sans = new SubjectAlternativeNameBuilder();
            sans.AddDnsName("nas.example.test");
            request.CertificateExtensions.Add(sans.Build());
            return request;
        }

        public void UseExisting(CertificateMaterial material)
        {
            Handler.Id = "existing-cert";
            Handler.Description = "Existing certificate";
            Handler.CertificatePem = material.CertificatePem;
            Handler.ChainPem = material.ChainPem;
            Handler.Services.Add(FakeDsm.Service("DSM Desktop Service", "default", "system"));
            Target.Configuration.RemoteCertificateId = Handler.Id;
        }

        public Task<ApiResult<DeploymentTargetPlan>> Plan(string remoteCertificateId = "") =>
            Executor.PlanAsync(Target, Material.Metadata, new("target", remoteCertificateId), default);

        public DeploymentExecutionContext Execution(DeploymentTargetPlan plan) => new()
        {
            TaskId = "task", Target = Target, Material = Material, Plan = plan,
            ReportProgressAsync = (_, _, _) => Task.CompletedTask
        };

        public void Dispose()
        {
            ca.Dispose(); certificate.Dispose(); oldCertificate.Dispose();
            caKey.Dispose(); key.Dispose(); oldKey.Dispose(); Handler.Dispose();
        }
    }

    /// <summary>按 DSM API 契约模拟远端状态，确保实际上传和读回都参与验证。</summary>
    private sealed class FakeDsm : HttpMessageHandler
    {
        public string Id { get; set; } = "";
        public string Description { get; set; } = "";
        public string CertificatePem { get; set; } = "";
        public string ChainPem { get; set; } = "";
        public bool IsDefault { get; set; }
        public List<object> Services { get; } = [];
        public List<object> AdditionalCertificates { get; } = [];
        public string ReadbackReplacement { get; set; } = "";
        public bool LoseImportResponse { get; set; }
        public bool FailExportAfterImport { get; set; }
        public bool RemoveServicesAfterImport { get; set; }
        public int CertificateWrites { get; private set; }
        public int ServiceWrites { get; private set; }
        public int Exports { get; private set; }
        public int Logouts { get; private set; }
        public string LastImportId { get; private set; } = "";
        public string LastImportDescription { get; private set; } = "";
        public bool LastImportAsDefault { get; private set; }
        public string UploadedKey { get; private set; } = "";

        public static object Service(string name, string service, string subscriber) => new
        {
            display_name = name, display_name_i18n = "common:web_desktop", service, subscriber,
            owner = "root", isPkg = false, multiple_cert = true, user_setable = true
        };

        public static object Certificate(string id, string description, bool isDefault = false, object[]? services = null) => new
        {
            id, desc = description, is_default = isDefault, services = services ?? [],
            subject = new { common_name = "nas.example.test" },
            subject_alt_name = new[] { "nas.example.test" }, valid_till = "2030-01-01"
        };

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            var fields = ParseQuery(request.RequestUri!.Query);
            if (request.Content is FormUrlEncodedContent)
                foreach (var field in ParseQuery(await request.Content.ReadAsStringAsync(ct))) fields[field.Key] = field.Value;
            var api = fields.GetValueOrDefault("api", "");
            var method = fields.GetValueOrDefault("method", "");
            if (api == "SYNO.API.Info")
                return Response(new Dictionary<string, object>
                {
                    ["SYNO.API.Auth"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 7 },
                    ["SYNO.Core.System"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 3, requestFormat = "JSON" },
                    ["SYNO.Core.Certificate.CRT"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 1, requestFormat = "JSON" },
                    ["SYNO.Core.Certificate"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 1, requestFormat = "JSON" }
                });
            if (api == "SYNO.API.Auth" && method == "login")
                return Response(new { sid = "test-sid", synotoken = "test-synotoken" });
            if (api == "SYNO.API.Auth" && method == "logout")
            {
                Logouts++;
                return Response(new { });
            }
            if (api == "SYNO.Core.System" && method == "info")
            {
                // DSM 7.x API 清单声明 JSON，业务参数需 JSON 编码，不能用宽松假接口掩盖错误。
                Assert.Equal("\"firmware\"", fields["type"]);
                return Response(new { firmware_ver = "DSM 7.2.2-72806 Update 3" });
            }
            if (api == "SYNO.Core.Certificate.CRT" && method == "list")
            {
                // 附加证书只参与列表快照，验证描述歧义和更新时不影响其他资源。
                var certificates = new List<object>(AdditionalCertificates);
                if (!string.IsNullOrEmpty(Id)) certificates.Insert(0, Certificate(Id, Description, IsDefault, Services.ToArray()));
                return Response(new { certificates });
            }
            if (api == "SYNO.Core.Certificate" && method == "export")
            {
                Exports++;
                if (FailExportAfterImport && CertificateWrites > 0) throw new HttpRequestException("Fake readback unavailable");
                Assert.Equal(Id, JsonSerializer.Deserialize<string>(fields["id"]));
                Assert.Equal("\"archive\"", fields["file"]);
                using var stream = new MemoryStream();
                using (var zip = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: true))
                {
                    Write(zip, "cert.pem", CertificateWrites > 0 && ReadbackReplacement.Length > 0 ? ReadbackReplacement : CertificatePem);
                    if (ChainPem.Length > 0) Write(zip, "chain.pem", ChainPem);
                    // 故意放入非 PEM 私钥，读回只能依赖公开证书，不能读取或记录旧私钥。
                    Write(zip, "privkey.pem", "PRIVATE KEY MUST NOT BE READ");
                }
                return new(HttpStatusCode.OK) { Content = new ByteArrayContent(stream.ToArray()) };
            }
            if (api == "SYNO.Core.Certificate" && method == "import")
            {
                CertificateWrites++;
                var form = Assert.IsType<MultipartFormDataContent>(request.Content);
                var parts = new Dictionary<string, string>();
                foreach (var part in form)
                    parts[part.Headers.ContentDisposition!.Name!.Trim('"')] = await part.ReadAsStringAsync(ct);
                LastImportId = parts["id"];
                LastImportDescription = parts["desc"];
                LastImportAsDefault = parts.GetValueOrDefault("as_default") == "true";
                UploadedKey = parts["key"];
                Id = string.IsNullOrEmpty(LastImportId) ? "new-cert" : LastImportId;
                Description = LastImportDescription;
                CertificatePem = parts["cert"];
                ChainPem = parts.GetValueOrDefault("inter_cert", "");
                IsDefault = LastImportAsDefault;
                if (RemoveServicesAfterImport) Services.Clear();
                if (LoseImportResponse) throw new HttpRequestException("Fake response lost after remote commit");
                return Response(new { id = Id, restart_httpd = true });
            }
            if (api == "SYNO.Core.Certificate.Service")
            {
                ServiceWrites++;
                return new(HttpStatusCode.BadRequest);
            }
            throw new InvalidOperationException($"Unexpected fake DSM API: {api}/{method}");
        }

        private static Dictionary<string, string> ParseQuery(string value) => value.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(item => item.Split('=', 2)).ToDictionary(item => Decode(item[0]), item => item.Length > 1 ? Decode(item[1]) : "");
        private static string Decode(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));
        private static HttpResponseMessage Response(object data) => new(HttpStatusCode.OK)
        { Content = JsonContent.Create(new { success = true, data }) };
        private static void Write(ZipArchive zip, string name, string text)
        {
            using var writer = new StreamWriter(zip.CreateEntry(name).Open(), new UTF8Encoding(false));
            writer.Write(text);
        }
    }
}
