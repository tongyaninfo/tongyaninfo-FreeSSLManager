using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;
using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Tests;

/// <summary>用合成适配器验证通用 Worker 的 ACME 恢复和写入门禁，不创建真实 CA 订单或 DNS 记录。</summary>
public sealed class AcmeWorkerIntegrationTests
{
    [Fact]
    public async Task SyncMergesPersistedOrderIntoOriginalIntentBeforeWorkerRestoresIt()
    {
        await using var fixture = await Fixture.CreateAsync(hasOrder: true);
        fixture.Provider.ListCertificates = [new(new(OrderId: Fixture.OrderUrl, ApiVersion: "AcmeV2"), "app.example.com", "",
            "PendingValidation", "pending", true, "LetsEncrypt", null, null, "ManualDns", "", false, true)];
        var synced = await fixture.Service.SyncAsync("acme-account", default);
        Assert.True(synced.Success, synced.Message);
        var original = Assert.Single(await fixture.Db.Certificates.ToListAsync());
        Assert.Equal("local", original.Id);
        Assert.Equal(Fixture.OrderUrl, original.OrderId);
        Assert.Equal("AcmeV2", original.ApiVersion);
        // 先同步再恢复仍是同一证书，不会撞订单唯一索引或创建第二个本地身份。
        await fixture.Service.ProcessJobAsync("job", default);
        Assert.Equal("local", Assert.Single(await fixture.Db.Certificates.ToListAsync()).Id);
        Assert.Equal(0, fixture.Provider.ApplyCalls);
        Assert.Single(fixture.Provider.ContinuedReferences);
    }

    [Fact]
    public async Task ApplicationFailureAfterOrderReceiptPreservesReferenceAndQueuesOriginalOrder()
    {
        await using var fixture = await Fixture.CreateAsync(hasOrder: false, seedIntent: false);
        fixture.Provider.Application = async (account, request, ct) =>
        {
            fixture.Db.CertificateIssuanceStates.Add(new() { Id = request.LocalCertificateId, AccountId = account.Id, Provider = "Acme",
                Domain = request.Domain, OrderUrl = Fixture.OrderUrl, Stage = "PendingValidation", ProtectedPayload = "synthetic-original-key" });
            await fixture.Db.SaveChangesAsync(ct);
            return ApiResult<CloudCertificateDetail>.Fail("ACME_CONNECTION_FAILED", "模拟订单已受理后的查询失败。");
        };
        var applied = await fixture.Service.ApplyAsync(new("acme-account", "app.example.com", ValidationMode: "ManualDns", AutoCleanup: false), default);
        Assert.True(applied.Success, applied.Message);
        Assert.Equal(Fixture.OrderUrl, applied.Data!.OrderId);
        Assert.Equal("AcmeV2", applied.Data.ApiVersion);
        Assert.Equal("Processing", applied.Data.Status);
        var job = Assert.Single(await fixture.Db.CertificateJobs.ToListAsync());
        Assert.Equal("Waiting", job.Status);
        await fixture.Service.ProcessJobAsync(job.Id, default);
        Assert.Equal(1, fixture.Provider.ApplyCalls);
        Assert.Equal(Fixture.OrderUrl, Assert.Single(fixture.Provider.QueriedReferences).OrderId);
        Assert.Equal(Fixture.OrderUrl, Assert.Single(fixture.Provider.ContinuedReferences).OrderId);
        var repeated = await fixture.Service.ApplyAsync(new("acme-account", "app.example.com", ValidationMode: "ManualDns", AutoCleanup: false), default);
        Assert.Equal("APPLICATION_IN_PROGRESS", repeated.Code);
        Assert.Equal(1, fixture.Provider.ApplyCalls);
        Assert.Single(await fixture.Db.Certificates.ToListAsync());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task WebIntentCapturesConfiguredDirectoryBeforeAnyCaResponse(bool staging)
    {
        var directory = staging ? AcmeProtocolClient.StagingDirectory : AcmeProtocolClient.ProductionDirectory;
        await using var fixture = await Fixture.CreateAsync(hasOrder: false, directory: directory, seedIntent: false);
        fixture.Provider.Application = async (_, request, ct) =>
        {
            var intent = await fixture.Db.Certificates.AsNoTracking().SingleAsync(x => x.Id == request.LocalCertificateId, ct);
            Assert.Equal(staging, intent.IsStaging);
            Assert.False(intent.HasPrivateKey);
            return ApiResult<CloudCertificateDetail>.Fail("ACME_REJECTED", "模拟未产生订单的 CA 明确拒绝。");
        };
        var result = await fixture.Service.ApplyAsync(new("acme-account", "app.example.com", ValidationMode: "ManualDns"), default);
        Assert.False(result.Success);
        var persisted = Assert.Single(await fixture.Db.Certificates.ToListAsync());
        Assert.Equal(staging, persisted.IsStaging);
        Assert.Equal("Failed", persisted.Status);
        Assert.False(persisted.CanDeploy);
        Assert.Equal(1, fixture.Provider.ApplyCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task McpQueuedIntentCapturesConfiguredDirectoryWithoutCallingCa(bool staging)
    {
        var directory = staging ? AcmeProtocolClient.StagingDirectory : AcmeProtocolClient.ProductionDirectory;
        await using var fixture = await Fixture.CreateAsync(hasOrder: false, directory: directory, seedIntent: false);
        var operations = new McpOperationService(fixture.Db, new PreauthorizedAuthorization(), fixture.Service, null!, null!, new GuidIdGenerator());
        var caller = new McpCallerContext("client", "actor", "authorization", ["ssl.write", "ssl.read"], "192.0.2.10", "admin");
        var prepared = await operations.PrepareApplicationAsync(caller,
            new("acme-account", "app.example.com", ValidationMode: "ManualDns"), "directory-intent", default);
        Assert.True(prepared.Success, prepared.Message);
        var submitted = await operations.SubmitAsync(caller, prepared.Data!.Id, "directory-intent", default);
        Assert.True(submitted.Success, submitted.Message);
        var persisted = Assert.Single(await fixture.Db.Certificates.ToListAsync());
        Assert.Equal(staging, persisted.IsStaging);
        Assert.False(persisted.HasPrivateKey);
        Assert.Equal("McpQueued", Assert.Single(await fixture.Db.CertificateJobs.ToListAsync()).Status);
        Assert.Equal(0, fixture.Provider.ApplyCalls);
        Assert.Empty(await fixture.Db.CertificateIssuanceStates.ToListAsync());
    }

    [Fact]
    public async Task PersistedOrderReceiptRestoresSubmittingJobWithoutAnotherApplication()
    {
        await using var fixture = await Fixture.CreateAsync(hasOrder: true);
        await fixture.Service.ProcessJobAsync("job", default);
        var certificate = await fixture.Db.Certificates.SingleAsync();
        var job = await fixture.Db.CertificateJobs.SingleAsync();
        Assert.Equal(Fixture.OrderUrl, certificate.OrderId);
        Assert.Equal("AcmeV2", certificate.ApiVersion);
        Assert.Equal("Processing", certificate.Status);
        Assert.Equal("Waiting", job.Status);
        Assert.Null(job.LeaseUntilUtc);
        Assert.Equal(0, fixture.Provider.ApplyCalls);
        var queried = Assert.Single(fixture.Provider.QueriedReferences);
        var continued = Assert.Single(fixture.Provider.ContinuedReferences);
        Assert.Equal(Fixture.OrderUrl, queried.OrderId);
        Assert.Equal("AcmeV2", queried.ApiVersion);
        Assert.Equal(queried, continued);
        // 恢复任务的后续重试仍只继续同一订单，不能回到申请入口。
        await fixture.Service.ProcessJobAsync("job", default);
        Assert.Equal(0, fixture.Provider.ApplyCalls);
        Assert.Equal(2, fixture.Provider.QueriedReferences.Count);
        Assert.All(fixture.Provider.QueriedReferences, value => Assert.Equal(queried, value));
        Assert.All(fixture.Provider.ContinuedReferences, value => Assert.Equal(continued, value));
    }

    [Theory]
    [InlineData("Prepared")]
    [InlineData("OrderSubmitting")]
    public async Task SubmittingWithoutAnOrderReceiptRemainsUnknownAndNeverResubmits(string stage)
    {
        await using var fixture = await Fixture.CreateAsync(hasOrder: false);
        var state = await fixture.Db.CertificateIssuanceStates.SingleAsync();
        state.Stage = stage;
        await fixture.Db.SaveChangesAsync();
        var originalPayload = state.ProtectedPayload;
        await fixture.Service.ProcessJobAsync("job", default);
        await fixture.Service.ProcessJobAsync("job", default);
        Assert.Equal("SubmissionUnknown", (await fixture.Db.CertificateJobs.SingleAsync()).Status);
        Assert.Equal("SubmissionUnknown", (await fixture.Db.Certificates.SingleAsync()).Status);
        Assert.Equal(originalPayload, state.ProtectedPayload);
        Assert.Equal("", state.OrderUrl);
        Assert.Equal(0, fixture.Provider.ApplyCalls);
        Assert.Empty(fixture.Provider.QueriedReferences);
        Assert.Empty(fixture.Provider.ContinuedReferences);
    }

    [Fact]
    public async Task RevokedMcpPermissionAllowsReadOnlyRecoveryButPreventsCaContinuation()
    {
        var gate = new DenyingGate();
        await using var fixture = await Fixture.CreateAsync(hasOrder: true, gate);
        await fixture.Service.ProcessJobAsync("job", default);
        Assert.Single(fixture.Provider.QueriedReferences);
        Assert.Empty(fixture.Provider.ContinuedReferences);
        Assert.Equal(0, fixture.Provider.ApplyCalls);
        Assert.Equal(new[] { "local" }, gate.CheckedCertificateIds);
        Assert.Equal("MCP 授权已撤销，停止外部写入。", (await fixture.Db.CertificateJobs.SingleAsync()).Message);
        Assert.Equal(Fixture.OrderUrl, (await fixture.Db.Certificates.SingleAsync()).OrderId);
    }

    [Fact]
    public async Task StagingCertificateIsRejectedByBackendDeploymentMaterialServiceBeforeDownloading()
    {
        await using var fixture = await Fixture.CreateAsync(hasOrder: true);
        var certificate = await fixture.Db.Certificates.SingleAsync();
        certificate.Status = "Issued"; certificate.HasPrivateKey = true; certificate.IsStaging = true;
        await fixture.Db.SaveChangesAsync();
        var materialService = new CertificateMaterialService(fixture.Db, fixture.Service);
        var material = await materialService.GetAsync("local", default);
        Assert.Equal("CERTIFICATE_NOT_DEPLOYABLE", material.Code);
        Assert.False(certificate.CanDeploy);
        Assert.Equal(0, fixture.Provider.DownloadCalls);
        Assert.Empty(fixture.Provider.QueriedReferences);
    }

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, FakeAcmeProvider provider, CertificateManagementService service) : IAsyncDisposable
    {
        public const string OrderUrl = "https://acme-staging-v02.api.letsencrypt.org/acme/order/synthetic/1";
        public AppDbContext Db => db;
        public FakeAcmeProvider Provider => provider;
        public CertificateManagementService Service => service;

        public static async Task<Fixture> CreateAsync(bool hasOrder, IMcpExecutionGate? gate = null,
            string directory = AcmeProtocolClient.ProductionDirectory, bool seedIntent = true)
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            db.CloudAccounts.Add(new() { Id = "acme-account", Name = "Synthetic ACME", Provider = "Acme", UseForCertificates = true,
                UseForDns = false, ContactEmail = "synthetic@example.com", AcmeDirectoryUrl = directory });
            if (seedIntent)
            {
                db.Certificates.Add(new() { Id = "local", AccountId = "acme-account", Provider = "Acme", Domain = "app.example.com",
                    Status = "Submitting", ValidationMode = "ManualDns", AutoCleanup = false, CleanupStatus = "NotRequested", HasPrivateKey = false });
                db.CertificateJobs.Add(new() { Id = "job", CertificateId = "local", Kind = "Apply", Status = "Submitting",
                    CreatedAtUtc = DateTime.UtcNow, NextRunAtUtc = DateTime.UtcNow });
                db.CertificateIssuanceStates.Add(new() { Id = "local", AccountId = "acme-account", Provider = "Acme", Domain = "app.example.com",
                    OrderUrl = hasOrder ? OrderUrl : "", Stage = hasOrder ? "PendingValidation" : "OrderSubmitting",
                    ProtectedPayload = "synthetic-encrypted-original-private-key", CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow });
            }
            await db.SaveChangesAsync();
            using var accountKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var provider = new FakeAcmeProvider(); var accounts = new Store(directory, accountKey.ExportPkcs8PrivateKeyPem());
            var resolver = new Resolver(provider); var ids = new GuidIdGenerator();
            var domains = new DomainManagementService(db, accounts, resolver, ids);
            var service = new CertificateManagementService(db, accounts, resolver, domains, ids, gate);
            return new(connection, db, provider, service);
        }
        public async ValueTask DisposeAsync() { await db.DisposeAsync(); await connection.DisposeAsync(); }
    }

    private sealed class FakeAcmeProvider : ICloudCertificateService
    {
        public string Provider => "Acme";
        public int ApplyCalls { get; private set; }
        public int DownloadCalls { get; private set; }
        public List<CloudCertificateReference> QueriedReferences { get; } = [];
        public List<CloudCertificateReference> ContinuedReferences { get; } = [];
        public IReadOnlyList<CloudCertificate> ListCertificates { get; set; } = [];
        public Func<CloudAccountCredentials, CloudCertificateApplyRequest, CancellationToken, Task<ApiResult<CloudCertificateDetail>>>? Application { get; set; }
        public Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
        { QueriedReferences.Add(reference); return Task.FromResult(ApiResult<CloudCertificateDetail>.Ok(Detail(reference, "PendingValidation"))); }
        public Task<ApiResult<CloudCertificateDetail>> ContinueApplicationAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
        { ContinuedReferences.Add(reference); return Task.FromResult(ApiResult<CloudCertificateDetail>.Ok(Detail(reference, "Processing"))); }
        public Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default)
        { ApplyCalls++; return Application is null ? throw new InvalidOperationException("恢复已有任务时不能重新申请。") : Application(account, request, ct); }
        public Task<ApiResult<CertificateDownload>> DownloadAsync(CloudAccountCredentials account, CloudCertificateReference reference, string format, CancellationToken ct = default)
        { DownloadCalls++; return Task.FromResult(ApiResult<CertificateDownload>.Fail("UNEXPECTED", "测试不应下载材料。")); }
        public Task<ApiResult<CloudConnectionTest>> TestAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListAsync(CloudAccountCredentials account, CancellationToken ct = default) => Task.FromResult(ApiResult<IReadOnlyList<CloudCertificate>>.Ok(ListCertificates));
        public Task<ApiResult<CloudOperation>> RevokeAsync(CloudAccountCredentials account, CloudCertificateReference reference, string reason, CancellationToken ct = default) => throw new NotSupportedException();
        private static CloudCertificateDetail Detail(CloudCertificateReference reference, string status) => new(new(reference, "app.example.com", "", status,
            status == "Processing" ? "processing" : "pending", true, "LetsEncrypt", null, null, "ManualDns", "", false, true), []);
    }

    private sealed class Resolver(FakeAcmeProvider provider) : ICloudProviderResolver
    {
        public ApiResult<ICloudCertificateService> ResolveCertificate(string name) => name == "Acme"
            ? ApiResult<ICloudCertificateService>.Ok(provider) : ApiResult<ICloudCertificateService>.Fail("UNEXPECTED", "仅合成 ACME 账号可用。");
        public ApiResult<IDnsProvider> ResolveDns(string name) => ApiResult<IDnsProvider>.Fail("UNEXPECTED", "此集成测试不写 DNS。");
    }

    private sealed class DenyingGate : IMcpExecutionGate
    {
        public List<string> CheckedCertificateIds { get; } = [];
        public Task<ApiResult<bool>> CheckCertificateAsync(string certificateId, CancellationToken ct)
        { CheckedCertificateIds.Add(certificateId); return Task.FromResult(ApiResult<bool>.Fail("MCP_REVOKED", "MCP 授权已撤销，停止外部写入。")); }
        public Task<ApiResult<bool>> CheckOperationAsync(string operationId, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<bool>> CheckDeploymentAsync(string batchId, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class PreauthorizedAuthorization : IMcpAuthorizationService
    {
        public Task<ApiResult<McpEffectivePermission>> AuthorizeAsync(McpCallerContext caller, string toolName, McpResourceScope? resource, bool worker, CancellationToken ct)
            => Task.FromResult(ApiResult<McpEffectivePermission>.Ok(new(1, 1, 1, [], true)));
    }

    private sealed class Store(string directory, string accountKey) : ICloudAccountStore
    {
        public Task<ApiResult<CloudAccountCredentials>> GetCredentialsAsync(string id, CancellationToken ct) => Task.FromResult(id == "acme-account"
            ? ApiResult<CloudAccountCredentials>.Ok(new(id, "Synthetic ACME", "Acme", directory.Replace("/directory", "/acme/acct/12345", StringComparison.Ordinal),
                accountKey, true, true, false, "", "synthetic@example.com", "", AcmeDirectoryUrl: directory))
            : ApiResult<CloudAccountCredentials>.Fail("ACCOUNT_NOT_FOUND", "合成账号不存在。"));
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, string? search, string? provider, bool? enabled, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<CloudAccountOption>>> ListOptionsAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSummary>> CreateAsync(CloudAccountInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSummary>> UpdateAsync(string id, CloudAccountInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSecrets>> RevealSecretsAsync(string accountId, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<bool>> RecordTestAsync(string accountId, bool success, string code, string message, CancellationToken ct) => throw new NotSupportedException();
    }
}
