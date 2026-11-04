using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;
using Xunit;

namespace SslManager.Tests;

/// <summary>覆盖证书删除状态边界及异步删除任务恢复。</summary>
public sealed class CertificateDeletionTests
{
    [Fact]
    public async Task RevokedCertificateCanBeDeleted()
    {
        await using var fixture = await Fixture.CreateAsync("Revoked", DateTime.UtcNow.AddDays(-1));
        fixture.Provider.DeleteResult = ApiResult<CloudOperation>.Ok(new("request", "Deleted"));

        var result = await fixture.Service.DeleteAsync(fixture.Certificate.Id, default);

        Assert.True(result.Success);
        Assert.Empty(await fixture.Db.Certificates.ToListAsync());
    }

    [Fact]
    public async Task SyncWaitsForDeletionBeforeFetchingCloudSnapshot()
    {
        await using var fixture = await Fixture.CreateAsync("Revoked", DateTime.UtcNow.AddDays(-1));
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Provider.ListResult = ApiResult<IReadOnlyList<CloudCertificate>>.Ok([
            new(new("cloud-certificate"), "ssl.example.com", "", "Revoked", "10", true, "83", null, null, "", "before-delete")
        ]);
        fixture.Provider.DeleteHandler = async () =>
        {
            entered.SetResult();
            await release.Task;
            fixture.Provider.ListResult = ApiResult<IReadOnlyList<CloudCertificate>>.Ok([]);
            return ApiResult<CloudOperation>.Ok(new("request", "Deleted"));
        };

        var deleting = fixture.Service.DeleteAsync(fixture.Certificate.Id, default);
        await entered.Task;
        var synchronizing = fixture.Service.SyncAsync("account", default);
        try
        {
            // 同步必须在删除完成后查询云端，不能将删除之前的快照排队后重新导入。
            Assert.Equal(0, fixture.Provider.ListCalls);
        }
        finally
        {
            release.SetResult();
            await Task.WhenAll(deleting, synchronizing);
        }

        Assert.True((await deleting).Success);
        Assert.True((await synchronizing).Success);
        Assert.Equal(1, fixture.Provider.ListCalls);
        Assert.Empty(await fixture.Db.Certificates.ToListAsync());
    }

    [Fact]
    public async Task ExpiredCertificateWithFutureEndDateIsRejected()
    {
        await using var fixture = await Fixture.CreateAsync("Expired", DateTime.UtcNow.AddMinutes(1));

        var result = await fixture.Service.DeleteAsync(fixture.Certificate.Id, default);

        Assert.Equal("EXPIRED_CERTIFICATE_REQUIRED", result.Code);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.Single(await fixture.Db.Certificates.ToListAsync());
    }

    [Fact]
    public async Task DeleteJobRemovesLocalCertificateWhenCloudReportsNotFound()
    {
        await using var fixture = await Fixture.CreateAsync("Expired", DateTime.UtcNow.AddDays(-1));
        fixture.Provider.DeleteResult = ApiResult<CloudOperation>.Ok(new("request", "Deleting", TaskId: "task-1"));
        fixture.Provider.GetResult = ApiResult<CloudCertificateDetail>.Fail("CertificateNotFound", "证书不存在");

        var submitted = await fixture.Service.DeleteAsync(fixture.Certificate.Id, default);
        var job = await fixture.Db.CertificateJobs.SingleAsync();
        await fixture.Service.ProcessJobAsync(job.Id, default);

        Assert.True(submitted.Success);
        Assert.Empty(await fixture.Db.Certificates.ToListAsync());
        Assert.Empty(await fixture.Db.CertificateJobs.ToListAsync());
    }

    [Fact]
    public async Task SyncRemovesDeletingCertificateMissingFromCompleteCloudList()
    {
        await using var fixture = await Fixture.CreateAsync("Deleting", DateTime.UtcNow.AddDays(-1));
        fixture.Provider.ListResult = ApiResult<IReadOnlyList<CloudCertificate>>.Ok([]);

        var result = await fixture.Service.SyncAsync("account", default);

        Assert.True(result.Success);
        Assert.Empty(await fixture.Db.Certificates.ToListAsync());
    }

    [Fact]
    public async Task SyncRemovesProcessingCertificateDeletedDirectlyInCloud()
    {
        await using var fixture = await Fixture.CreateAsync("Processing", DateTime.UtcNow.AddDays(30));
        fixture.Provider.ListResult = ApiResult<IReadOnlyList<CloudCertificate>>.Ok([]);

        var result = await fixture.Service.SyncAsync("account", default);

        Assert.True(result.Success);
        Assert.Empty(await fixture.Db.Certificates.ToListAsync());
    }

    [Theory]
    [InlineData("Expired")]
    [InlineData("Revoked")]
    [InlineData("Cancelled")]
    [InlineData("Failed")]
    public async Task SyncRemovesTerminalCertificateMissingFromAuthoritativeCloudSnapshot(string status)
    {
        await using var fixture = await Fixture.CreateAsync(status, DateTime.UtcNow.AddDays(-1));
        fixture.Provider.ListResult = ApiResult<IReadOnlyList<CloudCertificate>>.Ok([]);

        var result = await fixture.Service.SyncAsync("account", default);

        Assert.True(result.Success);
        Assert.Empty(await fixture.Db.Certificates.ToListAsync());
    }

    [Fact]
    public async Task SyncRecreatesHistoricalCertificatesReturnedByCloudSnapshot()
    {
        await using var fixture = await Fixture.CreateAsync("Processing", DateTime.UtcNow.AddDays(30));
        fixture.Provider.ListResult = ApiResult<IReadOnlyList<CloudCertificate>>.Ok([
            new(new("expired-certificate"), "expired.example.com", "", "Expired", "3", true, "83", null,
                DateTimeOffset.UtcNow.AddDays(-90), "", "expired-request"),
            new(new("revoked-certificate"), "revoked.example.com", "", "Revoked", "10", true, "83", null,
                DateTimeOffset.UtcNow.AddDays(-60), "", "revoked-request")
        ]);

        var result = await fixture.Service.SyncAsync("account", default);

        Assert.True(result.Success);
        var certificates = await fixture.Db.Certificates.OrderBy(x => x.CertificateId).ToListAsync();
        Assert.Equal(new[] { "expired-certificate", "revoked-certificate" }, certificates.Select(x => x.CertificateId));
        Assert.Equal(new[] { "Expired", "Revoked" }, certificates.Select(x => x.Status));
    }

    private sealed class Fixture : IAsyncDisposable
    {
        private readonly SqliteConnection connection;
        public AppDbContext Db { get; }
        public FakeProvider Provider { get; }
        public CertificateManagementService Service { get; }
        public ManagedCertificate Certificate { get; }

        private Fixture(SqliteConnection connection, AppDbContext db, FakeProvider provider, CertificateManagementService service, ManagedCertificate certificate)
        {
            this.connection = connection; Db = db; Provider = provider; Service = service; Certificate = certificate;
        }

        public static async Task<Fixture> CreateAsync(string status, DateTime notAfter)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            var provider = new FakeProvider();
            var accounts = new FakeAccounts();
            var resolver = new FakeResolver(provider);
            var ids = new GuidIdGenerator();
            var domains = new DomainManagementService(db, accounts, resolver, ids);
            var certificate = new ManagedCertificate
            {
                Id = "local-certificate", AccountId = "account", Provider = "TencentCloud", CertificateId = "cloud-certificate",
                ApiVersion = "V1", Domain = "ssl.example.com", Status = status, NotAfterUtc = notAfter, SyncedAtUtc = DateTime.UtcNow
            };
            db.Certificates.Add(certificate);
            await db.SaveChangesAsync();
            return new(connection, db, provider, new(db, accounts, resolver, domains, ids), certificate);
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }

    private sealed class FakeResolver(FakeProvider provider) : ICloudProviderResolver
    {
        public ApiResult<ICloudCertificateService> ResolveCertificate(string providerName) => ApiResult<ICloudCertificateService>.Ok(provider);
        public ApiResult<IDnsProvider> ResolveDns(string providerName) => ApiResult<IDnsProvider>.Ok(provider);
    }

    private sealed class FakeAccounts : ICloudAccountStore
    {
        public Task<ApiResult<CloudAccountCredentials>> GetCredentialsAsync(string id, CancellationToken ct) => Task.FromResult(
            ApiResult<CloudAccountCredentials>.Ok(new(id, id, "TencentCloud", "key", "secret", true, true, true, "", "", "")));
        public Task<ApiResult<bool>> RecordTestAsync(string accountId, bool success, string code, string message, CancellationToken ct) => Task.FromResult(ApiResult<bool>.Ok(true));
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountPage>.Fail("UNUSED", "测试未覆盖此路径"));
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, string? search, string? provider, bool? enabled, CancellationToken ct) => ListAsync(page, pageSize, ct);
        public Task<ApiResult<IReadOnlyList<CloudAccountOption>>> ListOptionsAsync(CancellationToken ct) => Task.FromResult(ApiResult<IReadOnlyList<CloudAccountOption>>.Fail("UNUSED", "测试未覆盖此路径"));
        public Task<ApiResult<CloudAccountSummary>> CreateAsync(CloudAccountInput input, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountSummary>.Fail("UNUSED", "测试未覆盖此路径"));
        public Task<ApiResult<CloudAccountSummary>> UpdateAsync(string id, CloudAccountInput input, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountSummary>.Fail("UNUSED", "测试未覆盖此路径"));
        public Task<ApiResult<CloudAccountSecrets>> RevealSecretsAsync(string id, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountSecrets>.Fail("UNUSED", "测试未覆盖此路径"));
    }

    private sealed class FakeProvider : ICloudCertificateService, IDnsProvider
    {
        public string Provider => "TencentCloud";
        public int DeleteCalls { get; private set; }
        public int ListCalls { get; private set; }
        public Func<Task<ApiResult<CloudOperation>>>? DeleteHandler { get; set; }
        public ApiResult<CloudOperation> DeleteResult { get; set; } = ApiResult<CloudOperation>.Ok(new("request", "Deleted"));
        public ApiResult<CloudCertificateDetail> GetResult { get; set; } = ApiResult<CloudCertificateDetail>.Fail("UNUSED", "未配置");
        public ApiResult<IReadOnlyList<CloudCertificate>> ListResult { get; set; } = ApiResult<IReadOnlyList<CloudCertificate>>.Ok([]);
        public Task<ApiResult<CloudOperation>> DeleteAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default) { DeleteCalls++; return DeleteHandler?.Invoke() ?? Task.FromResult(DeleteResult); }
        public Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default) => Task.FromResult(GetResult);
        public Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListAsync(CloudAccountCredentials account, CancellationToken ct = default) { ListCalls++; return Task.FromResult(ListResult); }
        public Task<ApiResult<CloudConnectionTest>> TestAsync(CloudAccountCredentials account, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudConnectionTest>.Fail("UNUSED", "未配置"));
        public Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default) => TestAsync(account, ct);
        public Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudCertificateDetail>.Fail("UNUSED", "未配置"));
        public Task<ApiResult<CloudOperation>> RevokeAsync(CloudAccountCredentials account, CloudCertificateReference reference, string reason, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudOperation>.Fail("UNUSED", "未配置"));
        public Task<ApiResult<CertificateDownload>> DownloadAsync(CloudAccountCredentials account, CloudCertificateReference reference, string format, CancellationToken ct = default) => Task.FromResult(ApiResult<CertificateDownload>.Fail("UNUSED", "未配置"));
        public Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default) => Task.FromResult(ApiResult<IReadOnlyList<DnsZone>>.Ok([]));
        public Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default) => Task.FromResult(ApiResult<IReadOnlyList<DnsRecord>>.Ok([]));
        public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default) => Task.FromResult(ApiResult<DnsRecord>.Fail("UNUSED", "未配置"));
        public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string recordId, DnsRecordRequest request, CancellationToken ct = default) => Task.FromResult(ApiResult<DnsRecord>.Fail("UNUSED", "未配置"));
        public Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string recordId, bool enabled, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudOperation>.Fail("UNUSED", "未配置"));
        public Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string recordId, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudOperation>.Fail("UNUSED", "未配置"));
    }
}
