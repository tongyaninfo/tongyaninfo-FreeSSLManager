using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;

namespace SslManager.Tests;

/// <summary>域名同步必须是完整快照：分页失败时保留旧数据，成功后才标记云端已不存在的域名。</summary>
public sealed class DomainSyncTests
{
    [Fact]
    public async Task FailedFullDomainListKeepsPreviousSnapshotUnchanged()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        db.CloudAccounts.Add(new CloudAccount { Id = "account", Name = "测试账号", Provider = "TencentCloud", Enabled = true, UseForDns = true });
        db.Domains.Add(new ManagedDomain { Id = "old-local", AccountId = "account", Provider = "TencentCloud", ZoneId = "old-zone", Name = "old.example.com", Status = "Enabled", SyncedAtUtc = DateTime.UtcNow.AddDays(-1) });
        await db.SaveChangesAsync();

        var provider = new FakeDnsProvider { Zones = ApiResult<IReadOnlyList<DnsZone>>.Fail("CloudPaginationIncomplete", "分页不完整") };
        var service = new DomainManagementService(db, new FakeAccounts(), new FakeResolver(provider), new GuidIdGenerator());

        var result = await service.SyncAsync("account", default);

        Assert.False(result.Success);
        var domain = await db.Domains.SingleAsync();
        Assert.Equal("old-zone", domain.ZoneId);
        Assert.Equal("Enabled", domain.Status);
    }

    [Fact]
    public async Task SuccessfulFullDomainListMarksOnlyMissingDomainsNotPresent()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        db.CloudAccounts.Add(new CloudAccount { Id = "account", Name = "测试账号", Provider = "TencentCloud", Enabled = true, UseForDns = true });
        db.Domains.Add(new ManagedDomain { Id = "old-local", AccountId = "account", Provider = "TencentCloud", ZoneId = "old-zone", Name = "old.example.com", Status = "Enabled", SyncedAtUtc = DateTime.UtcNow.AddDays(-1) });
        await db.SaveChangesAsync();

        var provider = new FakeDnsProvider { Zones = ApiResult<IReadOnlyList<DnsZone>>.Ok([new("new-zone", "New.Example.com.", "Enabled", [], "request")]) };
        var service = new DomainManagementService(db, new FakeAccounts(), new FakeResolver(provider), new GuidIdGenerator());

        var result = await service.SyncAsync("account", default);

        Assert.True(result.Success);
        Assert.Equal(2, await db.Domains.CountAsync());
        Assert.Equal("NotPresent", (await db.Domains.SingleAsync(x => x.ZoneId == "old-zone")).Status);
        Assert.Equal("new.example.com", (await db.Domains.SingleAsync(x => x.ZoneId == "new-zone")).Name);
    }

    private sealed class FakeResolver(FakeDnsProvider provider) : ICloudProviderResolver
    {
        public ApiResult<ICloudCertificateService> ResolveCertificate(string providerName) => ApiResult<ICloudCertificateService>.Ok(provider);
        public ApiResult<IDnsProvider> ResolveDns(string providerName) => ApiResult<IDnsProvider>.Ok(provider);
    }

    private sealed class FakeAccounts : ICloudAccountStore
    {
        public Task<ApiResult<CloudAccountCredentials>> GetCredentialsAsync(string id, CancellationToken ct) => Task.FromResult(
            ApiResult<CloudAccountCredentials>.Ok(new(id, "测试账号", "TencentCloud", "key", "secret", true, true, true, "", "", "")));
        public Task<ApiResult<bool>> RecordTestAsync(string accountId, bool success, string code, string message, CancellationToken ct) => Task.FromResult(ApiResult<bool>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountPage>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, string? search, string? provider, bool? enabled, CancellationToken ct) => ListAsync(page, pageSize, ct);
        public Task<ApiResult<IReadOnlyList<CloudAccountOption>>> ListOptionsAsync(CancellationToken ct) => Task.FromResult(ApiResult<IReadOnlyList<CloudAccountOption>>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<CloudAccountSummary>> CreateAsync(CloudAccountInput input, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountSummary>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<CloudAccountSummary>> UpdateAsync(string id, CloudAccountInput input, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountSummary>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<CloudAccountSecrets>> RevealSecretsAsync(string id, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountSecrets>.Fail("UNUSED", "未覆盖"));
    }

    private sealed class FakeDnsProvider : ICloudCertificateService, IDnsProvider
    {
        public string Provider => "TencentCloud";
        public ApiResult<IReadOnlyList<DnsZone>> Zones { get; set; } = ApiResult<IReadOnlyList<DnsZone>>.Ok([]);
        public Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default) => Task.FromResult(Zones);
        public Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default) => Task.FromResult(ApiResult<IReadOnlyList<DnsRecord>>.Ok([]));
        public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default) => Task.FromResult(ApiResult<DnsRecord>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string recordId, DnsRecordRequest request, CancellationToken ct = default) => Task.FromResult(ApiResult<DnsRecord>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string recordId, bool enabled, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudOperation>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string recordId, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudOperation>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<CloudConnectionTest>> TestAsync(CloudAccountCredentials account, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudConnectionTest>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListAsync(CloudAccountCredentials account, CancellationToken ct = default) => Task.FromResult(ApiResult<IReadOnlyList<CloudCertificate>>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudCertificateDetail>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudCertificateDetail>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<CloudOperation>> RevokeAsync(CloudAccountCredentials account, CloudCertificateReference reference, string reason, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudOperation>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<CertificateDownload>> DownloadAsync(CloudAccountCredentials account, CloudCertificateReference reference, string format, CancellationToken ct = default) => Task.FromResult(ApiResult<CertificateDownload>.Fail("UNUSED", "未覆盖"));
        public Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default) => TestAsync(account, ct);
    }
}
