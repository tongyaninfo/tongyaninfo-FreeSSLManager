using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;
using Xunit;

namespace SslManager.Tests;

/// <summary>验证证书编排的 DNS 所有权边界；所有云接口均为内存替身。</summary>
public sealed class CertificateManagementTests
{
    [Fact]
    public async Task ManagedDnsCreatesBeforeIssuanceAndDeletesOnlyOwnedExactRecordAfterIssuance()
    {
        await using var fixture = await Fixture.CreateAsync();
        var applied = await fixture.Service.ApplyAsync(fixture.Request(), default);
        Assert.True(applied.Success);
        await fixture.ProcessAsync();
        Assert.Single(fixture.Provider.Created);
        Assert.Empty(fixture.Provider.DeletedIds);
        Assert.Equal("PendingValidation", applied.Data!.Status);
        var validation = await fixture.Db.ValidationRecords.SingleAsync();
        Assert.True(validation.CreatedBySystem);
        Assert.Equal("Created", validation.Status);
        fixture.Provider.Records.Add(new("unrelated", "example.com", "other", "TXT", "challenge-value", 600, "Enabled", "default", "r"));
        fixture.Provider.CurrentStatus = "Issued";
        await fixture.ProcessAsync();
        Assert.Equal(new[] { validation.RecordId }, fixture.Provider.DeletedIds);
        Assert.Contains(fixture.Provider.Records, x => x.Id == "unrelated");
        Assert.Equal("Deleted", validation.Status);
        Assert.Equal("Completed", applied.Data.CleanupStatus);
        Assert.Equal("Completed", (await fixture.Db.CertificateJobs.SingleAsync()).Status);
        Assert.All(fixture.Provider.DnsAccountIds, id => Assert.Equal("dns-account", id));
    }

    [Fact]
    public async Task PreexistingExactValidationRecordIsReusedAndNeverDeleted()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Records.Add(Record("existing", "challenge-value"));
        var applied = await fixture.Service.ApplyAsync(fixture.Request(), default);
        await fixture.ProcessAsync();
        var validation = await fixture.Db.ValidationRecords.SingleAsync();
        Assert.Equal("Reused", validation.Status);
        Assert.False(validation.CreatedBySystem);
        Assert.Empty(fixture.Provider.Created);
        fixture.Provider.CurrentStatus = "Issued";
        await fixture.ProcessAsync();
        Assert.Empty(fixture.Provider.DeletedIds);
        Assert.Single(fixture.Provider.Records);
        Assert.Equal("Completed", applied.Data!.CleanupStatus);
    }

    [Theory]
    [InlineData("manually-changed-value")]
    [InlineData("challenge-value.")]
    public async Task ManuallyChangedTxtValueIsNeverDeleted(string changedValue)
    {
        await using var fixture = await Fixture.CreateAsync();
        var applied = await fixture.Service.ApplyAsync(fixture.Request(), default);
        await fixture.ProcessAsync();
        var owned = Assert.Single(fixture.Provider.Records);
        fixture.Provider.Records[0] = owned with { Value = changedValue };
        fixture.Provider.CurrentStatus = "Issued";
        await fixture.ProcessAsync();
        Assert.Empty(fixture.Provider.DeletedIds);
        Assert.Equal(changedValue, Assert.Single(fixture.Provider.Records).Value);
        Assert.Equal("Changed", (await fixture.Db.ValidationRecords.SingleAsync()).Status);
        Assert.Equal("Failed", applied.Data!.CleanupStatus);
    }

    [Fact]
    public async Task UnknownSubmissionBlocksRepeatedApplyAndWorkerDoesNotResubmit()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.ApplyFailure = ApiResult<CloudCertificateDetail>.Fail("OUTCOME_UNKNOWN", "远端可能已受理，请核对云端订单。");
        var first = await fixture.Service.ApplyAsync(fixture.Request(), default);
        var repeated = await fixture.Service.ApplyAsync(fixture.Request(), default);
        Assert.False(first.Success);
        Assert.Equal("APPLICATION_IN_PROGRESS", repeated.Code);
        await fixture.ProcessAsync();
        Assert.Equal(1, fixture.Provider.ApplyCalls);
        Assert.Equal("SubmissionUnknown", (await fixture.Db.Certificates.SingleAsync()).Status);
        Assert.Equal("SubmissionUnknown", (await fixture.Db.CertificateJobs.SingleAsync()).Status);
        Assert.Empty(fixture.Provider.Created);
    }

    [Fact]
    public async Task PendingApplicationCanBeCancelledAndThenDeletedLocally()
    {
        await using var fixture = await Fixture.CreateAsync();
        var applied = await fixture.Service.ApplyAsync(fixture.Request(), default);
        Assert.True(applied.Success);

        var cancelled = await fixture.Service.CancelAsync(applied.Data!.Id, default);

        Assert.True(cancelled.Success);
        Assert.Equal(1, fixture.Provider.CancelCalls);
        var certificate = await fixture.Db.Certificates.SingleAsync();
        Assert.Equal("Cancelled", certificate.Status);
        Assert.Equal("Completed", (await fixture.Db.CertificateJobs.SingleAsync()).Status);

        var deleted = await fixture.Service.DeleteAsync(applied.Data.Id, default);
        Assert.True(deleted.Success);
        Assert.Equal(1, fixture.Provider.DeleteCalls);
        Assert.Empty(await fixture.Db.Certificates.ToListAsync());
    }

    [Fact]
    public async Task UnknownCancellationIsReconciledAsCompletedWhenCloudReportsCancelled()
    {
        await using var fixture = await Fixture.CreateAsync();
        var applied = await fixture.Service.ApplyAsync(fixture.Request(), default);
        fixture.Provider.CancelFailure = ApiResult<CloudOperation>.Fail("OUTCOME_UNKNOWN", "取消结果待核对");

        var cancelled = await fixture.Service.CancelAsync(applied.Data!.Id, default);
        Assert.False(cancelled.Success);
        Assert.Equal("Processing", (await fixture.Db.Certificates.SingleAsync()).Status);

        fixture.Provider.CurrentStatus = "Cancelled";
        await fixture.ProcessAsync();
        Assert.Equal("Cancelled", (await fixture.Db.Certificates.SingleAsync()).Status);
        Assert.Equal("Completed", (await fixture.Db.CertificateJobs.SingleAsync()).Status);
    }

    [Fact]
    public async Task CrossZoneChallengeIsBlockedWithoutDnsMutation()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Challenges = [new("app.example.com", "_validation.attacker.example.net", "TXT", "challenge-value")];
        var applied = await fixture.Service.ApplyAsync(fixture.Request(), default);
        Assert.True(applied.Success);
        await fixture.ProcessAsync();
        Assert.Empty(fixture.Provider.Created);
        Assert.Empty(fixture.Provider.DeletedIds);
        Assert.Equal("Blocked", (await fixture.Db.ValidationRecords.SingleAsync()).Status);
    }

    [Fact]
    public async Task ApplicationOutsideSelectedZoneIsRejectedBeforeCloudSubmission()
    {
        await using var fixture = await Fixture.CreateAsync();
        var response = await fixture.Service.ApplyAsync(fixture.Request() with { Domain = "app.example.net" }, default);
        Assert.Equal("DNS_ZONE_MISMATCH", response.Code);
        Assert.Equal(0, fixture.Provider.ApplyCalls);
        Assert.Empty(await fixture.Db.Certificates.ToListAsync());
    }

    [Fact]
    public async Task PersistentChallengeIsCreatedBeforeIssuanceAndRetainedAfterIssuance()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Challenges = [new("app.example.com", "_validation.app.example.com", "CNAME", "validation.example.net", true)];
        await fixture.Service.ApplyAsync(fixture.Request(), default);
        await fixture.ProcessAsync();
        Assert.Single(fixture.Provider.Created);
        fixture.Provider.CurrentStatus = "Issued";
        await fixture.ProcessAsync();
        Assert.Empty(fixture.Provider.DeletedIds);
        Assert.Single(fixture.Provider.Records);
    }

    [Theory]
    [InlineData("", "TXT", "challenge-value")]
    [InlineData("_validation.app.example.com", "", "challenge-value")]
    [InlineData("_validation.app.example.com", "TXT", "")]
    [InlineData("_validation.app.example.com", "SOA", "challenge-value")]
    public async Task NativeCleanupWithoutCompleteChallengeSnapshotRemainsUnknown(string name, string type, string value)
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Challenges = [new("app.example.com", name, type, value)];
        fixture.Db.Domains.Add(new ManagedDomain { Id = "native-zone", AccountId = "certificate-account",
            Provider = "TencentCloud", ZoneId = "cloud-native-zone", Name = "example.com", Status = "Enabled" });
        await fixture.Db.SaveChangesAsync();
        var response = await fixture.Service.ApplyAsync(fixture.Request() with { ValidationMode = "NativeAutoDns", DnsZoneId = null }, default);
        fixture.Provider.CurrentStatus = "Issued";
        await fixture.ProcessAsync();
        Assert.Equal("Unknown", response.Data!.CleanupStatus);
        Assert.Empty(fixture.Provider.DeletedIds);
    }

    private static DnsRecord Record(string id, string value) => new(id, "example.com", "_validation.app", "TXT", value, 600, "Enabled", "default", "r");

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, FakeProvider provider, CertificateManagementService service) : IAsyncDisposable
    {
        public AppDbContext Db { get; } = db;
        public FakeProvider Provider { get; } = provider;
        public CertificateManagementService Service { get; } = service;
        public CertificateApplyRequest Request() => new("certificate-account", "app.example.com", ValidationMode: "ManagedDns", DnsZoneId: "dns-zone");
        public async Task ProcessAsync() => await Service.ProcessJobAsync((await Db.CertificateJobs.SingleAsync()).Id, default);
        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            db.Domains.Add(new ManagedDomain { Id = "dns-zone", AccountId = "dns-account", Provider = "Aliyun",
                ZoneId = "cloud-zone", Name = "example.com", Status = "Enabled" });
            await db.SaveChangesAsync();
            var provider = new FakeProvider();
            var accounts = new FakeStore();
            var resolver = new FakeResolver(provider);
            var ids = new GuidIdGenerator();
            var domains = new DomainManagementService(db, accounts, resolver, ids);
            return new(connection, db, provider, new(db, accounts, resolver, domains, ids));
        }
        public async ValueTask DisposeAsync() { await Db.DisposeAsync(); await connection.DisposeAsync(); }
    }

    private sealed class FakeResolver(FakeProvider provider) : ICloudProviderResolver
    {
        public ApiResult<ICloudCertificateService> ResolveCertificate(string name) => ApiResult<ICloudCertificateService>.Ok(provider);
        public ApiResult<IDnsProvider> ResolveDns(string name) => ApiResult<IDnsProvider>.Ok(provider);
    }

    private sealed class FakeStore : ICloudAccountStore
    {
        public Task<ApiResult<CloudAccountCredentials>> GetCredentialsAsync(string id, CancellationToken ct) => Task.FromResult(
            id is "certificate-account" or "dns-account"
                ? ApiResult<CloudAccountCredentials>.Ok(new(id, id, id == "dns-account" ? "Aliyun" : "TencentCloud", "fake-id", "fake-secret", true, true, true, "", "", ""))
                : ApiResult<CloudAccountCredentials>.Fail("ACCOUNT_NOT_FOUND", "模拟账号不存在"));
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountPage>.Fail("UNUSED", "不应调用"));
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, string? search, string? provider, bool? enabled, CancellationToken ct) => ListAsync(page, pageSize, ct);
        public Task<ApiResult<IReadOnlyList<CloudAccountOption>>> ListOptionsAsync(CancellationToken ct) => Task.FromResult(ApiResult<IReadOnlyList<CloudAccountOption>>.Fail("UNUSED", "不应调用"));
        public Task<ApiResult<CloudAccountSummary>> CreateAsync(CloudAccountInput input, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountSummary>.Fail("UNUSED", "不应调用"));
        public Task<ApiResult<CloudAccountSummary>> UpdateAsync(string id, CloudAccountInput input, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountSummary>.Fail("UNUSED", "不应调用"));
        public Task<ApiResult<CloudAccountSecrets>> RevealSecretsAsync(string id, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountSecrets>.Fail("UNUSED", "不应调用"));
        public Task<ApiResult<bool>> RecordTestAsync(string accountId, bool success, string code, string message, CancellationToken ct) => Task.FromResult(ApiResult<bool>.Ok(true));
    }

    private sealed class FakeProvider : ICloudCertificateService, IDnsProvider
    {
        public string Provider => "TencentCloud";
        public string CurrentStatus { get; set; } = "PendingValidation";
        public IReadOnlyList<DnsChallenge> Challenges { get; set; } = [new("app.example.com", "_validation.app.example.com", "TXT", "challenge-value")];
        public ApiResult<CloudCertificateDetail>? ApplyFailure { get; set; }
        public ApiResult<CloudOperation>? CancelFailure { get; set; }
        public int ApplyCalls { get; private set; }
        public int CancelCalls { get; private set; }
        public int DeleteCalls { get; private set; }
        public List<DnsRecord> Records { get; } = [];
        public List<DnsRecordRequest> Created { get; } = [];
        public List<string?> DeletedIds { get; } = [];
        public List<string> DnsAccountIds { get; } = [];
        private CloudCertificateDetail Detail() => new(new(new("cloud-certificate", ApiVersion: "V1"), "app.example.com", "", CurrentStatus,
            CurrentStatus, true, "free", null, null, "ManagedDns", "request-id"), Challenges);
        public Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default)
        { ApplyCalls++; return Task.FromResult(ApplyFailure ?? ApiResult<CloudCertificateDetail>.Ok(Detail())); }
        public Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudCertificateDetail>.Ok(Detail()));
        public Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListAsync(CloudAccountCredentials account, CancellationToken ct = default) => Task.FromResult(ApiResult<IReadOnlyList<CloudCertificate>>.Ok([Detail().Certificate]));
        public Task<ApiResult<CloudConnectionTest>> TestAsync(CloudAccountCredentials account, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudConnectionTest>.Ok(new(Provider, "r", "模拟通过")));
        public Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default) => TestAsync(account, ct);
        public Task<ApiResult<CloudOperation>> RevokeAsync(CloudAccountCredentials account, CloudCertificateReference reference, string reason, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudOperation>.Fail("UNUSED", "不应调用"));
        public Task<ApiResult<CloudOperation>> CancelAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
        { CancelCalls++; return Task.FromResult(CancelFailure ?? ApiResult<CloudOperation>.Ok(new("cancel-request", "Cancelled"), "模拟已取消")); }
        public Task<ApiResult<CloudOperation>> DeleteAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
        { DeleteCalls++; return Task.FromResult(ApiResult<CloudOperation>.Ok(new("delete-request", "Deleted"), "模拟已删除")); }
        public Task<ApiResult<CertificateDownload>> DownloadAsync(CloudAccountCredentials account, CloudCertificateReference reference, string format, CancellationToken ct = default) => Task.FromResult(ApiResult<CertificateDownload>.Fail("UNUSED", "不应调用"));
        public Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default) => Task.FromResult(ApiResult<IReadOnlyList<DnsZone>>.Ok([new("cloud-zone", "example.com", "Enabled", [], "r")]));
        public Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default)
        { DnsAccountIds.Add(account.Id); return Task.FromResult(ApiResult<IReadOnlyList<DnsRecord>>.Ok(Records.ToArray())); }
        public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default)
        {
            DnsAccountIds.Add(account.Id); Created.Add(request);
            var record = new DnsRecord("created-" + Created.Count, zone, request.Name, request.Type, request.Value, request.Ttl, "Enabled", request.Line, "r", request.Mx);
            Records.Add(record);
            return Task.FromResult(ApiResult<DnsRecord>.Ok(record));
        }
        public Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string recordId, CancellationToken ct = default)
        {
            DnsAccountIds.Add(account.Id); DeletedIds.Add(recordId); Records.RemoveAll(x => x.Id == recordId);
            return Task.FromResult(ApiResult<CloudOperation>.Ok(new("r", "Deleted")));
        }
        public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string recordId, DnsRecordRequest request, CancellationToken ct = default) => Task.FromResult(ApiResult<DnsRecord>.Fail("UNUSED", "不应调用"));
        public Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string recordId, bool enabled, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudOperation>.Fail("UNUSED", "不应调用"));
    }
}
