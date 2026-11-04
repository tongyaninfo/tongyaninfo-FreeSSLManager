using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;

namespace SslManager.Tests;

/// <summary>使用内存 DNS 协议替身核验吊销记录所有权、断点恢复及跨账号托管域选择。</summary>
public sealed class CertificateRevocationDnsTests
{
    [Fact]
    public async Task OwnedTxtIsCreatedAfterIntentAndDeletedOnlyAfterCertificateCleanupWithReadback()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.BeforeCreate = () => Assert.Equal("Creating", fixture.LastSavedStatus);
        var ready = await fixture.EnsureAsync();
        Assert.True(ready.Success && ready.Data);
        var ledger = Assert.Single(fixture.Item.RevocationValidation!);
        Assert.True(ledger.CreatedBySystem);
        fixture.Provider.BeforeDelete = () => Assert.Equal("Deleting", fixture.LastSavedStatus);
        var deleting = await fixture.CleanupAsync();
        Assert.True(deleting.Success);
        Assert.False(deleting.Data);
        Assert.True((await fixture.CleanupAsync()).Data);
        Assert.Equal("Deleted", ledger.Status);
        Assert.Equal(1, fixture.Provider.CreateCalls);
        Assert.Equal(1, fixture.Provider.DeleteCalls);
        Assert.Empty(fixture.Provider.Records);
    }

    [Fact]
    public async Task ExistingIdenticalRecordIsReusedAndNeverDeleted()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Records.Add(fixture.Remote("preexisting"));
        Assert.True((await fixture.EnsureAsync()).Data);
        Assert.False(Assert.Single(fixture.Item.RevocationValidation!).CreatedBySystem);
        Assert.True((await fixture.CleanupAsync()).Data);
        Assert.Single(fixture.Provider.Records);
        Assert.Equal(0, fixture.Provider.CreateCalls);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
    }

    [Fact]
    public async Task UnknownCreationIsReadOnlyReconciledAndNeverClaimsDeletionOwnership()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.CreateFailure = true;
        Assert.False((await fixture.EnsureAsync()).Data);
        Assert.Equal("CreationUnknown", Assert.Single(fixture.Item.RevocationValidation!).Status);
        Assert.True((await fixture.EnsureAsync()).Data);
        var record = Assert.Single(fixture.Item.RevocationValidation!);
        Assert.Equal("Reused", record.Status);
        Assert.False(record.CreatedBySystem);
        Assert.True((await fixture.CleanupAsync()).Data);
        Assert.Equal(1, fixture.Provider.CreateCalls);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.Single(fixture.Provider.Records);
    }

    [Fact]
    public async Task InterruptedCreatingIntentWithoutRecordDoesNotCreateAgain()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Item.RevocationValidation = [fixture.Ledger("Creating", false)];
        var result = await fixture.EnsureAsync();
        Assert.True(result.Success);
        Assert.False(result.Data);
        Assert.Equal(0, fixture.Provider.CreateCalls);
    }

    [Fact]
    public async Task DifferentTxtValueCanBeAddedWithoutOverwritingTheExistingRecord()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Records.Add(fixture.Remote("other") with { Value = "other-validation-token" });
        Assert.True((await fixture.EnsureAsync()).Data);
        Assert.Equal(2, fixture.Provider.Records.Count);
        Assert.Contains(fixture.Provider.Records, record => record.Id == "other" && record.Value == "other-validation-token");
    }

    [Theory]
    [InlineData("CNAME", "CNAME")]
    [InlineData("CNAME", "TXT")]
    [InlineData("TXT", "CNAME")]
    public async Task CnameConflictsNeverOverwriteExistingDns(string challengeType, string existingType)
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Records.Add(fixture.Remote("existing") with { Type = existingType, Value = "other-value.example.test" });
        var result = await fixture.EnsureAsync(fixture.Challenge with { Type = challengeType });
        Assert.False(result.Success);
        Assert.Equal("REVOCATION_DNS_CONFLICT", result.Code);
        Assert.Equal(0, fixture.Provider.CreateCalls);
        Assert.Single(fixture.Provider.Records);
    }

    [Theory]
    [InlineData("CAA", "_revoke.vpn.example.test", false)]
    [InlineData("", "_revoke.vpn.example.test", false)]
    [InlineData("TXT", "_revoke.vpn.example.test", true)]
    [InlineData("TXT", "_revoke.example.test", false)]
    [InlineData("TXT", "_revoke.attacker.test", false)]
    [InlineData("TXT", "https://vpn.example.test", false)]
    public async Task InvalidOrOutOfScopeChallengeDoesNotGuessOrWriteDns(string type, string name, bool relative)
    {
        await using var fixture = await Fixture.CreateAsync();
        var result = await fixture.EnsureAsync(fixture.Challenge with { Type = type, Name = name, IsRelative = relative });
        Assert.False(result.Success);
        Assert.Equal(0, fixture.Provider.CreateCalls);
        Assert.Empty(fixture.Provider.Records);
    }

    [Theory]
    [InlineData("example.test", true)]
    [InlineData("unrelated.test", false)]
    public async Task AuthorizationDomainMayBeTheLegitimateAncestorWhileRecordNameStaysInsideThePlan(string authorizationDomain, bool expected)
    {
        await using var fixture = await Fixture.CreateAsync();
        var result = await fixture.EnsureAsync(fixture.Challenge with { Domain = authorizationDomain });
        Assert.Equal(expected, result.Success);
        Assert.Equal(expected ? 1 : 0, fixture.Provider.CreateCalls);
        if (expected)
        {
            var ledger = Assert.Single(fixture.Item.RevocationValidation!);
            Assert.Equal(fixture.Config.Domain, ledger.Domain);
            Assert.Equal(fixture.Challenge.Name, ledger.Name);
        }
        else
        {
            Assert.Equal("REVOCATION_DNS_CHALLENGE_INVALID", result.Code);
            Assert.Empty(fixture.Provider.Records);
        }
    }

    [Fact]
    public async Task TokenRotationAppendsLedgerAndCleansEveryOwnedRecord()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.EnsureAsync()).Data);
        Assert.True((await fixture.EnsureAsync(fixture.Challenge with { Value = "rotated-token" })).Data);
        Assert.Equal(2, fixture.Item.RevocationValidation!.Count);
        for (var step = 0; step < 5; step++) await fixture.CleanupAsync();
        Assert.Equal(2, fixture.Provider.DeleteCalls);
        Assert.All(fixture.Item.RevocationValidation, record => Assert.Equal("Deleted", record.Status));
        Assert.Empty(fixture.Provider.Records);
    }

    [Fact]
    public async Task ManuallyChangedRecordPersistentRecordAndOtherValidationReferenceAreProtected()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.EnsureAsync()).Data);
        var ledger = Assert.Single(fixture.Item.RevocationValidation!);
        fixture.Provider.Records[0] = fixture.Provider.Records[0] with { Value = "manually-changed" };
        Assert.True((await fixture.CleanupAsync()).Data);
        Assert.Equal("Changed", ledger.Status);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        fixture.Provider.Records.Clear();
        fixture.Provider.Records.Add(fixture.Remote("persistent"));
        fixture.Item.RevocationValidation = [fixture.Ledger("Created", true, "persistent")];
        fixture.Item.RevocationValidation[0].IsPersistent = true;
        Assert.True((await fixture.CleanupAsync()).Data);
        fixture.Item.RevocationValidation = [fixture.Ledger("Created", true, "persistent")];
        fixture.Db.ValidationRecords.Add(new()
        {
            Id = "another-validation", CertificateId = "another-cert", Name = fixture.Challenge.Name, Type = "TXT",
            Value = "different-snapshot-value", DnsZoneId = "zone", RecordId = "persistent", Status = "Reused"
        });
        await fixture.Db.SaveChangesAsync();
        Assert.True((await fixture.CleanupAsync()).Data);
        Assert.Equal("Protected", fixture.Item.RevocationValidation[0].Status);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
    }

    [Fact]
    public async Task AnotherActiveRunWithTheSameRecordPreventsDeletion()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.EnsureAsync()).Data);
        var other = new ScheduleCertificateCleanup
        {
            CertificateId = "another-old-cert", Domain = fixture.Config.Domain, Status = "Revoking",
            RevocationValidation = [fixture.Ledger("Reused", false, fixture.Item.RevocationValidation![0].RecordId)]
        };
        fixture.Db.CertificateScheduleRuns.Add(new()
        {
            Id = "another-run", ScheduleId = "another-schedule", TriggerKey = "manual", Active = true,
            OldCertificatesJson = JsonSerializer.Serialize(new[] { other }, Json)
        });
        await fixture.Db.SaveChangesAsync();
        Assert.True((await fixture.CleanupAsync()).Data);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.Equal("Protected", fixture.Item.RevocationValidation![0].Status);
    }

    [Fact]
    public async Task UnknownDeletionOnlyReadsBackAndDoesNotSendDeleteTwice()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.EnsureAsync()).Data);
        fixture.Provider.DeleteFailure = true;
        Assert.False((await fixture.CleanupAsync()).Data);
        Assert.True((await fixture.CleanupAsync()).Data);
        Assert.Equal(1, fixture.Provider.DeleteCalls);
        Assert.Equal("Deleted", fixture.Item.RevocationValidation![0].Status);
    }

    [Fact]
    public async Task RecordChangedDuringDeletionCheckpointIsReadAgainAndNeverDeleted()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.EnsureAsync()).Data);
        fixture.BeforeSave = () =>
        {
            if (fixture.LastSavedStatus == "Deleting")
                fixture.Provider.Records[0] = fixture.Provider.Records[0] with { Value = "changed-during-checkpoint" };
            return Task.CompletedTask;
        };
        var result = await fixture.CleanupAsync();
        Assert.True(result.Success && result.Data);
        Assert.Equal("Changed", fixture.Item.RevocationValidation![0].Status);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.Single(fixture.Provider.Records);
        Assert.Contains("保留", result.Message);
    }

    [Fact]
    public async Task FailedFinalReadBeforeAnyDeleteCallCanRetryTheReadWithoutLosingOwnership()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.EnsureAsync()).Data);
        fixture.Provider.FailListCall = fixture.Provider.ListCalls + 2;
        Assert.False((await fixture.CleanupAsync()).Data);
        Assert.Equal("Created", fixture.Item.RevocationValidation![0].Status);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.False((await fixture.CleanupAsync()).Data);
        Assert.True((await fixture.CleanupAsync()).Data);
        Assert.Equal(1, fixture.Provider.DeleteCalls);
    }

    [Theory]
    [InlineData("Disabled")]
    [InlineData("Unknown")]
    [InlineData("")]
    public async Task MatchingButDisabledOrUnconfirmedRecordIsNotTreatedAsReady(string status)
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Records.Add(fixture.Remote("disabled-existing") with { Status = status });
        var result = await fixture.EnsureAsync();
        Assert.False(result.Success);
        Assert.Equal("REVOCATION_DNS_NOT_ENABLED", result.Code);
        Assert.Equal(0, fixture.Provider.CreateCalls);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.Single(fixture.Provider.Records);
    }

    [Fact]
    public async Task SameAccountZoneHasPriorityAndOtherAccountsNeedAUniqueLongestMatch()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Db.CloudAccounts.Add(new() { Id = "other", Provider = "FakeDns", Name = "另一个DNS账号" });
        fixture.Db.Domains.Add(new() { Id = "more-specific", AccountId = "other", Name = "vpn.example.test", ZoneId = "cloud-more-specific" });
        await fixture.Db.SaveChangesAsync();
        Assert.True((await fixture.EnsureAsync()).Data);
        Assert.Equal("account", fixture.Item.RevocationValidation![0].AccountId);
        Assert.Equal("zone", fixture.Item.RevocationValidation[0].ZoneId);
    }

    [Fact]
    public async Task UniqueOtherDnsAccountIsSupportedButEqualZonesAcrossAccountsAreRejected()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.Db.CloudAccounts.Where(account => account.Id == "account").ExecuteUpdateAsync(update => update.SetProperty(account => account.UseForDns, false));
        fixture.Db.CloudAccounts.Add(new() { Id = "dns-only", Provider = "FakeDns", Name = "独立DNS账号" });
        fixture.Db.Domains.Add(new() { Id = "dns-zone", AccountId = "dns-only", Name = "example.test", ZoneId = "cloud-dns" });
        await fixture.Db.SaveChangesAsync();
        Assert.True((await fixture.EnsureAsync()).Data);
        Assert.Equal("dns-only", fixture.Item.RevocationValidation![0].AccountId);
        fixture.Item.RevocationValidation = null;
        fixture.Provider.Records.Clear();
        fixture.Db.CloudAccounts.Add(new() { Id = "another-dns", Provider = "FakeDns", Name = "冲突DNS账号" });
        fixture.Db.Domains.Add(new() { Id = "ambiguous-zone", AccountId = "another-dns", Name = "example.test", ZoneId = "cloud-ambiguous" });
        await fixture.Db.SaveChangesAsync();
        var result = await fixture.EnsureAsync();
        Assert.False(result.Success);
        Assert.Equal("REVOCATION_DNS_ZONE_AMBIGUOUS", result.Code);
        Assert.Equal(1, fixture.Provider.CreateCalls);
    }

    [Fact]
    public async Task DisableBetweenIntentAndCloudCallPreventsMutationAndForgedSnapshotCannotExpandScope()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.BeforeSave = async () => await fixture.Db.CertificateSchedules.Where(schedule => schedule.Id == "schedule")
            .ExecuteUpdateAsync(update => update.SetProperty(schedule => schedule.Enabled, false));
        Assert.False((await fixture.EnsureAsync()).Success);
        Assert.Equal(0, fixture.Provider.CreateCalls);
        fixture.Item.RevocationValidation = [fixture.Ledger("Created", true)];
        fixture.Item.RevocationValidation[0].Name = "_revoke.other.example.test";
        Assert.False((await fixture.CleanupAsync()).Success);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
    }

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private sealed class Fixture(SqliteConnection connection, AppDbContext db, FakeDns provider, CertificateRevocationDnsService service) : IAsyncDisposable
    {
        public AppDbContext Db => db;
        public FakeDns Provider => provider;
        public CertificateScheduleInput Config { get; } = new() { AccountId = "account", Domain = "vpn.example.test", ValidationMode = "ManagedDns" };
        public CertificateScheduleRun Run { get; } = new() { Id = "run", ScheduleId = "schedule", Active = true };
        public ScheduleCertificateCleanup Item { get; } = new() { CertificateId = "old-cert", Domain = "vpn.example.test", Status = "Revoking" };
        public DnsChallenge Challenge { get; } = new("vpn.example.test", "_revoke.vpn.example.test", "TXT", "revocation-secret-token");
        public string LastSavedStatus { get; private set; } = "";
        public Func<Task>? BeforeSave { get; set; }
        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options); await db.Database.EnsureCreatedAsync();
            db.CloudAccounts.Add(new() { Id = "account", Name = "测试DNS", Provider = "FakeDns" });
            db.Domains.Add(new() { Id = "zone", AccountId = "account", Name = "example.test", ZoneId = "cloud-zone" });
            db.CertificateSchedules.Add(new() { Id = "schedule", Name = "测试计划", AccountId = "account", Domain = "vpn.example.test", Enabled = true });
            await db.SaveChangesAsync();
            var provider = new FakeDns(); var domains = new DomainManagementService(db, new FakeAccounts(), new FakeResolver(provider), new GuidIdGenerator());
            return new(connection, db, provider, new(db, domains));
        }
        private async Task SaveAsync(CancellationToken ct)
        {
            LastSavedStatus = Item.RevocationValidation?.LastOrDefault()?.Status ?? "";
            if (BeforeSave is not null) await BeforeSave();
            Run.OldCertificatesJson = JsonSerializer.Serialize(new[] { Item }, Json);
            await Db.SaveChangesAsync(ct);
        }
        public Task<ApiResult<bool>> EnsureAsync(DnsChallenge? challenge = null) => service.EnsureAsync(Run, Item, Config, [challenge ?? Challenge], SaveAsync, default);
        public Task<ApiResult<bool>> CleanupAsync() => service.CleanupAsync(Run, Item, Config, SaveAsync, default);
        public DnsRecord Remote(string id) => new(id, "example.test", "_revoke.vpn", "TXT", Challenge.Value, 600, "Enabled", "default", "request");
        public ScheduleRevocationDnsRecord Ledger(string status, bool owned, string id = "owned-id") => new()
        {
            Domain = Config.Domain, Name = Challenge.Name, Type = "TXT", Value = Challenge.Value,
            AccountId = "account", ZoneId = "zone", ZoneName = "example.test", RecordId = id, CreatedBySystem = owned, Status = status
        };
        public async ValueTask DisposeAsync() { await Db.DisposeAsync(); await connection.DisposeAsync(); }
    }
    private sealed class FakeResolver(FakeDns provider) : ICloudProviderResolver
    {
        public ApiResult<IDnsProvider> ResolveDns(string name) => ApiResult<IDnsProvider>.Ok(provider);
        public ApiResult<ICloudCertificateService> ResolveCertificate(string name) => throw new NotSupportedException();
    }
    private sealed class FakeAccounts : ICloudAccountStore
    {
        public Task<ApiResult<CloudAccountCredentials>> GetCredentialsAsync(string id, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountCredentials>.Ok(new(id, id, "FakeDns", "fake-key", "fake-secret", true, true, true, "", "", "")));
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, string? search, string? provider, bool? enabled, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<CloudAccountOption>>> ListOptionsAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSummary>> CreateAsync(CloudAccountInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSummary>> UpdateAsync(string id, CloudAccountInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSecrets>> RevealSecretsAsync(string id, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<bool>> RecordTestAsync(string id, bool success, string code, string message, CancellationToken ct) => throw new NotSupportedException();
    }
    private sealed class FakeDns : IDnsProvider
    {
        public string Provider => "FakeDns";
        public List<DnsRecord> Records { get; } = [];
        public int CreateCalls { get; private set; }
        public int DeleteCalls { get; private set; }
        public bool CreateFailure { get; set; }
        public bool DeleteFailure { get; set; }
        public int ListCalls { get; private set; }
        public int? FailListCall { get; set; }
        public Action? BeforeCreate { get; set; }
        public Action? BeforeDelete { get; set; }
        public Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default)
        {
            ListCalls++;
            return Task.FromResult(ListCalls == FailListCall ? ApiResult<IReadOnlyList<DnsRecord>>.Fail("NETWORK_ERROR", "query unavailable")
                : ApiResult<IReadOnlyList<DnsRecord>>.Ok(Records.ToArray()));
        }
        public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest input, CancellationToken ct = default)
        {
            BeforeCreate?.Invoke(); CreateCalls++;
            var record = new DnsRecord("created-" + CreateCalls, zone, input.Name, input.Type, input.Value, input.Ttl, "Enabled", "default", "request");
            Records.Add(record);
            return Task.FromResult(CreateFailure ? ApiResult<DnsRecord>.Fail("NETWORK_ERROR", "unknown") : ApiResult<DnsRecord>.Ok(record));
        }
        public Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string id, CancellationToken ct = default)
        {
            BeforeDelete?.Invoke(); DeleteCalls++; Records.RemoveAll(record => record.Id == id);
            return Task.FromResult(DeleteFailure ? ApiResult<CloudOperation>.Fail("NETWORK_ERROR", "unknown") : ApiResult<CloudOperation>.Ok(new("request", "Deleted")));
        }
        public Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string id, DnsRecordRequest input, CancellationToken ct = default) => throw new InvalidOperationException("吊销验证不能覆盖已有DNS。");
        public Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string id, bool enabled, CancellationToken ct = default) => throw new NotSupportedException();
    }
}
