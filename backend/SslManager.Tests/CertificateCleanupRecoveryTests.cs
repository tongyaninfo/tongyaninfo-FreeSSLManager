using System.Text.Json;
using System.Text.Json.Nodes;
using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;

namespace SslManager.Tests;

/// <summary>用隔离数据库和假 DNS 验证申请清理的持久恢复；不申请真实证书或访问外部设备。</summary>
public sealed class CertificateCleanupRecoveryTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Theory]
    [InlineData("Creating")]
    [InlineData("CreationUnknown")]
    public async Task InterruptedCreationReadsBackExistingRecordWithoutApplyingOrClaimingOwnership(string status)
    {
        await using var fixture = await Fixture.CreateAsync(status, false, "PendingValidation");
        fixture.Provider.Records.Add(fixture.Remote());
        await fixture.Service.ProcessJobAsync("job", default);
        var validation = await fixture.Db.ValidationRecords.AsNoTracking().SingleAsync();
        Assert.Equal("Reused", validation.Status);
        Assert.False(validation.CreatedBySystem);
        Assert.Equal("dns-record", validation.RecordId);
        Assert.Equal(0, fixture.Provider.CreateCalls);
        Assert.Equal(0, fixture.Provider.ApplyCalls);
    }

    [Fact]
    public async Task UnknownCreationWithoutReadbackDoesNotCreateAnotherRecord()
    {
        await using var fixture = await Fixture.CreateAsync("CreationUnknown", false, "PendingValidation");
        await fixture.Service.ProcessJobAsync("job", default);
        Assert.Equal("CreationUnknown", (await fixture.Db.ValidationRecords.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(0, fixture.Provider.CreateCalls);
        Assert.Equal(0, fixture.Provider.ApplyCalls);
    }

    [Fact]
    public async Task RestartAfterPersistedDeleteIntentReadsIdentityAndCompletesTheSameRecord()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Records.Add(fixture.Remote());
        var snapshot = (await fixture.Service.CaptureApplicationCleanupForScheduleAsync("certificate", default)).Data!;
        await Assert.ThrowsAsync<OperationCanceledException>(() => fixture.Service.AdvanceApplicationCleanupForScheduleAsync(snapshot, async ct =>
        {
            await fixture.PersistAsync(snapshot, ct);
            if (snapshot.Records[0].Status == "Deleting") throw new OperationCanceledException();
        }, default));
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        fixture.Restart();
        snapshot = await fixture.ReadSnapshotAsync();
        fixture.Provider.BeforeDelete = async () =>
        {
            Assert.Equal("Deleting", (await fixture.ReadSnapshotAsync()).Records[0].Status);
            Assert.True(fixture.Provider.ListCalls >= 3);
        };
        var completed = await fixture.AdvanceAsync(snapshot);
        Assert.True(completed.Success && completed.Data);
        Assert.Equal("Deleted", snapshot.Records[0].Status);
        Assert.Equal(1, fixture.Provider.DeleteCalls);
        Assert.Equal(0, fixture.Provider.ApplyCalls);
    }

    [Fact]
    public async Task UnknownDeletionThatCompletedIsConfirmedWithoutSendingDeleteAgain()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Records.Add(fixture.Remote());
        fixture.Provider.UnknownDelete = true;
        var snapshot = (await fixture.Service.CaptureApplicationCleanupForScheduleAsync("certificate", default)).Data!;
        Assert.True((await fixture.AdvanceAsync(snapshot)).Data);
        fixture.Restart();
        snapshot = await fixture.ReadSnapshotAsync();
        Assert.True((await fixture.AdvanceAsync(snapshot)).Data);
        Assert.Equal(1, fixture.Provider.DeleteCalls);
    }

    [Fact]
    public async Task UnknownDeletionCanRetryOnlyAfterOwnedIdentityIsReadBackUnchanged()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Records.Add(fixture.Remote());
        fixture.Provider.UnknownDelete = true;
        fixture.Provider.KeepRecordOnDelete = true;
        var snapshot = (await fixture.Service.CaptureApplicationCleanupForScheduleAsync("certificate", default)).Data!;
        Assert.False((await fixture.AdvanceAsync(snapshot)).Data);
        fixture.Restart();
        snapshot = await fixture.ReadSnapshotAsync();
        fixture.Provider.KeepRecordOnDelete = false;
        Assert.True((await fixture.AdvanceAsync(snapshot)).Data);
        Assert.Equal(2, fixture.Provider.DeleteCalls);
        Assert.Empty(fixture.Provider.Records);
    }

    [Theory]
    [InlineData("persistent")]
    [InlineData("shared")]
    [InlineData("changed")]
    [InlineData("disabled")]
    public async Task ProtectedApplicationRecordsArePreservedAcrossRecovery(string protection)
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Records.Add(fixture.Remote());
        var row = await fixture.Db.ValidationRecords.SingleAsync();
        if (protection == "persistent") row.IsPersistent = true;
        if (protection == "shared") fixture.Db.ValidationRecords.Add(new()
        { Id = "other-validation", CertificateId = "other-certificate", DnsZoneId = "zone", RecordId = "dns-record", Name = row.Name, Type = row.Type, Value = row.Value, Status = "Reused" });
        if (protection == "changed") fixture.Provider.Records[0] = fixture.Remote() with { Value = "manually-changed" };
        if (protection == "disabled") fixture.Provider.Records[0] = fixture.Remote() with { Status = "Disabled" };
        await fixture.Db.SaveChangesAsync();
        var snapshot = (await fixture.Service.CaptureApplicationCleanupForScheduleAsync("certificate", default)).Data!;
        Assert.True((await fixture.AdvanceAsync(snapshot)).Data);
        fixture.Restart();
        Assert.True((await fixture.AdvanceAsync(await fixture.ReadSnapshotAsync())).Data);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.Single(fixture.Provider.Records);
    }

    [Fact]
    public async Task RevocationLedgerProtectsAnApplicationRecordWithTheSameIdentity()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Records.Add(fixture.Remote());
        var run = await fixture.Db.CertificateScheduleRuns.SingleAsync();
        run.OldCertificatesJson = JsonSerializer.Serialize(new[] { new ScheduleCertificateCleanup
        {
            CertificateId = "older-certificate", Domain = "app.example.test", Status = "Revoking",
            RevocationValidation = [new() { ZoneId = "zone", RecordId = "dns-record", Name = "_validation.app.example.test", Type = "TXT", Value = "application-token", Status = "Reused" }]
        } }, Json);
        await fixture.Db.SaveChangesAsync();
        var snapshot = (await fixture.Service.CaptureApplicationCleanupForScheduleAsync("certificate", default)).Data!;
        Assert.True((await fixture.AdvanceAsync(snapshot)).Data);
        Assert.Equal("Shared", snapshot.Records[0].Status);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
    }

    [Fact]
    public async Task AnotherArchivedApplicationLedgerStillProtectsDnsAfterItsCertificateRowsDisappear()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Records.Add(fixture.Remote());
        var snapshot = (await fixture.Service.CaptureApplicationCleanupForScheduleAsync("certificate", default)).Data!;
        var other = JsonSerializer.Deserialize<ScheduleApplicationDnsCleanup>(JsonSerializer.Serialize(snapshot, Json), Json)!;
        other.CertificateId = "removed-other-certificate";
        other.Records[0].ValidationRecordId = "removed-other-validation";
        fixture.Db.CertificateSchedules.Add(new() { Id = "other-schedule", Name = "另一轮", AccountId = "other-account", Domain = "app.example.test" });
        fixture.Db.CertificateScheduleRuns.Add(new()
        {
            Id = "other-run", ScheduleId = "other-schedule", CertificateId = other.CertificateId, Active = true,
            ConfigSnapshotJson = JsonSerializer.Serialize(new { applicationCleanup = other }, Json)
        });
        await fixture.Db.SaveChangesAsync();
        var result = await fixture.Service.AdvanceApplicationCleanupForScheduleAsync(snapshot, ct => fixture.Db.SaveChangesAsync(ct), default);
        Assert.True(result.Data);
        Assert.Equal("Shared", snapshot.Records[0].Status);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
    }

    [Fact]
    public async Task PersistentFlagAddedAfterCaptureIsRevalidatedBeforeDeleting()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.Records.Add(fixture.Remote());
        var snapshot = (await fixture.Service.CaptureApplicationCleanupForScheduleAsync("certificate", default)).Data!;
        (await fixture.Db.ValidationRecords.SingleAsync()).IsPersistent = true;
        await fixture.Db.SaveChangesAsync();
        Assert.True((await fixture.AdvanceAsync(snapshot)).Data);
        Assert.Equal("RetainedPersistent", snapshot.Records[0].Status);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
    }

    [Fact]
    public async Task LatePersistedOriginalCreationReceiptCanRestoreOwnershipWithoutCreatingAgain()
    {
        await using var fixture = await Fixture.CreateAsync("CreationUnknown", false);
        fixture.Provider.Records.Add(fixture.Remote());
        var snapshot = (await fixture.Service.CaptureApplicationCleanupForScheduleAsync("certificate", default)).Data!;
        var row = await fixture.Db.ValidationRecords.SingleAsync();
        row.CreatedBySystem = true; row.RecordId = "dns-record"; row.Status = "Created";
        await fixture.Db.SaveChangesAsync();
        Assert.True((await fixture.AdvanceAsync(snapshot)).Data);
        Assert.Equal("Deleted", snapshot.Records[0].Status);
        Assert.Equal(1, fixture.Provider.DeleteCalls);
        Assert.Equal(0, fixture.Provider.CreateCalls);
    }

    [Fact]
    public async Task CertificateDeletionArchivesApplicationLedgerBeforeRemovingValidationRows()
    {
        await using var fixture = await Fixture.CreateAsync(certificateStatus: "Revoked");
        fixture.Provider.Records.Add(fixture.Remote());
        var run = await fixture.Db.CertificateScheduleRuns.SingleAsync();
        run.CertificateId = "new-certificate";
        run.OldCertificatesJson = JsonSerializer.Serialize(new[] { new ScheduleCertificateCleanup { CertificateId = "certificate", Domain = "app.example.test" } }, Json);
        await fixture.Db.SaveChangesAsync();
        Assert.True((await fixture.Service.DeleteAsync("certificate", default)).Success);
        Assert.Empty(await fixture.Db.ValidationRecords.ToListAsync());
        fixture.Restart();
        var json = JsonNode.Parse((await fixture.Db.CertificateScheduleRuns.SingleAsync()).OldCertificatesJson)!;
        var snapshot = json[0]!["applicationCleanup"]!.Deserialize<ScheduleApplicationDnsCleanup>(Json)!;
        Assert.Equal("dns-record", snapshot.Records[0].RecordId);
        Assert.True((await fixture.AdvanceAsync(snapshot)).Data);
        Assert.Equal(1, fixture.Provider.DeleteCalls);
        Assert.Equal(0, fixture.Provider.ApplyCalls);
    }

    [Fact]
    public async Task ArchiveRetriesChangedJsonAndFencesAnActorHoldingThePreviousSnapshot()
    {
        await using var fixture = await Fixture.CreateAsync(certificateStatus: "Revoked");
        var run = await fixture.Db.CertificateScheduleRuns.SingleAsync();
        run.LeaseToken = "first-lease"; run.LeaseUntilUtc = DateTime.UtcNow.AddMinutes(5);
        await fixture.Db.SaveChangesAsync();
        await using var oldActor = fixture.NewContext();
        var oldSnapshot = await oldActor.CertificateScheduleRuns.SingleAsync();
        await using var currentActor = fixture.NewContext();
        CertificateScheduleRun? currentSnapshot = null;
        var interceptor = new ArchiveRaceInterceptor(async _ =>
        {
            await using var concurrent = fixture.NewContext();
            var advanced = await concurrent.CertificateScheduleRuns.SingleAsync();
            advanced.ConfigSnapshotJson = "{\"recoveryAttempts\":7,\"externalProgress\":\"advanced\"}";
            advanced.TargetsJson = "[{\"targetId\":\"preserved-target\",\"status\":\"Succeeded\"}]";
            advanced.LeaseToken = "new-lease";
            advanced.LeaseUntilUtc = DateTime.UtcNow.AddMinutes(5);
            await concurrent.SaveChangesAsync();
            currentSnapshot = await currentActor.CertificateScheduleRuns.SingleAsync();
        });
        fixture.Restart(interceptor);
        Assert.True((await fixture.Service.DeleteAsync("certificate", default)).Success);
        var latest = await fixture.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync();
        var config = JsonNode.Parse(latest.ConfigSnapshotJson)!;
        Assert.Equal("advanced", config["externalProgress"]!.GetValue<string>());
        Assert.Equal(7, config["recoveryAttempts"]!.GetValue<int>());
        Assert.Equal("certificate", config["applicationCleanup"]!["certificateId"]!.GetValue<string>());
        Assert.Contains("preserved-target", latest.TargetsJson);
        Assert.NotEqual("new-lease", latest.LeaseToken);
        Assert.True(interceptor.Calls >= 2);
        oldSnapshot.Message = "late actor must not overwrite";
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => oldActor.SaveChangesAsync());
        currentSnapshot!.Message = "latest lease actor also held JSON without the appended ledger";
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => currentActor.SaveChangesAsync());
    }

    [Fact]
    public async Task ArchiveContentionKeepsCertificateAndValidationRowsUntilTheSnapshotCanBeSaved()
    {
        await using var fixture = await Fixture.CreateAsync(certificateStatus: "Revoked");
        var interceptor = new ArchiveRaceInterceptor(async attempt =>
        {
            await using var concurrent = fixture.NewContext();
            var run = await concurrent.CertificateScheduleRuns.SingleAsync();
            run.ConfigSnapshotJson = JsonSerializer.Serialize(new { externalProgress = attempt }, Json);
            await concurrent.SaveChangesAsync();
        }, repeat: true);
        fixture.Restart(interceptor);
        await Assert.ThrowsAsync<DbUpdateConcurrencyException>(() => fixture.Service.DeleteAsync("certificate", default));
        Assert.True(await fixture.Db.Certificates.AsNoTracking().AnyAsync(value => value.Id == "certificate"));
        Assert.True(await fixture.Db.ValidationRecords.AsNoTracking().AnyAsync(value => value.Id == "validation"));
        Assert.Equal(0, fixture.Provider.CertificateDeleteCalls);
        Assert.Equal(8, interceptor.Calls);
    }

    [Fact]
    public async Task AlreadyArchivedApplicationSnapshotDoesNotRotateOrWriteTheActiveLease()
    {
        await using var fixture = await Fixture.CreateAsync(certificateStatus: "Revoked");
        var snapshot = (await fixture.Service.CaptureApplicationCleanupForScheduleAsync("certificate", default)).Data!;
        await fixture.PersistAsync(snapshot, default);
        var run = await fixture.Db.CertificateScheduleRuns.SingleAsync();
        run.LeaseToken = "same-active-lease"; run.LeaseUntilUtc = DateTime.UtcNow.AddMinutes(5);
        await fixture.Db.SaveChangesAsync();
        var interceptor = new ArchiveRaceInterceptor(_ => throw new InvalidOperationException("已有台账不能重新写入运行JSON"));
        fixture.Restart(interceptor);
        Assert.True((await fixture.Service.DeleteAsync("certificate", default)).Success);
        Assert.Equal("same-active-lease", (await fixture.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync()).LeaseToken);
        Assert.Equal(0, interceptor.Calls);
    }

    [Fact]
    public async Task RevocationChallengesNeverBecomeApplicationValidationRows()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.RevocationChallenges = [new("app.example.test", "_revoke.app.example.test", "TXT", "revocation-token")];
        Assert.True((await fixture.Service.RevokeAsync("certificate", "superseded", default)).Success);
        var original = Assert.Single(await fixture.Db.ValidationRecords.AsNoTracking().ToListAsync());
        Assert.Equal("application-token", original.Value);
        Assert.Equal("_validation.app.example.test", original.Name);
    }

    [Fact]
    public async Task CloudManagedApplicationDnsIsOnlyReadEvenIfLegacyOwnershipWasSet()
    {
        await using var fixture = await Fixture.CreateAsync();
        var certificate = await fixture.Db.Certificates.SingleAsync();
        certificate.ValidationMode = "NativeAutoDns";
        fixture.Provider.Records.Add(fixture.Remote());
        await fixture.Db.SaveChangesAsync();
        var snapshot = (await fixture.Service.CaptureApplicationCleanupForScheduleAsync("certificate", default)).Data!;
        Assert.False((await fixture.AdvanceAsync(snapshot)).Data);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        fixture.Provider.Records.Clear();
        Assert.True((await fixture.AdvanceAsync(snapshot)).Data);
    }

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, FakeProvider provider) : IAsyncDisposable
    {
        public AppDbContext Db { get; private set; } = db;
        public FakeProvider Provider => provider;
        public CertificateManagementService Service => CreateService(Db);
        public DnsRecord Remote() => new("dns-record", "example.test", "_validation.app", "TXT", "application-token", 600, "Enabled", "default", "request");
        private CertificateManagementService CreateService(AppDbContext database)
        {
            var store = new FakeStore(); var resolver = new FakeResolver(provider); var ids = new GuidIdGenerator();
            return new(database, store, resolver, new(database, store, resolver, ids), ids);
        }
        public static async Task<Fixture> CreateAsync(string status = "Created", bool owned = true, string certificateStatus = "Issued")
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options); await db.Database.EnsureCreatedAsync();
            db.Domains.Add(new() { Id = "zone", AccountId = "account", Name = "example.test", Status = "Enabled" });
            db.Certificates.Add(new() { Id = "certificate", AccountId = "account", Provider = "TencentCloud", CertificateId = "cloud-certificate", Domain = "app.example.test", ValidationMode = "ManagedDns", DnsZoneId = "zone", AutoCleanup = true, Status = certificateStatus });
            db.ValidationRecords.Add(new() { Id = "validation", CertificateId = "certificate", Domain = "app.example.test", Name = "_validation.app.example.test", Type = "TXT", Value = "application-token", DnsZoneId = "zone", RecordId = owned ? "dns-record" : null, CreatedBySystem = owned, Status = status });
            db.CertificateJobs.Add(new() { Id = "job", CertificateId = "certificate", Status = "Waiting", Kind = "Apply" });
            db.CertificateSchedules.Add(new() { Id = "schedule", Name = "恢复测试", AccountId = "account", Domain = "app.example.test", Enabled = true });
            db.CertificateScheduleRuns.Add(new() { Id = "run", ScheduleId = "schedule", CertificateId = "certificate", ConfigSnapshotJson = "{}", Active = true });
            await db.SaveChangesAsync();
            return new(connection, db, new() { CertificateStatus = certificateStatus });
        }
        public async Task PersistAsync(ScheduleApplicationDnsCleanup snapshot, CancellationToken ct)
        {
            var run = await Db.CertificateScheduleRuns.SingleAsync(ct);
            var config = JsonNode.Parse(run.ConfigSnapshotJson)!.AsObject();
            config["applicationCleanup"] = JsonSerializer.SerializeToNode(snapshot, Json);
            run.ConfigSnapshotJson = config.ToJsonString(Json);
            await Db.SaveChangesAsync(ct);
        }
        public async Task<ScheduleApplicationDnsCleanup> ReadSnapshotAsync()
        {
            var json = (await Db.CertificateScheduleRuns.AsNoTracking().SingleAsync()).ConfigSnapshotJson;
            return JsonNode.Parse(json)!["applicationCleanup"]!.Deserialize<ScheduleApplicationDnsCleanup>(Json)!;
        }
        public Task<ApiResult<bool>> AdvanceAsync(ScheduleApplicationDnsCleanup snapshot) => Service.AdvanceApplicationCleanupForScheduleAsync(snapshot, ct => PersistAsync(snapshot, ct), default);
        public AppDbContext NewContext(DbCommandInterceptor? interceptor = null)
        {
            var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection);
            if (interceptor is not null) options.AddInterceptors(interceptor);
            return new(options.Options);
        }
        public void Restart(DbCommandInterceptor? interceptor = null) { Db.Dispose(); Db = NewContext(interceptor); }
        public async ValueTask DisposeAsync() { await Db.DisposeAsync(); await connection.DisposeAsync(); }
    }

    /// <summary>在归档 CAS 即将执行时让另一个 DbContext 推进状态，复现跨 Worker 的真实竞争窗口。</summary>
    private sealed class ArchiveRaceInterceptor(Func<int, Task> advance, bool repeat = false) : DbCommandInterceptor
    {
        public int Calls { get; private set; }
        public override async ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.StartsWith("UPDATE \"CertificateScheduleRuns\"", StringComparison.Ordinal) &&
                command.CommandText.Contains("\"ConfigSnapshotJson\"", StringComparison.Ordinal) && command.CommandText.Contains("\"OldCertificatesJson\"", StringComparison.Ordinal))
            {
                Calls++;
                if (repeat || Calls == 1) await advance(Calls);
            }
            return result;
        }
    }

    private sealed class FakeResolver(FakeProvider provider) : ICloudProviderResolver
    {
        public ApiResult<ICloudCertificateService> ResolveCertificate(string name) => ApiResult<ICloudCertificateService>.Ok(provider);
        public ApiResult<IDnsProvider> ResolveDns(string name) => ApiResult<IDnsProvider>.Ok(provider);
    }
    private sealed class FakeStore : ICloudAccountStore
    {
        public Task<ApiResult<CloudAccountCredentials>> GetCredentialsAsync(string id, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountCredentials>.Ok(new(id, id, "TencentCloud", "fake-key", "fake-secret", true, true, true, "", "", "")));
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, string? search, string? provider, bool? enabled, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<CloudAccountOption>>> ListOptionsAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSummary>> CreateAsync(CloudAccountInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSummary>> UpdateAsync(string id, CloudAccountInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSecrets>> RevealSecretsAsync(string id, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<bool>> RecordTestAsync(string id, bool success, string code, string message, CancellationToken ct) => throw new NotSupportedException();
    }
    private sealed class FakeProvider : ICloudCertificateService, IDnsProvider
    {
        public string Provider => "TencentCloud";
        public string CertificateStatus { get; set; } = "Issued";
        public List<DnsRecord> Records { get; } = [];
        public int ApplyCalls { get; private set; }
        public int CreateCalls { get; private set; }
        public int DeleteCalls { get; private set; }
        public int CertificateDeleteCalls { get; private set; }
        public int ListCalls { get; private set; }
        public bool UnknownDelete { get; set; }
        public bool KeepRecordOnDelete { get; set; }
        public Func<Task>? BeforeDelete { get; set; }
        public IReadOnlyList<DnsChallenge> RevocationChallenges { get; set; } = [];
        public Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudCertificateDetail>.Ok(new(new(reference, "app.example.test", "", CertificateStatus, CertificateStatus, true, "free", null, null, "ManagedDns", "request"), [new("app.example.test", "_validation.app.example.test", "TXT", "application-token")])));
        public Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default) { ApplyCalls++; throw new InvalidOperationException("恢复不能创建新申请"); }
        public Task<ApiResult<CloudOperation>> RevokeAsync(CloudAccountCredentials account, CloudCertificateReference reference, string reason, CancellationToken ct = default) => Task.FromResult(ApiResult<CloudOperation>.Ok(new("revoke-request", "Revoking", RevocationChallenges)));
        public Task<ApiResult<CloudOperation>> DeleteAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
        { CertificateDeleteCalls++; return Task.FromResult(ApiResult<CloudOperation>.Ok(new("delete-request", "Deleted"))); }
        public Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default) { ListCalls++; return Task.FromResult(ApiResult<IReadOnlyList<DnsRecord>>.Ok(Records.ToArray())); }
        public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default) { CreateCalls++; throw new InvalidOperationException("核对不能重复创建DNS"); }
        public async Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string recordId, CancellationToken ct = default)
        {
            if (BeforeDelete is not null) await BeforeDelete();
            DeleteCalls++; if (!KeepRecordOnDelete) Records.RemoveAll(value => value.Id == recordId);
            return UnknownDelete ? ApiResult<CloudOperation>.Fail("NETWORK_ERROR", "响应丢失") : ApiResult<CloudOperation>.Ok(new("dns-delete", "Deleted"));
        }
        public Task<ApiResult<CloudConnectionTest>> TestAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CertificateDownload>> DownloadAsync(CloudAccountCredentials account, CloudCertificateReference reference, string format, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string recordId, DnsRecordRequest request, CancellationToken ct = default) => throw new InvalidOperationException("恢复不能覆盖DNS");
        public Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string recordId, bool enabled, CancellationToken ct = default) => throw new InvalidOperationException("恢复不能修改DNS启用状态");
    }
}
