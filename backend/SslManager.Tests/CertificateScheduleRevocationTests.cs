using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;
using SslManager.Api.Service.impl.Deployment;

namespace SslManager.Tests;

/// <summary>通过隔离云与 DNS 协议目标验证吊销验证、断点恢复和最后清理，不连接真实设备。</summary>
public sealed class CertificateScheduleRevocationTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Theory]
    [InlineData("ManagedDns")]
    [InlineData("NativeAutoDns")]
    public async Task AutomaticRevocationCreatesOnlyDedicatedChallengeAndCleansItAfterConfirmedRevocationAndDeletion(string mode)
    {
        await using var fixture = await Fixture.CreateAsync(mode);

        await fixture.AdvanceAsync(18);

        Assert.Equal(1, fixture.Provider.RevokeCalls);
        Assert.Equal(1, fixture.Provider.DnsCreates);
        Assert.Equal(1, fixture.Provider.CertificateDeletes);
        Assert.Equal(new[] { "revoke-dns" }, fixture.Provider.DeletedDnsIds);
        Assert.True(fixture.Provider.Operations.IndexOf("dns-create") < fixture.Provider.Operations.IndexOf("cloud-revoked"));
        Assert.True(fixture.Provider.Operations.IndexOf("cloud-revoked") < fixture.Provider.Operations.IndexOf("cloud-delete"));
        Assert.True(fixture.Provider.Operations.IndexOf("cloud-delete") < fixture.Provider.Operations.IndexOf("dns-delete"));
        Assert.False(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
        Assert.True(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "new-cert"));
        // 新证书的原申请验证记录与本轮吊销台账完全隔离，不能被误写或误清理。
        Assert.True(await fixture.Db.ValidationRecords.AnyAsync(record => record.Id == "new-application-validation"));
        Assert.Contains(fixture.Provider.Records, record => record.Id == "application-dns");
        var run = await fixture.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync();
        Assert.Equal("Succeeded", run.Status);
        Assert.DoesNotContain("application-challenge-value", run.OldCertificatesJson);
    }

    [Fact]
    public async Task ExistingAdditionalValidationAttentionRecoversWithoutAnotherApplicationDeploymentOrRevocation()
    {
        await using var fixture = await Fixture.CreateAsync("ManagedDns", resumedRevocation: true);

        await fixture.AdvanceAsync(18);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(1, fixture.Provider.DnsCreates);
        Assert.Equal(1, fixture.Provider.CertificateDeletes);
        Assert.Equal(1, await fixture.Db.CertificateScheduleRuns.CountAsync());
        Assert.Equal(1, await fixture.Db.DeploymentBatches.CountAsync());
        Assert.Equal("Succeeded", (await fixture.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync()).Status);
    }

    [Fact]
    public async Task DelayedRevocationChallengeKeepsPollingAndFinishesWithoutAnotherSubmission()
    {
        await using var fixture = await Fixture.CreateAsync("ManagedDns");
        fixture.Provider.DelayChallenges = true;
        await fixture.AdvanceAsync(4);
        Assert.Equal(1, fixture.Provider.RevokeCalls);
        var waiting = await fixture.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync();
        Assert.True(waiting.Active);
        Assert.Equal("CleaningOldCertificates", waiting.Status);
        Assert.Equal(0, fixture.Provider.DnsCreates);
        fixture.Provider.DelayChallenges = false;
        await fixture.AdvanceAsync(18);
        Assert.Equal("Succeeded", (await fixture.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(1, fixture.Provider.RevokeCalls);
        Assert.Equal(1, fixture.Provider.CertificateDeletes);
    }

    [Theory]
    [InlineData("FILE")]
    [InlineData("")]
    public async Task FileOrUntypedRevocationChallengesRemainForReviewWithoutGuessingDnsType(string type)
    {
        await using var fixture = await Fixture.CreateAsync("ManagedDns", resumedRevocation: true);
        fixture.Provider.RevocationType = type;

        await fixture.AdvanceAsync(6);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(0, fixture.Provider.DnsCreates);
        Assert.Equal(0, fixture.Provider.CertificateDeletes);
        Assert.Empty(fixture.Provider.DeletedDnsIds);
        Assert.Equal("NeedsAttention", (await fixture.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync()).Status);
    }

    [Fact]
    public async Task PersistedDnsLedgerCanFinishAfterCertificateAndValidationRowsHaveAlreadyDisappeared()
    {
        await using var fixture = await Fixture.CreateAsync("ManagedDns", resumedRevocation: true);
        var run = await fixture.Db.CertificateScheduleRuns.SingleAsync();
        var old = JsonSerializer.Deserialize<List<ScheduleCertificateCleanup>>(run.OldCertificatesJson, Json)!;
        old[0].Status = "DnsCleaning";
        old[0].RevocationValidation = [fixture.OwnedRecord()];
        run.Status = "CleaningOldCertificates";
        run.Code = "";
        run.OldCertificatesJson = JsonSerializer.Serialize(old, Json);
        fixture.Provider.Records.Add(fixture.RevocationRecord());
        fixture.Db.Certificates.Remove(await fixture.Db.Certificates.SingleAsync(certificate => certificate.Id == "old-cert"));
        await fixture.Db.SaveChangesAsync();

        await fixture.AdvanceAsync(10);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(0, fixture.Provider.CertificateDeletes);
        Assert.Equal(new[] { "revoke-dns" }, fixture.Provider.DeletedDnsIds);
        Assert.Equal("Succeeded", (await fixture.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync()).Status);
        Assert.Contains(fixture.Provider.Records, record => record.Id == "application-dns");
    }

    [Theory]
    [InlineData("Revoking")]
    [InlineData("DnsCleaning")]
    public async Task DisabledScheduleRetainsLedgerWithoutAnyNewDnsOrCertificateWrites(string stage)
    {
        await using var fixture = await Fixture.CreateAsync("ManagedDns", resumedRevocation: true);
        var schedule = await fixture.Db.CertificateSchedules.SingleAsync();
        schedule.Enabled = false;
        var run = await fixture.Db.CertificateScheduleRuns.SingleAsync();
        run.Status = "CleaningOldCertificates";
        run.Code = "";
        var old = JsonSerializer.Deserialize<List<ScheduleCertificateCleanup>>(run.OldCertificatesJson, Json)!;
        old[0].Status = stage;
        if (stage == "DnsCleaning")
        {
            old[0].RevocationValidation = [fixture.OwnedRecord()];
            fixture.Provider.Records.Add(fixture.RevocationRecord());
            fixture.Db.Certificates.Remove(await fixture.Db.Certificates.SingleAsync(certificate => certificate.Id == "old-cert"));
        }
        run.OldCertificatesJson = JsonSerializer.Serialize(old, Json);
        await fixture.Db.SaveChangesAsync();

        await fixture.AdvanceAsync(5);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(0, fixture.Provider.CertificateDeletes);
        Assert.Equal(0, fixture.Provider.DnsCreates);
        Assert.Empty(fixture.Provider.DeletedDnsIds);
        var retained = await fixture.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync();
        Assert.True(retained.Active);
        Assert.NotEmpty(retained.OldCertificatesJson);
    }

    [Fact]
    public async Task RunViewsNeverReturnPrivateRevocationLedgerValues()
    {
        await using var fixture = await Fixture.CreateAsync("ManagedDns", resumedRevocation: true);
        var run = await fixture.Db.CertificateScheduleRuns.SingleAsync();
        var old = JsonSerializer.Deserialize<List<ScheduleCertificateCleanup>>(run.OldCertificatesJson, Json)!;
        old[0].RevocationValidation = [fixture.OwnedRecord()];
        run.OldCertificatesJson = JsonSerializer.Serialize(old, Json);
        await fixture.Db.SaveChangesAsync();

        var service = fixture.NewService();
        var schedule = await service.GetAsync("schedule", default);
        var history = await service.ListRunsAsync("schedule", 1, 20, default);

        Assert.True(schedule.Success, schedule.Message);
        Assert.True(history.Success, history.Message);
        Assert.Contains("revocation-challenge-value", run.OldCertificatesJson);
        Assert.DoesNotContain("revocation-challenge-value", JsonSerializer.Serialize(schedule));
        Assert.DoesNotContain("revocation-challenge-value", JsonSerializer.Serialize(history));
        Assert.DoesNotContain("test-cloud-secret", JsonSerializer.Serialize(history));
    }

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, FakeProvider provider) : IAsyncDisposable
    {
        public AppDbContext Db { get; } = db;
        public FakeProvider Provider { get; } = provider;
        private readonly Accounts accounts = new();

        public CertificateScheduleService NewService()
        {
            var ids = new GuidIdGenerator();
            var resolver = new Resolver(Provider);
            var domains = new DomainManagementService(Db, accounts, resolver, ids);
            var certificates = new CertificateManagementService(Db, accounts, resolver, domains, ids);
            var protection = new EphemeralDataProtectionProvider();
            var executors = new DeploymentExecutorResolver([]);
            var targets = new DeploymentTargetService(Db, executors, protection, ids);
            var deployments = new DeploymentService(Db, targets, executors, new UnusedMaterials(), protection, ids);
            return new(Db, certificates, accounts, resolver, deployments, targets, ids,
                revocationDns: new CertificateRevocationDnsService(Db, domains));
        }

        public static async Task<Fixture> CreateAsync(string mode, bool resumedRevocation = false)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            var provider = new FakeProvider { CloudStatus = resumedRevocation ? "Revoking" : "Issued" };
            var fixture = new Fixture(connection, db, provider);
            var next = DateTime.UtcNow.AddMonths(1);
            var input = new CertificateScheduleInput
            {
                Name = "自动吊销验证", AccountId = "account", Domain = "vpn.example.test", ValidationMode = mode,
                FirstRunAtUtc = next, TargetIds = ["target"], AutoCleanup = true, RevokeOldCertificates = true
            };
            db.CloudAccounts.Add(new() { Id = "account", Name = "测试云账号", Provider = "TencentCloud" });
            db.Users.Add(new() { Id = "admin", Username = "admin", NormalizedUsername = "ADMIN", Enabled = true, Role = "admin" });
            db.Domains.Add(new() { Id = "zone", AccountId = "account", Provider = "TencentCloud", ZoneId = "cloud-zone", Name = "example.test" });
            db.DeploymentTargets.Add(new()
            {
                Id = "target", Name = "已验证目标", ExecutorKey = "linux.files.ssh.v1", Enabled = true,
                ConfigurationJson = "{\"sourceDomain\":\"vpn.example.test\"}"
            });
            db.CertificateSchedules.Add(new()
            {
                Id = "schedule", Name = input.Name, AccountId = "account", Domain = input.Domain, ValidationMode = mode,
                TargetIdsJson = "[\"target\"]", FirstRunAtUtc = next, NextRunAtUtc = next, CreatedByUserId = "admin", Enabled = true
            });
            db.Certificates.AddRange(new ManagedCertificate
            {
                Id = "new-cert", AccountId = "account", Provider = "TencentCloud", CertificateId = "new-cloud",
                Domain = input.Domain, Status = "Issued", NotBeforeUtc = DateTime.UtcNow.AddDays(-1), NotAfterUtc = DateTime.UtcNow.AddMonths(3)
            }, new ManagedCertificate
            {
                Id = "old-cert", AccountId = "account", Provider = "TencentCloud", CertificateId = "old-cloud",
                Domain = input.Domain, Status = resumedRevocation ? "Revoking" : "Issued", ValidationMode = mode,
                NotBeforeUtc = DateTime.UtcNow.AddMonths(-1), NotAfterUtc = DateTime.UtcNow.AddDays(10)
            });
            db.ValidationRecords.Add(new()
            {
                Id = "new-application-validation", CertificateId = "new-cert", Name = "_application.vpn.example.test",
                Type = "TXT", Value = "application-challenge-value", RecordId = "application-dns", DnsZoneId = "zone",
                CreatedBySystem = true, Status = "Created"
            });
            db.DeploymentBatches.Add(new() { Id = "batch", CertificateId = "new-cert", CertificateDomain = input.Domain, Status = "Succeeded" });
            db.DeploymentTasks.Add(new()
            {
                Id = "task", BatchId = "batch", TargetId = "target", ResourceKey = "resource", Status = "Succeeded", VerificationLevel = "FilesChecked"
            });
            db.DeploymentBindings.Add(new()
            {
                Id = "binding", TargetId = "target", ResourceKey = "resource", CertificateId = "new-cert", LastTaskId = "task"
            });
            if (resumedRevocation)
                db.CertificateJobs.Add(new() { Id = "revoke-job", CertificateId = "old-cert", Kind = "Revoke", Status = "Waiting" });
            db.CertificateScheduleRuns.Add(new()
            {
                Id = "run", ScheduleId = "schedule", TriggerKey = "revocation-test", ConfigSnapshotJson = JsonSerializer.Serialize(input, Json),
                CertificateId = "new-cert", Status = resumedRevocation ? "NeedsAttention" : "CleaningOldCertificates",
                Code = resumedRevocation ? "ADDITIONAL_REVOKE_VALIDATION" : "", Active = true,
                CreatedAtUtc = DateTime.UtcNow, ScheduledForUtc = DateTime.UtcNow, NextCheckAtUtc = DateTime.UtcNow.AddSeconds(-1),
                TargetsJson = JsonSerializer.Serialize(new[] { new ScheduleTargetProgress { TargetId = "target", BatchId = "batch", Status = "Succeeded" } }, Json),
                OldCertificatesJson = JsonSerializer.Serialize(new[] { new ScheduleCertificateCleanup
                {
                    CertificateId = "old-cert", Domain = input.Domain, Status = resumedRevocation ? "Revoking" : "Pending"
                } }, Json)
            });
            await db.SaveChangesAsync();
            return fixture;
        }

        public ScheduleRevocationDnsRecord OwnedRecord() => new()
        {
            AccountId = "account", Domain = "vpn.example.test", Name = "_revoke.vpn.example.test", Type = "TXT",
            Value = "revocation-challenge-value", ZoneId = "zone", ZoneName = "example.test", RecordId = "revoke-dns",
            CreatedBySystem = true, Status = "Created"
        };

        public DnsRecord RevocationRecord() => new("revoke-dns", "example.test", "_revoke.vpn", "TXT", "revocation-challenge-value", 600, "Enabled", "default", "r");

        public async Task AdvanceAsync(int steps)
        {
            for (var step = 0; step < steps; step++)
            {
                Db.ChangeTracker.Clear();
                await Db.CertificateScheduleRuns.Where(run => run.Id == "run" && run.Active)
                    .ExecuteUpdateAsync(update => update.SetProperty(run => run.NextCheckAtUtc, DateTime.UtcNow.AddSeconds(-1)));
                // 每步重新构造服务，验证所有恢复信息都来自数据库，不能依赖内存中的挑战或状态。
                await NewService().ProcessNextAsync(default);
            }
        }

        public async ValueTask DisposeAsync() { await Db.DisposeAsync(); await connection.DisposeAsync(); }
    }

    private sealed class UnusedMaterials : ICertificateMaterialService
    {
        public Task<ApiResult<CertificateMaterial>> GetAsync(string certificateId, CancellationToken ct) => throw new InvalidOperationException("吊销验证阶段不得重新部署材料。");
    }

    private sealed class Resolver(FakeProvider provider) : ICloudProviderResolver
    {
        public ApiResult<ICloudCertificateService> ResolveCertificate(string name) => ApiResult<ICloudCertificateService>.Ok(provider);
        public ApiResult<IDnsProvider> ResolveDns(string name) => ApiResult<IDnsProvider>.Ok(provider);
    }

    private sealed class Accounts : ICloudAccountStore
    {
        public Task<ApiResult<CloudAccountCredentials>> GetCredentialsAsync(string id, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountCredentials>.Ok(
            new(id, id, "TencentCloud", "test-cloud-key", "test-cloud-secret", true, true, true, "", "", "")));
        public Task<ApiResult<bool>> RecordTestAsync(string accountId, bool success, string code, string message, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, string? search, string? provider, bool? enabled, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<CloudAccountOption>>> ListOptionsAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSummary>> CreateAsync(CloudAccountInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSummary>> UpdateAsync(string id, CloudAccountInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSecrets>> RevealSecretsAsync(string accountId, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class FakeProvider : ICloudCertificateService, IDnsProvider
    {
        public string Provider => "TencentCloud";
        public string CloudStatus { get; set; } = "Issued";
        public string RevocationType { get; set; } = "TXT";
        public bool DelayChallenges { get; set; }
        public int RevokeCalls { get; private set; }
        public int CertificateDeletes { get; private set; }
        public int DnsCreates { get; private set; }
        public List<string> DeletedDnsIds { get; } = [];
        public List<string> Operations { get; } = [];
        public List<DnsRecord> Records { get; } = [new("application-dns", "example.test", "_application.vpn", "TXT", "application-challenge-value", 600, "Enabled", "default", "r")];

        public Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
        {
            if (CloudStatus == "Revoking" && Records.Any(record => record.Id == "revoke-dns"))
            {
                CloudStatus = "Revoked";
                Operations.Add("cloud-revoked");
            }
            return Task.FromResult(ApiResult<CloudCertificateDetail>.Ok(new(new(reference, "vpn.example.test", "", CloudStatus, CloudStatus,
                true, "test", DateTimeOffset.UtcNow.AddMonths(-1), DateTimeOffset.UtcNow.AddDays(10), "ManagedDns", "r"),
                [new("vpn.example.test", "_application.vpn.example.test", "TXT", "application-challenge-value")],
                RevocationChallenges: CloudStatus == "Revoking" && !DelayChallenges ? [new("vpn.example.test", "_revoke.vpn.example.test", RevocationType, "revocation-challenge-value")] : [])));
        }

        public Task<ApiResult<CloudOperation>> RevokeAsync(CloudAccountCredentials account, CloudCertificateReference reference, string reason, CancellationToken ct = default)
        {
            RevokeCalls++; Operations.Add("cloud-revoke"); CloudStatus = "Revoking";
            // 提交接口没有记录类型，后续必须读取专用吊销验证详情，不能借用原申请挑战。
            return Task.FromResult(ApiResult<CloudOperation>.Ok(new("revoke-r", "Revoking",
                [new("vpn.example.test", "_revoke.vpn.example.test", "", "revocation-challenge-value")])));
        }

        public Task<ApiResult<CloudOperation>> DeleteAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
        {
            CertificateDeletes++; Operations.Add("cloud-delete");
            return Task.FromResult(ApiResult<CloudOperation>.Ok(new("delete-r", "Deleted")));
        }

        public Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default) =>
            Task.FromResult(ApiResult<IReadOnlyList<DnsRecord>>.Ok(Records.ToArray()));
        public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default)
        {
            DnsCreates++; Operations.Add("dns-create");
            var record = new DnsRecord("revoke-dns", zone, request.Name, request.Type, request.Value, request.Ttl, "Enabled", request.Line, "create-r");
            Records.Add(record);
            return Task.FromResult(ApiResult<DnsRecord>.Ok(record));
        }
        public Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string recordId, CancellationToken ct = default)
        {
            DeletedDnsIds.Add(recordId); Operations.Add("dns-delete");
            Records.RemoveAll(record => record.Id == recordId);
            return Task.FromResult(ApiResult<CloudOperation>.Ok(new("dns-delete-r", "Deleted")));
        }
        public Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudConnectionTest>> TestAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default) => throw new InvalidOperationException("恢复吊销验证不能创建新申请。");
        public Task<ApiResult<CertificateDownload>> DownloadAsync(CloudAccountCredentials account, CloudCertificateReference reference, string format, CancellationToken ct = default) => throw new InvalidOperationException("恢复吊销验证不能重新下载部署材料。");
        public Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string recordId, DnsRecordRequest request, CancellationToken ct = default) => throw new InvalidOperationException("不能覆盖既有 DNS 记录。");
        public Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string recordId, bool enabled, CancellationToken ct = default) => throw new NotSupportedException();
    }
}
