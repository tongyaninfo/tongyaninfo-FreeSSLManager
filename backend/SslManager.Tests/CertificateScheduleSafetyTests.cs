using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Common;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;
using SslManager.Api.Service.impl.Deployment;

namespace SslManager.Tests;

/// <summary>使用隔离数据库验证新增计划表的兼容性、去重约束及旧证书清理边界。</summary>
public sealed class CertificateScheduleSafetyTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task ExpiredOldCertificateIsDeletedWithoutRevocationAfterVerifiedDeployment()
    {
        await using var fixture = await CleanupFixture.CreateAsync("Expired");

        await fixture.AdvanceAsync(8);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(1, fixture.Provider.DeleteCalls);
        Assert.False(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
        Assert.True(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "new-cert"));
    }

    [Fact]
    public async Task IssuedOldCertificateWaitsForConfirmedRevocationBeforeDeletion()
    {
        await using var fixture = await CleanupFixture.CreateAsync("Issued");

        await fixture.AdvanceAsync(5);

        Assert.Equal(1, fixture.Provider.RevokeCalls);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.True(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
        fixture.Provider.CloudStatus = "Revoked";
        await fixture.AdvanceAsync(8);

        Assert.Equal(1, fixture.Provider.RevokeCalls);
        Assert.Equal(1, fixture.Provider.DeleteCalls);
        Assert.False(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
        Assert.True(fixture.Provider.Calls.IndexOf("revoke") < fixture.Provider.Calls.IndexOf("delete"));
    }

    [Theory]
    [InlineData("Failed", "FilesChecked")]
    [InlineData("Running", "FilesChecked")]
    [InlineData("Succeeded", "None")]
    [InlineData("Skipped", "None")]
    public async Task AnyUnsuccessfulOrUnverifiedTargetPreventsOldCertificateCleanup(string targetStatus, string verification)
    {
        await using var fixture = await CleanupFixture.CreateAsync("Issued");
        var task = await fixture.Db.DeploymentTasks.SingleAsync();
        task.Status = targetStatus;
        task.VerificationLevel = verification;
        await fixture.Db.SaveChangesAsync();

        await fixture.AdvanceAsync(5);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.True(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
    }

    [Theory]
    [InlineData("binding")]
    [InlineData("queued")]
    [InlineData("running")]
    [InlineData("needs-attention")]
    public async Task OldCertificateStillBoundOrReferencedByAnUnfinishedDeploymentIsProtected(string reference)
    {
        await using var fixture = await CleanupFixture.CreateAsync("Issued");
        if (reference == "binding")
            fixture.Db.DeploymentBindings.Add(new() { Id = "old-binding", TargetId = "another-target", ResourceKey = "other-resource", CertificateId = "old-cert" });
        else
        {
            fixture.Db.DeploymentBatches.Add(new() { Id = "other-batch", CertificateId = "old-cert", Status = "Running" });
            fixture.Db.DeploymentTasks.Add(new()
            {
                Id = "other-task", BatchId = "other-batch", TargetId = "another-target", ResourceKey = "other-resource",
                Status = reference switch { "queued" => "Queued", "running" => "Running", _ => "NeedsAttention" }
            });
        }
        await fixture.Db.SaveChangesAsync();

        await fixture.AdvanceAsync(8);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.True(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
    }

    [Theory]
    [InlineData("other-account", "vpn.example.test")]
    [InlineData("account", "other.example.test")]
    [InlineData("account", "sub.vpn.example.test")]
    public async Task CleanupSnapshotCannotExpandToAnotherAccountOrDomain(string accountId, string domain)
    {
        await using var fixture = await CleanupFixture.CreateAsync("Issued");
        var old = await fixture.Db.Certificates.SingleAsync(certificate => certificate.Id == "old-cert");
        old.AccountId = accountId;
        old.Domain = domain;
        await fixture.Db.SaveChangesAsync();

        await fixture.AdvanceAsync(8);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.True(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
    }

    [Fact]
    public async Task UnknownRevocationResultDoesNotResubmitOrDeleteOnLaterWorkerPasses()
    {
        await using var fixture = await CleanupFixture.CreateAsync("Issued");
        fixture.Provider.RevokeResult = ApiResult<CloudOperation>.Fail("NETWORK_ERROR", "提交结果未知");

        await fixture.AdvanceAsync(10);

        Assert.Equal(1, fixture.Provider.RevokeCalls);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.True(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
    }

    [Fact]
    public async Task ExplicitlyRejectedRevocationRetriesAfterRateLimitAndContinuesCleanup()
    {
        await using var fixture = await CleanupFixture.CreateAsync("Issued");
        fixture.Provider.RevokeResult = ApiResult<CloudOperation>.Fail("RATE_LIMITED", "本次请求未受理");
        await fixture.AdvanceAsync(1);
        Assert.Equal(1, fixture.Provider.RevokeCalls);
        Assert.True((await fixture.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync()).Active);
        fixture.Provider.RevokeResult = ApiResult<CloudOperation>.Ok(new("accepted", "Revoking"));
        await fixture.AdvanceAsync(1);
        Assert.Equal(2, fixture.Provider.RevokeCalls);
        fixture.Provider.CloudStatus = "Revoked";
        await fixture.AdvanceAsync(8);
        Assert.Equal(2, fixture.Provider.RevokeCalls);
        Assert.Equal(1, fixture.Provider.DeleteCalls);
        Assert.Equal("Succeeded", (await fixture.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync()).Status);
    }

    [Fact]
    public async Task UnknownDeletionResultDoesNotResubmitOnLaterWorkerPasses()
    {
        await using var fixture = await CleanupFixture.CreateAsync("Expired");
        fixture.Provider.DeleteResult = ApiResult<CloudOperation>.Fail("NETWORK_ERROR", "提交结果未知");

        await fixture.AdvanceAsync(10);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(1, fixture.Provider.DeleteCalls);
        Assert.True(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
    }

    [Fact]
    public async Task DisabledOldCertificateCleanupOptionLeavesExistingCertificateUntouched()
    {
        await using var fixture = await CleanupFixture.CreateAsync("Issued", revokeOldCertificates: false);

        await fixture.AdvanceAsync(8);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.True(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
    }

    [Theory]
    [InlineData("Revoked")]
    [InlineData("Expired")]
    [InlineData("Cancelled")]
    [InlineData("Processing")]
    public async Task NewCertificateThatIsNoLongerIssuedPreventsOldCertificateCleanup(string status)
    {
        await using var fixture = await CleanupFixture.CreateAsync("Issued");
        var current = await fixture.Db.Certificates.SingleAsync(certificate => certificate.Id == "new-cert");
        current.Status = status;
        await fixture.Db.SaveChangesAsync();

        await fixture.AdvanceAsync(4);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.True(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("not-yet-valid")]
    [InlineData("missing-expiry")]
    [InlineData("account-changed")]
    [InlineData("domain-changed")]
    [InlineData("removed")]
    public async Task MissingInvalidOrReassignedNewCertificatePreventsOldCertificateCleanup(string change)
    {
        await using var fixture = await CleanupFixture.CreateAsync("Issued");
        var current = await fixture.Db.Certificates.SingleAsync(certificate => certificate.Id == "new-cert");
        switch (change)
        {
            case "expired": current.NotAfterUtc = DateTime.UtcNow.AddSeconds(-1); break;
            case "not-yet-valid": current.NotBeforeUtc = DateTime.UtcNow.AddDays(1); break;
            case "missing-expiry": current.NotAfterUtc = null; break;
            case "account-changed": current.AccountId = "another-account"; break;
            case "domain-changed": current.Domain = "another.example.test"; break;
            case "removed": fixture.Db.Certificates.Remove(current); break;
        }
        await fixture.Db.SaveChangesAsync();

        await fixture.AdvanceAsync(4);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.True(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
    }

    [Theory]
    [InlineData("another-certificate")]
    [InlineData("later-task")]
    [InlineData("removed-binding")]
    public async Task ChangedCurrentDeploymentBindingPreventsCleanupDespiteHistoricalSuccess(string change)
    {
        await using var fixture = await CleanupFixture.CreateAsync("Issued");
        var binding = await fixture.Db.DeploymentBindings.SingleAsync();
        switch (change)
        {
            case "another-certificate": binding.CertificateId = "third-cert"; binding.LastTaskId = "third-task"; break;
            case "later-task": binding.LastTaskId = "later-task"; break;
            case "removed-binding": fixture.Db.DeploymentBindings.Remove(binding); break;
        }
        await fixture.Db.SaveChangesAsync();

        await fixture.AdvanceAsync(4);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.True(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
    }

    [Theory]
    [InlineData("Queued")]
    [InlineData("Running")]
    [InlineData("NeedsAttention")]
    public async Task ActiveRollbackOfTheSameResourceProtectsOldCertificateEvenWhenBatchReferencesTheNewCertificate(string status)
    {
        await using var fixture = await CleanupFixture.CreateAsync("Issued");
        // 恢复任务沿用原新证书批次元数据，但实际将把旧文件放回同一远端资源。
        fixture.Db.DeploymentBatches.Add(new()
        {
            Id = "rollback-batch", CertificateId = "new-cert", OperationType = "Rollback", Status = "Running"
        });
        fixture.Db.DeploymentTasks.Add(new()
        {
            Id = "rollback-task", BatchId = "rollback-batch", TargetId = "target", SourceTaskId = "verified-task",
            ResourceKey = "verified-resource", Status = status
        });
        await fixture.Db.SaveChangesAsync();

        await fixture.AdvanceAsync(4);

        Assert.Equal(0, fixture.Provider.RevokeCalls);
        Assert.Equal(0, fixture.Provider.DeleteCalls);
        Assert.True(await fixture.Db.Certificates.AnyAsync(certificate => certificate.Id == "old-cert"));
    }

    [Fact]
    public async Task AddingScheduleMigrationPreservesExistingCloudCertificateAndTargetRows()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = Database(connection);
        await db.GetService<IMigrator>().MigrateAsync("20261028061614_AddDeploymentRecoveryTasks");
        await HistoricalDatabaseRows.InsertAsync(db, "CloudAccounts", new CloudAccount
        {
            Id = "existing-account", Name = "既有云账号", Provider = "TencentCloud",
            ProtectedAccessKeyId = "original-key-ciphertext", ProtectedAccessKeySecret = "original-secret-ciphertext"
        });
        await HistoricalDatabaseRows.InsertAsync(db, "Certificates", new ManagedCertificate
        {
            Id = "existing-certificate", AccountId = "existing-account", CertificateId = "cloud-id",
            Domain = "vpn.example.test", Status = "Issued"
        });
        db.DeploymentTargets.Add(new()
        {
            Id = "existing-target", Name = "既有部署目标", ExecutorKey = "linux.files.ssh.v1", Endpoint = "ssh.invalid",
            ConfigurationJson = "{\"sourceDomain\":\"vpn.example.test\"}", ProtectedCredentials = "original-target-ciphertext"
        });
        await db.SaveChangesAsync();
        db.ChangeTracker.Clear();

        await db.Database.MigrateAsync();

        var account = await db.CloudAccounts.SingleAsync();
        Assert.Equal("original-key-ciphertext", account.ProtectedAccessKeyId);
        Assert.Equal("original-secret-ciphertext", account.ProtectedAccessKeySecret);
        Assert.Equal("cloud-id", (await db.Certificates.SingleAsync()).CertificateId);
        var target = await db.DeploymentTargets.SingleAsync();
        Assert.Equal("original-target-ciphertext", target.ProtectedCredentials);
        Assert.Equal("{\"sourceDomain\":\"vpn.example.test\"}", target.ConfigurationJson);
        Assert.Empty(await db.CertificateSchedules.ToListAsync());
        Assert.Empty(await db.CertificateScheduleRuns.ToListAsync());
        Assert.Contains("20261101093752_AddCertificateSchedules", await db.Database.GetAppliedMigrationsAsync());
    }

    [Fact]
    public async Task DatabaseAllowsDisabledDuplicatesButOnlyOneEnabledAccountDomainSchedule()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = Database(connection);
        await db.Database.EnsureCreatedAsync();
        db.CertificateSchedules.Add(Schedule("first", true));
        var disabled = Schedule("disabled", false);
        db.CertificateSchedules.Add(disabled);
        await db.SaveChangesAsync();

        disabled.Enabled = true;

        var exception = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        Assert.Equal(19, Assert.IsType<SqliteException>(exception.InnerException).SqliteErrorCode);
    }

    [Fact]
    public async Task DatabaseEnforcesOneActiveRunAndOnePersistedRunPerTrigger()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = Database(connection);
        await db.Database.EnsureCreatedAsync();
        db.CertificateSchedules.Add(Schedule("schedule", true));
        var original = Run("original", "first-trigger", true);
        db.CertificateScheduleRuns.Add(original);
        await db.SaveChangesAsync();
        var overlapping = Run("overlapping", "second-trigger", true);
        db.CertificateScheduleRuns.Add(overlapping);
        var overlap = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        Assert.Equal(19, Assert.IsType<SqliteException>(overlap.InnerException).SqliteErrorCode);
        db.Entry(overlapping).State = EntityState.Detached;
        original.Active = false;
        await db.SaveChangesAsync();
        db.CertificateScheduleRuns.Add(overlapping);
        await db.SaveChangesAsync();
        db.CertificateScheduleRuns.Add(Run("duplicate", "first-trigger", false));
        var duplicate = await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
        Assert.Equal(19, Assert.IsType<SqliteException>(duplicate.InnerException).SqliteErrorCode);
    }

    private static AppDbContext Database(SqliteConnection connection) => new(new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite(connection).Options);

    private static CertificateSchedule Schedule(string id, bool enabled) => new()
    {
        Id = id, Name = id, AccountId = "account", Domain = "vpn.example.test", Enabled = enabled,
        FirstRunAtUtc = DateTime.UtcNow.AddMonths(1), NextRunAtUtc = DateTime.UtcNow.AddMonths(1)
    };

    private static CertificateScheduleRun Run(string id, string trigger, bool active) => new()
    {
        Id = id, ScheduleId = "schedule", TriggerKey = trigger, Active = active,
        ScheduledForUtc = DateTime.UtcNow, CreatedAtUtc = DateTime.UtcNow, NextCheckAtUtc = DateTime.UtcNow
    };

    private sealed class CleanupFixture(SqliteConnection connection, AppDbContext db,
        CleanupProvider provider, CertificateScheduleService schedules) : IAsyncDisposable
    {
        public AppDbContext Db { get; } = db;
        public CleanupProvider Provider { get; } = provider;

        public static async Task<CleanupFixture> CreateAsync(string oldStatus, bool revokeOldCertificates = true)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = Database(connection);
            await db.Database.EnsureCreatedAsync();
            var provider = new CleanupProvider { CloudStatus = oldStatus };
            var accounts = new CleanupAccounts();
            var providers = new CleanupResolver(provider);
            var ids = new GuidIdGenerator();
            var domains = new DomainManagementService(db, accounts, providers, ids);
            var certificates = new CertificateManagementService(db, accounts, providers, domains, ids);
            var protection = new EphemeralDataProtectionProvider();
            var executors = new DeploymentExecutorResolver([]);
            var targets = new DeploymentTargetService(db, executors, protection, ids);
            var deployments = new DeploymentService(db, targets, executors, new UnusedMaterials(), protection, ids);
            var schedules = new CertificateScheduleService(db, certificates, accounts, providers, deployments, targets, ids);
            var next = DateTime.UtcNow.AddMonths(1);
            var configuration = new CertificateScheduleInput
            {
                Name = "安全清理测试", AccountId = "account", Domain = "vpn.example.test", TargetIds = ["target"],
                FirstRunAtUtc = next, RevokeOldCertificates = revokeOldCertificates
            };
            db.CloudAccounts.Add(new() { Id = "account", Name = "测试账号", Provider = "TencentCloud" });
            db.Users.Add(new() { Id = "admin", Username = "admin", NormalizedUsername = "ADMIN", Role = "admin", Enabled = true });
            db.Domains.Add(new() { Id = "zone", AccountId = "account", Name = "example.test", ZoneId = "zone" });
            db.DeploymentTargets.Add(new()
            {
                Id = "target", Name = "已验证目标", ExecutorKey = "linux.files.ssh.v1", Enabled = true,
                ConfigurationJson = "{\"sourceDomain\":\"vpn.example.test\"}"
            });
            db.CertificateSchedules.Add(new()
            {
                Id = "schedule", Name = configuration.Name, AccountId = "account", Domain = configuration.Domain,
                TargetIdsJson = "[\"target\"]", FirstRunAtUtc = next, NextRunAtUtc = next, Enabled = true,
                CreatedByUserId = "admin", RevokeOldCertificates = revokeOldCertificates
            });
            db.Certificates.AddRange(new ManagedCertificate
            {
                Id = "new-cert", AccountId = "account", Provider = "TencentCloud", CertificateId = "new-cloud",
                Domain = "vpn.example.test", Status = "Issued", NotAfterUtc = DateTime.UtcNow.AddMonths(3)
            }, new ManagedCertificate
            {
                Id = "old-cert", AccountId = "account", Provider = "TencentCloud", CertificateId = "old-cloud",
                Domain = "vpn.example.test", Status = oldStatus,
                NotAfterUtc = oldStatus == "Expired" ? DateTime.UtcNow.AddDays(-1) : DateTime.UtcNow.AddDays(10)
            });
            db.DeploymentBatches.Add(new()
            {
                Id = "verified-batch", CertificateId = "new-cert", CertificateDomain = "vpn.example.test", Status = "Succeeded"
            });
            db.DeploymentTasks.Add(new()
            {
                Id = "verified-task", BatchId = "verified-batch", TargetId = "target", ResourceKey = "verified-resource",
                Status = "Succeeded", VerificationLevel = "FilesChecked"
            });
            db.DeploymentBindings.Add(new()
            {
                Id = "current-binding", TargetId = "target", ResourceKey = "verified-resource",
                CertificateId = "new-cert", LastTaskId = "verified-task"
            });
            db.CertificateScheduleRuns.Add(new()
            {
                Id = "run", ScheduleId = "schedule", TriggerKey = "cleanup-test", CertificateId = "new-cert",
                ConfigSnapshotJson = JsonSerializer.Serialize(configuration, Json), Status = "CleaningOldCertificates",
                TargetsJson = JsonSerializer.Serialize(new[] { new ScheduleTargetProgress
                {
                    TargetId = "target", TargetName = "已验证目标", BatchId = "verified-batch", Status = "Succeeded"
                } }, Json),
                OldCertificatesJson = JsonSerializer.Serialize(new[] { new ScheduleCertificateCleanup
                {
                    CertificateId = "old-cert", Domain = "vpn.example.test", Status = "Pending"
                } }, Json),
                Active = true, ScheduledForUtc = DateTime.UtcNow, CreatedAtUtc = DateTime.UtcNow,
                NextCheckAtUtc = DateTime.UtcNow.AddSeconds(-1)
            });
            await db.SaveChangesAsync();
            return new(connection, db, provider, schedules);
        }

        public async Task AdvanceAsync(int steps)
        {
            for (var step = 0; step < steps; step++)
            {
                Db.ChangeTracker.Clear();
                await Db.CertificateScheduleRuns.Where(run => run.Id == "run" && run.Active)
                    .ExecuteUpdateAsync(update => update.SetProperty(run => run.NextCheckAtUtc, DateTime.UtcNow.AddSeconds(-1)));
                await schedules.ProcessNextAsync(default);
            }
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }

    private sealed class UnusedMaterials : ICertificateMaterialService
    {
        public Task<ApiResult<CertificateMaterial>> GetAsync(string certificateId, CancellationToken ct) =>
            throw new InvalidOperationException("清理阶段不能读取或部署新材料。");
    }

    private sealed class CleanupResolver(CleanupProvider provider) : ICloudProviderResolver
    {
        public ApiResult<ICloudCertificateService> ResolveCertificate(string providerName) => ApiResult<ICloudCertificateService>.Ok(provider);
        public ApiResult<IDnsProvider> ResolveDns(string providerName) => ApiResult<IDnsProvider>.Ok(provider);
    }

    private sealed class CleanupAccounts : ICloudAccountStore
    {
        public Task<ApiResult<CloudAccountCredentials>> GetCredentialsAsync(string id, CancellationToken ct) => Task.FromResult(
            ApiResult<CloudAccountCredentials>.Ok(new(id, id, "TencentCloud", "test-key", "test-secret", true, true, true, "", "", "")));
        public Task<ApiResult<bool>> RecordTestAsync(string accountId, bool success, string code, string message, CancellationToken ct) => Task.FromResult(ApiResult<bool>.Ok(true));
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, string? search, string? provider, bool? enabled, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<CloudAccountOption>>> ListOptionsAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSummary>> CreateAsync(CloudAccountInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSummary>> UpdateAsync(string id, CloudAccountInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSecrets>> RevealSecretsAsync(string accountId, CancellationToken ct) => throw new NotSupportedException();
    }

    private sealed class CleanupProvider : ICloudCertificateService, IDnsProvider
    {
        public string Provider => "TencentCloud";
        public string CloudStatus { get; set; } = "Issued";
        public int RevokeCalls { get; private set; }
        public int DeleteCalls { get; private set; }
        public List<string> Calls { get; } = [];
        public ApiResult<CloudOperation> RevokeResult { get; set; } = ApiResult<CloudOperation>.Ok(new("revoke-request", "Revoking"));
        public ApiResult<CloudOperation> DeleteResult { get; set; } = ApiResult<CloudOperation>.Ok(new("delete-request", "Deleted"));

        public Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
        {
            Calls.Add("query");
            return Task.FromResult(ApiResult<CloudCertificateDetail>.Ok(new(new(reference, "vpn.example.test", "", CloudStatus,
                CloudStatus, true, "test", DateTimeOffset.UtcNow.AddMonths(-3),
                CloudStatus == "Expired" ? DateTimeOffset.UtcNow.AddDays(-1) : DateTimeOffset.UtcNow.AddDays(10),
                "NativeAutoDns", "read-request"), [])));
        }

        public Task<ApiResult<CloudOperation>> RevokeAsync(CloudAccountCredentials account, CloudCertificateReference reference, string reason, CancellationToken ct = default)
        {
            Calls.Add("revoke");
            RevokeCalls++;
            if (RevokeResult.Success) CloudStatus = "Revoking";
            return Task.FromResult(RevokeResult);
        }

        public Task<ApiResult<CloudOperation>> DeleteAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
        {
            Calls.Add("delete");
            DeleteCalls++;
            return Task.FromResult(DeleteResult);
        }

        public Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudConnectionTest>> TestAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default) => throw new InvalidOperationException("清理阶段不能创建新申请。");
        public Task<ApiResult<CertificateDownload>> DownloadAsync(CloudAccountCredentials account, CloudCertificateReference reference, string format, CancellationToken ct = default) => throw new InvalidOperationException("清理阶段不能下载材料。");
        public Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string recordId, DnsRecordRequest request, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string recordId, bool enabled, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string recordId, CancellationToken ct = default) => throw new NotSupportedException();
    }
}
