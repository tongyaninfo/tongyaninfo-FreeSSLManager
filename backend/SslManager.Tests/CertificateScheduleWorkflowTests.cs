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

/// <summary>只使用隔离数据库、假云接口和假执行器验证整轮持久化恢复，不申请或部署真实证书。</summary>
public sealed class CertificateScheduleWorkflowTests
{
    [Fact]
    public async Task ApplyIsLinkedBeforeCloudCallAndIssuedCertificateDeploysEachTargetOnlyOnce()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.BeforeApply = async () =>
        {
            var run = await fixture.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync();
            Assert.NotEmpty(run.CertificateId);
            Assert.True(await fixture.Db.CertificateJobs.AnyAsync(job => job.CertificateId == run.CertificateId && job.Status == "Submitting"));
        };
        var requested = await fixture.Schedules.RunNowAsync("schedule", default);
        Assert.True(requested.Success, requested.Message);
        var next = (await fixture.Db.CertificateSchedules.AsNoTracking().SingleAsync()).NextRunAtUtc;
        await fixture.StepAsync();
        var run = await fixture.RunAsync();
        Assert.Equal("WaitingForIssuance", run.Status);
        Assert.Equal(1, fixture.Provider.ApplyCalls);
        Assert.Equal("RUN_ACTIVE", (await fixture.Schedules.RunNowAsync("schedule", default)).Code);
        fixture.Provider.CurrentStatus = "Issued";
        await fixture.Certificates.ProcessJobAsync((await fixture.Db.CertificateJobs.SingleAsync()).Id, default);
        // DNS 清理任务即使尚未完成，已签发证书也必须可以进入部署。
        await fixture.Db.CertificateJobs.ExecuteUpdateAsync(update => update.SetProperty(job => job.Status, "Waiting"));
        await fixture.StepAsync();
        await fixture.StepAsync();
        run = await fixture.RunAsync();
        var progress = JsonSerializer.Deserialize<List<ScheduleTargetProgress>>(run.TargetsJson, Json)!;
        Assert.NotEmpty(Assert.Single(progress).BatchId);
        Assert.Equal("Draft", (await fixture.Db.DeploymentBatches.SingleAsync()).Status);
        await fixture.StepAsync();
        Assert.Equal("Queued", (await fixture.Db.DeploymentBatches.AsNoTracking().SingleAsync()).Status);
        await fixture.Deployments.ProcessNextAsync(default);
        for (var step = 0; step < 4; step++) await fixture.StepAsync();
        run = await fixture.RunAsync();
        Assert.Equal("Succeeded", run.Status);
        Assert.False(run.Active);
        Assert.Equal("Disabled", run.CleanupStatus);
        Assert.Equal(1, fixture.Executor.ExecuteCalls);
        Assert.Equal(1, fixture.Provider.ApplyCalls);
        Assert.Equal(next, (await fixture.Db.CertificateSchedules.AsNoTracking().SingleAsync()).NextRunAtUtc);
        Assert.Single(await fixture.Db.DeploymentBatches.ToListAsync());
        Assert.Contains(await fixture.Db.AuditLogs.ToListAsync(), audit => audit.Action == "ScheduleApplyIntent");
    }

    [Fact]
    public async Task UnknownApplicationIsNotResubmittedByWorkerOrRecheck()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Provider.ApplyFailure = ApiResult<CloudCertificateDetail>.Fail("NETWORK_ERROR", "可能已经受理");
        Assert.True((await fixture.Schedules.RunNowAsync("schedule", default)).Success);
        await fixture.StepAsync();
        var run = await fixture.RunAsync();
        Assert.Equal("NeedsAttention", run.Status);
        Assert.True(run.Active);
        Assert.Equal("SubmissionUnknown", (await fixture.Db.Certificates.SingleAsync()).Status);
        for (var step = 0; step < 3; step++) await fixture.StepAsync();
        Assert.Equal(1, fixture.Provider.ApplyCalls);
        Assert.True((await fixture.Schedules.ResumeRunAsync(run.Id, default)).Success);
        await fixture.StepAsync();
        Assert.Equal("NeedsAttention", (await fixture.RunAsync()).Status);
        Assert.Equal(1, fixture.Provider.ApplyCalls);
        Assert.Empty(await fixture.Db.DeploymentBatches.ToListAsync());
    }

    [Fact]
    public async Task ExistingUnknownReferenceResumesPollingTheSameApplicationAfterReadback()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.Schedules.RunNowAsync("schedule", default)).Success);
        await fixture.StepAsync();
        await fixture.Db.Certificates.ExecuteUpdateAsync(update => update.SetProperty(item => item.Status, "SubmissionUnknown"));
        await fixture.Db.CertificateJobs.ExecuteUpdateAsync(update => update.SetProperty(item => item.Status, "SubmissionUnknown"));
        fixture.Provider.CurrentStatus = "PendingValidation";
        await fixture.StepAsync();
        Assert.Equal("Waiting", (await fixture.Db.CertificateJobs.AsNoTracking().SingleAsync()).Status);
        Assert.Equal("PendingValidation", (await fixture.Db.Certificates.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(1, fixture.Provider.ApplyCalls);
        Assert.Equal("WaitingForIssuance", (await fixture.RunAsync()).Status);
    }

    [Fact]
    public async Task DisabledScheduleDoesNotSubmitAnAlreadyPreparedDraft()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.Schedules.RunNowAsync("schedule", default)).Success);
        await fixture.StepAsync();
        fixture.Provider.CurrentStatus = "Issued";
        await fixture.Certificates.ProcessJobAsync((await fixture.Db.CertificateJobs.SingleAsync()).Id, default);
        await fixture.StepAsync(); await fixture.StepAsync();
        Assert.Equal("Draft", (await fixture.Db.DeploymentBatches.SingleAsync()).Status);
        Assert.True((await fixture.Schedules.SetEnabledAsync("schedule", false, default)).Success);
        await fixture.StepAsync();
        Assert.Equal("Draft", (await fixture.Db.DeploymentBatches.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(0, fixture.Executor.ExecuteCalls);
        Assert.False((await fixture.RunAsync()).Active);
    }

    [Fact]
    public async Task LongRunningCycleFinishesAtAFutureAnchoredPointInsteadOfImmediatelyApplyingAgain()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.Schedules.RunNowAsync("schedule", default)).Success);
        await fixture.StepAsync();
        await fixture.Db.CertificateSchedules.ExecuteUpdateAsync(update => update
            .SetProperty(item => item.FirstRunAtUtc, DateTime.UtcNow.AddHours(-12))
            .SetProperty(item => item.IntervalUnit, "hour")
            .SetProperty(item => item.NextRunAtUtc, DateTime.UtcNow.AddHours(-10)));
        fixture.Provider.CurrentStatus = "Failed";
        await fixture.Certificates.ProcessJobAsync((await fixture.Db.CertificateJobs.SingleAsync()).Id, default);
        await fixture.StepAsync();
        Assert.False((await fixture.RunAsync()).Active);
        Assert.True((await fixture.Db.CertificateSchedules.AsNoTracking().SingleAsync()).NextRunAtUtc > DateTime.UtcNow);
        await fixture.Schedules.ProcessNextAsync(default);
        Assert.Single(await fixture.Db.CertificateScheduleRuns.ToListAsync());
        Assert.Equal(1, fixture.Provider.ApplyCalls);
    }

    [Fact]
    public async Task AliyunWithoutAnUnusedFreeInstanceNeverSubmitsAnApplication()
    {
        await using var fixture = await Fixture.CreateAsync("Aliyun");
        fixture.Provider.FreeInstances = [];
        Assert.True((await fixture.Schedules.RunNowAsync("schedule", default)).Success);
        await fixture.StepAsync();
        Assert.Equal("FREE_INSTANCE_UNAVAILABLE", (await fixture.RunAsync()).Code);
        Assert.Equal(0, fixture.Provider.ApplyCalls);
        Assert.Empty(await fixture.Db.Certificates.ToListAsync());
    }

    [Fact]
    public async Task AliyunReservationSurvivesANewContextAndSameRunNeverAppliesTwice()
    {
        await using var fixture = await Fixture.CreateAsync("Aliyun");
        var requested = await fixture.Schedules.RunNowAsync("schedule", default);
        Assert.True(requested.Success);
        var runId = requested.Data!.Id;
        await fixture.Db.CertificateScheduleRuns.Where(run => run.Id == runId).ExecuteUpdateAsync(update => update
            .SetProperty(run => run.LeaseToken, "first-lease").SetProperty(run => run.LeaseUntilUtc, DateTime.UtcNow.AddMinutes(5)));
        fixture.Db.ChangeTracker.Clear();
        var request = new CertificateApplyRequest("account", "vpn.example.test", ValidationMode: "ManagedDns", AutoCleanup: false);
        var first = await fixture.Certificates.ApplyForScheduleAsync(request, runId, "first-lease", ["only-free-instance"], default);
        Assert.True(first.Success, first.Message);
        Assert.Equal("only-free-instance", first.Data!.InstanceId);

        // 使用全新 DbContext 和证书服务；预约依据数据库持久记录，不依赖该服务的内存状态。
        await using var secondDb = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(fixture.Connection).Options);
        secondDb.CertificateSchedules.Add(new()
        {
            Id = "second-schedule", Name = "第二域名", AccountId = "account", Domain = "other.example.test", Enabled = true,
            FirstRunAtUtc = DateTime.UtcNow.AddMonths(1), NextRunAtUtc = DateTime.UtcNow.AddMonths(1)
        });
        secondDb.CertificateScheduleRuns.Add(new()
        {
            Id = "second-run", ScheduleId = "second-schedule", TriggerKey = "reservation", LeaseToken = "second-lease",
            LeaseUntilUtc = DateTime.UtcNow.AddMinutes(5), NextCheckAtUtc = DateTime.UtcNow
        });
        await secondDb.SaveChangesAsync();
        var ids = new GuidIdGenerator(); var accounts = new FakeAccounts("Aliyun"); var providers = new FakeResolver(fixture.Provider);
        var secondCertificates = new CertificateManagementService(secondDb, accounts, providers,
            new DomainManagementService(secondDb, accounts, providers, ids), ids);
        var second = await secondCertificates.ApplyForScheduleAsync(request with { Domain = "other.example.test" },
            "second-run", "second-lease", ["only-free-instance"], default);
        Assert.Equal("FREE_INSTANCE_UNAVAILABLE", second.Code);
        var replay = await secondCertificates.ApplyForScheduleAsync(request, runId, "first-lease", ["only-free-instance"], default);
        Assert.True(replay.Success, replay.Message);
        Assert.Equal(first.Data.Id, replay.Data!.Id);
        Assert.Equal(1, fixture.Provider.ApplyCalls);
        Assert.Single(await secondDb.Certificates.ToListAsync());
    }

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task RestartRebuildsExpiredDraftUsingTheSameCertificateAndBatch()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.PrepareDraftAsync();
        var certificateId = (await fixture.RunAsync()).CertificateId;
        var batchId = (await fixture.Db.DeploymentBatches.AsNoTracking().SingleAsync()).Id;
        await fixture.Db.DeploymentBatches.ExecuteUpdateAsync(update => update.SetProperty(batch => batch.ExpiresAtUtc, DateTime.UtcNow.AddHours(-1)));
        await using var restarted = fixture.Restart();
        await restarted.StepAsync();
        Assert.Equal("Queued", (await restarted.Db.DeploymentBatches.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(batchId, (await restarted.Db.DeploymentBatches.AsNoTracking().SingleAsync()).Id);
        Assert.Equal(certificateId, (await restarted.RunAsync()).CertificateId);
        await restarted.Deployments.ProcessNextAsync(default);
        for (var step = 0; step < 5; step++) await restarted.StepAsync();
        Assert.Equal("Succeeded", (await restarted.RunAsync()).Status);
        Assert.Equal(1, restarted.Provider.ApplyCalls);
        Assert.Equal(1, restarted.Executor.ExecuteCalls);
    }

    [Fact]
    public async Task ChangedTargetConfigurationBeforeDeploymentCannotExpandTheOriginalRun()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.Schedules.RunNowAsync("schedule", default); await fixture.StepAsync();
        await fixture.Db.DeploymentTargets.ExecuteUpdateAsync(update => update.SetProperty(target => target.ConfigRevision, 2));
        fixture.Provider.CurrentStatus = "Issued";
        await fixture.Certificates.ProcessJobAsync((await fixture.Db.CertificateJobs.SingleAsync()).Id, default);
        for (var step = 0; step < 3; step++) await fixture.StepAsync();
        Assert.Equal("Failed", (await fixture.RunAsync()).Status);
        Assert.Empty(await fixture.Db.DeploymentBatches.ToListAsync());
        Assert.Equal(0, fixture.Executor.ExecuteCalls);
        Assert.Equal(1, fixture.Provider.ApplyCalls);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task LegacyTargetRevisionRequiresEvidenceThatTheConfigurationPredatesTheRun(bool changed)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.Schedules.RunNowAsync("schedule", default); await fixture.StepAsync();
        var run = await fixture.RunAsync();
        var progress = JsonSerializer.Deserialize<List<ScheduleTargetProgress>>(run.TargetsJson, Json)!;
        progress.Single().ConfigRevision = 0;
        var json = JsonSerializer.Serialize(progress, Json);
        await fixture.Db.CertificateScheduleRuns.ExecuteUpdateAsync(update => update.SetProperty(item => item.TargetsJson, json));
        if (changed) await fixture.Db.DeploymentTargets.ExecuteUpdateAsync(update => update
            .SetProperty(item => item.ConfigRevision, 2).SetProperty(item => item.UpdatedAtUtc, DateTime.UtcNow.AddMinutes(1)));
        fixture.Provider.CurrentStatus = "Issued";
        await fixture.Certificates.ProcessJobAsync((await fixture.Db.CertificateJobs.SingleAsync()).Id, default);
        await using var restarted = fixture.Restart();
        for (var step = 0; step < 3; step++) await restarted.StepAsync();
        if (changed)
        {
            Assert.Equal("TARGET_REVISION_UNCONFIRMED", (await restarted.RunAsync()).Code);
            Assert.Empty(await restarted.Db.DeploymentBatches.ToListAsync());
        }
        else Assert.Equal("Queued", (await restarted.Db.DeploymentBatches.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(1, restarted.Provider.ApplyCalls);
        Assert.Equal(0, restarted.Executor.ExecuteCalls);
    }

    [Fact]
    public async Task RestartRebuildsExpiredQueuedMaterialWithoutASecondApplicationOrTask()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.PrepareDraftAsync(); await fixture.StepAsync();
        var original = await fixture.Db.DeploymentTasks.AsNoTracking().SingleAsync();
        await fixture.Db.DeploymentMaterialSnapshots.ExecuteUpdateAsync(update => update.SetProperty(snapshot => snapshot.ExpiresAtUtc, DateTime.UtcNow.AddDays(-1)));
        await using var restarted = fixture.Restart();
        await restarted.StepAsync();
        var renewed = await restarted.Db.DeploymentTasks.AsNoTracking().SingleAsync();
        Assert.Equal(original.Id, renewed.Id);
        Assert.NotEqual(original.MaterialSnapshotId, renewed.MaterialSnapshotId);
        await restarted.Deployments.ProcessNextAsync(default);
        for (var step = 0; step < 5; step++) await restarted.StepAsync();
        Assert.Equal("Succeeded", (await restarted.RunAsync()).Status);
        Assert.Equal(1, restarted.Provider.ApplyCalls);
        Assert.Equal(1, restarted.Executor.ExecuteCalls);
        Assert.Single(await restarted.Db.DeploymentTasks.ToListAsync());
    }

    [Fact]
    public async Task InterruptedRunIsAutomaticallyResumedAfterANewServiceScope()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.Schedules.RunNowAsync("schedule", default); await fixture.StepAsync();
        var certificateId = (await fixture.RunAsync()).CertificateId;
        await fixture.Db.CertificateScheduleRuns.ExecuteUpdateAsync(update => update
            .SetProperty(run => run.Status, "NeedsAttention").SetProperty(run => run.Code, "SCHEDULE_STEP_INTERRUPTED"));
        await using var restarted = fixture.Restart();
        restarted.Provider.CurrentStatus = "Issued";
        await restarted.Certificates.ProcessJobAsync((await restarted.Db.CertificateJobs.SingleAsync()).Id, default);
        for (var step = 0; step < 3; step++) await restarted.StepAsync();
        await restarted.Deployments.ProcessNextAsync(default);
        for (var step = 0; step < 5; step++) await restarted.StepAsync();
        Assert.Equal("Succeeded", (await restarted.RunAsync()).Status);
        Assert.Equal(certificateId, (await restarted.RunAsync()).CertificateId);
        Assert.Equal(1, restarted.Provider.ApplyCalls);
    }

    [Fact]
    public async Task InterruptedRemoteDeploymentIsInspectedBeforeBeingCompleted()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.PrepareDraftAsync(); await fixture.StepAsync();
        await fixture.Db.DeploymentTasks.ExecuteUpdateAsync(update => update
            .SetProperty(task => task.Status, "Running").SetProperty(task => task.LeaseId, "stopped-process")
            .SetProperty(task => task.LeaseUntilUtc, DateTime.UtcNow.AddMinutes(-1)));
        await using var restarted = fixture.Restart();
        await restarted.StepAsync();
        await restarted.Deployments.ProcessNextAsync(default);
        for (var step = 0; step < 5; step++) await restarted.StepAsync();
        Assert.Equal("Succeeded", (await restarted.RunAsync()).Status);
        Assert.Equal(1, restarted.Executor.RecoveryCalls);
        Assert.Equal(0, restarted.Executor.ExecuteCalls);
        Assert.Equal(1, restarted.Provider.ApplyCalls);
        Assert.Single(await restarted.Db.DeploymentBindings.ToListAsync());
    }

    [Fact]
    public async Task RecoveryMetadataDoesNotChangeTheDatabaseModel()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.False(fixture.Db.Database.HasPendingModelChanges());
    }

    [Fact]
    public async Task ApplicationDnsCleanupSurvivesRestartAndMustFinishBeforeTheRunCompletes()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.Db.CertificateSchedules.ExecuteUpdateAsync(update => update
            .SetProperty(schedule => schedule.AutoCleanup, true).SetProperty(schedule => schedule.ValidationMode, "ManagedDns"));
        await fixture.Schedules.RunNowAsync("schedule", default); await fixture.StepAsync();
        var certificateId = (await fixture.RunAsync()).CertificateId;
        fixture.Db.ValidationRecords.Add(new()
        {
            Id = "application-validation", CertificateId = certificateId, Domain = "vpn.example.test",
            Name = "_dnsauth.vpn.example.test", Type = "TXT", Value = "private-challenge",
            DnsZoneId = "zone", RecordId = "dns-record", CreatedBySystem = true, Status = "Created"
        });
        await fixture.Db.SaveChangesAsync();
        fixture.Provider.DnsRecords.Add(new("dns-record", "example.test", "_dnsauth.vpn", "TXT", "private-challenge", 600, "Enabled", "default", "read"));
        fixture.Provider.DelayDnsDeletion = true;
        fixture.Provider.CurrentStatus = "Issued";
        await fixture.Certificates.ProcessJobAsync((await fixture.Db.CertificateJobs.SingleAsync()).Id, default);
        for (var step = 0; step < 3; step++) await fixture.StepAsync();
        await fixture.Deployments.ProcessNextAsync(default);
        for (var step = 0; step < 3; step++) await fixture.StepAsync();
        Assert.True((await fixture.RunAsync()).Active);
        var view = (await fixture.Schedules.ListRunsAsync("schedule", 1, 10, default)).Data!.Items.Single();
        Assert.Equal("Running", view.ApplicationCleanupStatus);
        Assert.DoesNotContain("private-challenge", JsonSerializer.Serialize(view, Json));
        await using var restarted = fixture.Restart();
        restarted.Provider.DelayDnsDeletion = false;
        for (var step = 0; step < 6; step++) await restarted.StepAsync();
        Assert.Equal("Succeeded", (await restarted.RunAsync()).Status);
        Assert.Empty(restarted.Provider.DnsRecords);
        Assert.Equal(1, restarted.Provider.ApplyCalls);
        Assert.Equal(1, restarted.Executor.ExecuteCalls);
    }

    [Fact]
    public async Task MissingHistoricalBindingAutomaticallyRechecksAfterATemporaryNetworkFailure()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.PrepareDraftAsync(); await fixture.StepAsync();
        await fixture.Deployments.ProcessNextAsync(default); await fixture.StepAsync();
        // 保留原绑定历史行，仅模拟待修复资源的绑定尚未保存。
        await fixture.Db.DeploymentBindings.ExecuteUpdateAsync(update => update.SetProperty(binding => binding.ResourceKey, "other-resource"));
        fixture.Executor.InspectionFailuresRemaining = 1;
        await using var restarted = fixture.Restart();
        await restarted.StepAsync();
        Assert.Equal("CleaningOldCertificates", (await restarted.RunAsync()).Status);
        Assert.True((await restarted.RunAsync()).Active);
        await restarted.StepAsync();
        Assert.Equal("Succeeded", (await restarted.RunAsync()).Status);
        Assert.Equal(1, restarted.Provider.ApplyCalls);
        Assert.Equal(1, restarted.Executor.ExecuteCalls);
    }

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, FakeCloud provider,
        CertificateManagementService certificates, DeploymentService deployments, CertificateScheduleService schedules,
        FakeExecutor executor, IDataProtectionProvider protection) : IAsyncDisposable
    {
        public AppDbContext Db => db;
        public FakeCloud Provider => provider;
        public CertificateManagementService Certificates => certificates;
        public DeploymentService Deployments => deployments;
        public CertificateScheduleService Schedules => schedules;
        public FakeExecutor Executor => executor;
        public SqliteConnection Connection => connection;

        public static async Task<Fixture> CreateAsync(string providerName = "TencentCloud")
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            var cloud = new FakeCloud { ProviderName = providerName }; var accounts = new FakeAccounts(providerName); var providers = new FakeResolver(cloud); var ids = new GuidIdGenerator();
            var domains = new DomainManagementService(db, accounts, providers, ids);
            var certificates = new CertificateManagementService(db, accounts, providers, domains, ids);
            var executor = new FakeExecutor(); var resolver = new DeploymentExecutorResolver([executor]); var protection = new EphemeralDataProtectionProvider();
            var targets = new DeploymentTargetService(db, resolver, protection, ids);
            var deployments = new DeploymentService(db, targets, resolver, new FakeMaterials(), protection, ids);
            var schedules = new CertificateScheduleService(db, certificates, accounts, providers, deployments, targets, ids);
            db.CloudAccounts.Add(new() { Id = "account", Name = "自动化测试账号", Provider = providerName });
            db.Domains.Add(new() { Id = "zone", AccountId = "account", Name = "example.test", ZoneId = "zone" });
            await db.SaveChangesAsync();
            var target = await targets.SaveAsync(null, new()
            {
                Name = "测试目标", ExecutorKey = executor.Descriptor.Key, Endpoint = "target.example.test", Username = "user", Password = "fake-password",
                Configuration = new() { SourceDomain = "vpn.example.test" }
            }, default);
            Assert.True(target.Success, target.Message);
            db.CertificateSchedules.Add(new()
            {
                Id = "schedule", Name = "测试周期", AccountId = "account", Domain = "vpn.example.test", ValidationMode = "NativeAutoDns",
                AutoCleanup = false, RevokeOldCertificates = false, TargetIdsJson = JsonSerializer.Serialize(new[] { target.Data!.Id }),
                FirstRunAtUtc = DateTime.UtcNow.AddMonths(1), NextRunAtUtc = DateTime.UtcNow.AddMonths(1), CreatedByUserId = "admin"
            });
            await db.SaveChangesAsync();
            return new(connection, db, cloud, certificates, deployments, schedules, executor, protection);
        }
        // 使用全新 DbContext/服务模拟进程重启；数据库、远端替身及持久密钥保持不变。
        public Fixture Restart()
        {
            var database = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            var accounts = new FakeAccounts(provider.ProviderName); var providers = new FakeResolver(provider); var ids = new GuidIdGenerator();
            var certificates = new CertificateManagementService(database, accounts, providers, new DomainManagementService(database, accounts, providers, ids), ids);
            var resolver = new DeploymentExecutorResolver([executor]);
            var targets = new DeploymentTargetService(database, resolver, protection, ids);
            var deployments = new DeploymentService(database, targets, resolver, new FakeMaterials(), protection, ids);
            return new(connection, database, provider, certificates, deployments,
                new CertificateScheduleService(database, certificates, accounts, providers, deployments, targets, ids), executor, protection);
        }
        public async Task PrepareDraftAsync()
        {
            Assert.True((await Schedules.RunNowAsync("schedule", default)).Success);
            await StepAsync(); Provider.CurrentStatus = "Issued";
            await Certificates.ProcessJobAsync((await Db.CertificateJobs.SingleAsync()).Id, default);
            await StepAsync(); await StepAsync();
            Assert.Equal("Draft", (await Db.DeploymentBatches.AsNoTracking().SingleAsync()).Status);
        }
        public Task<CertificateScheduleRun> RunAsync() => Db.CertificateScheduleRuns.AsNoTracking().SingleAsync();
        public async Task StepAsync()
        {
            Db.ChangeTracker.Clear();
            await Db.CertificateScheduleRuns.Where(item => item.Active).ExecuteUpdateAsync(update => update.SetProperty(item => item.NextCheckAtUtc, DateTime.UtcNow.AddSeconds(-1)));
            await Schedules.ProcessNextAsync(default);
        }
        public async ValueTask DisposeAsync() { await Db.DisposeAsync(); await connection.DisposeAsync(); }
    }

    private sealed class FakeMaterials : ICertificateMaterialService
    {
        public Task<ApiResult<CertificateMaterial>> GetAsync(string id, CancellationToken ct) => Task.FromResult(ApiResult<CertificateMaterial>.Ok(new()
        {
            Metadata = new(id, "vpn.example.test", ["vpn.example.test"], "fingerprint", "digest", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddMonths(3)),
            CertificatePem = "certificate", FullChainPem = "chain", PrivateKeyPem = "private"
        }));
    }
    private sealed class FakeExecutor : IDeploymentExecutor, IDeploymentRecoveryExecutor
    {
        public DeploymentExecutorDescriptor Descriptor => new("linux.files.ssh.v1", "测试 Linux", "Fake", "Linux", "SSH", AuthenticationModes: ["Password"]);
        public int ExecuteCalls { get; private set; }
        public int RecoveryCalls { get; private set; }
        public int InspectionFailuresRemaining { get; set; }
        public Task<ApiResult<DeploymentRecoveryResult>> RecoverAsync(DeploymentExecutionContext context, CancellationToken ct)
        {
            RecoveryCalls++;
            return Task.FromResult(ApiResult<DeploymentRecoveryResult>.Ok(new("Completed", "原远端结果已核对", new("恢复核对完成", "remote", context.Material.Metadata.Fingerprint, "FilesChecked"))));
        }
        public Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target, CertificateMaterialMetadata material, DeploymentSelection selection, CancellationToken ct) =>
            Task.FromResult(ApiResult<DeploymentTargetPlan>.Ok(new("resource:" + target.Id, "Replace", "测试预检", "{}")));
        public Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct)
        { ExecuteCalls++; return Task.FromResult(ApiResult<DeploymentExecutionResult>.Ok(new("已核对", "remote", context.Material.Metadata.Fingerprint, "FilesChecked"))); }
        public Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct) => Task.FromResult(
            InspectionFailuresRemaining-- > 0 ? ApiResult<DeploymentInspection>.Fail("NETWORK_ERROR", "查询暂不可用") :
                ApiResult<DeploymentInspection>.Ok(new(true, "已核对", context.Material.Fingerprint, "FilesChecked")));
        public Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct) => Task.FromResult(ApiResult<DeploymentConnectionTest>.Ok(new("test", "可连接")));
    }
    private sealed class FakeResolver(FakeCloud cloud) : ICloudProviderResolver
    {
        public ApiResult<ICloudCertificateService> ResolveCertificate(string provider) => ApiResult<ICloudCertificateService>.Ok(cloud);
        public ApiResult<IDnsProvider> ResolveDns(string provider) => ApiResult<IDnsProvider>.Ok(cloud);
    }
    private sealed class FakeAccounts(string providerName = "TencentCloud") : ICloudAccountStore
    {
        public Task<ApiResult<CloudAccountCredentials>> GetCredentialsAsync(string id, CancellationToken ct) => Task.FromResult(ApiResult<CloudAccountCredentials>.Ok(new(id, id, providerName, "test-key", "test-secret", true, true, true, "", "", "")));
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, string? search, string? provider, bool? enabled, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<CloudAccountOption>>> ListOptionsAsync(CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSummary>> CreateAsync(CloudAccountInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSummary>> UpdateAsync(string id, CloudAccountInput input, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<CloudAccountSecrets>> RevealSecretsAsync(string id, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<bool>> RecordTestAsync(string id, bool success, string code, string message, CancellationToken ct) => throw new NotSupportedException();
    }
    private sealed class FakeCloud : ICloudCertificateService, IDnsProvider
    {
        public string ProviderName { get; set; } = "TencentCloud";
        public string Provider => ProviderName;
        public string CurrentStatus { get; set; } = "PendingValidation";
        public int ApplyCalls { get; private set; }
        public bool DelayDnsDeletion { get; set; }
        public List<DnsRecord> DnsRecords { get; } = [];
        public Func<Task>? BeforeApply { get; set; }
        public ApiResult<CloudCertificateDetail>? ApplyFailure { get; set; }
        public IReadOnlyList<AliyunCertificateInstanceOption> FreeInstances { get; set; } = [new("only-free-instance", "免费实例", "", "inactive", "free")];
        public Task<ApiResult<IReadOnlyList<AliyunCertificateInstanceOption>>> ListAliyunInstancesAsync(CloudAccountCredentials account, CancellationToken ct = default) => Task.FromResult(ApiResult<IReadOnlyList<AliyunCertificateInstanceOption>>.Ok(FreeInstances));
        public async Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default)
        { ApplyCalls++; if (BeforeApply is not null) await BeforeApply(); return ApplyFailure ?? Detail(new("cloud-cert")); }
        public Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default) => Task.FromResult(Detail(reference));
        private ApiResult<CloudCertificateDetail> Detail(CloudCertificateReference reference) => ApiResult<CloudCertificateDetail>.Ok(new(new(reference, "vpn.example.test", "", CurrentStatus, CurrentStatus, true, "test", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddMonths(3), "ManagedDns", "request"), []));
        public Task<ApiResult<CloudConnectionTest>> TestAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudOperation>> RevokeAsync(CloudAccountCredentials account, CloudCertificateReference reference, string reason, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CertificateDownload>> DownloadAsync(CloudAccountCredentials account, CloudCertificateReference reference, string format, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default) =>
            Task.FromResult(ApiResult<IReadOnlyList<DnsRecord>>.Ok(DnsRecords.ToArray()));
        public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string id, DnsRecordRequest request, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string id, bool enabled, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string id, CancellationToken ct = default)
        {
            if (!DelayDnsDeletion) DnsRecords.RemoveAll(record => record.Id == id);
            return Task.FromResult(ApiResult<CloudOperation>.Ok(new("delete", "Deleted")));
        }
    }
}
