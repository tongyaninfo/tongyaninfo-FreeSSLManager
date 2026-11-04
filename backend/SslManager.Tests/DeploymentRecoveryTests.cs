using System.Text.Json;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Deployment;

namespace SslManager.Tests;

/// <summary>只用内存数据库和假远端验证重启恢复，不启动 API 或操作真实证书。</summary>
public sealed class DeploymentRecoveryTests
{
    [Fact]
    public async Task ExpiredDraftRebuildsOriginalBatchAndKeepsCallerRunTracked()
    {
        await using var f = await Fixture.CreateAsync();
        await f.Db.DeploymentBatches.ExecuteUpdateAsync(update => update.SetProperty(x => x.ExpiresAtUtc, DateTime.UtcNow.AddMinutes(-1)));
        var run = await f.Db.CertificateScheduleRuns.SingleAsync();
        var result = await f.Service.RecoverForScheduleAsync(f.Plan.BatchId, "run", "run-lease", default);
        Assert.True(result.Success, result.Message);
        Assert.Equal(f.Plan.BatchId, result.Data!.Id);
        Assert.Equal(2, result.Data.PlanRevision);
        Assert.Equal("Draft", result.Data.Status);
        Assert.NotEqual(EntityState.Detached, f.Db.Entry(run).State);
        Assert.Single(await f.Db.DeploymentBatches.ToListAsync());
        Assert.Single(await f.Db.Certificates.ToListAsync());
        Assert.Single(await f.Db.AuditLogs.Where(x => x.Action == "ScheduleDeploymentRebuilt").ToListAsync());
        Assert.Equal(0, f.Executor.ExecuteCalls);
    }

    [Fact]
    public async Task MissingMaterialDownloadsOnlyTheOriginalCertificateAndRejectsChangedIdentity()
    {
        await using var f = await Fixture.CreateAsync();
        // 模拟快照引用缺失，保留所有原历史行，测试不会删除任何文件或记录。
        await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update.SetProperty(x => x.MaterialSnapshotId, "missing"));
        f.Materials.Fingerprint = "another-certificate";
        var result = await f.Service.RecoverForScheduleAsync(f.Plan.BatchId, "run", "run-lease", default);
        Assert.Equal("MATERIAL_IDENTITY_CHANGED", result.Code);
        Assert.Equal("cert", f.Materials.LastCertificateId);
        Assert.Equal(0, f.Executor.ExecuteCalls);
        Assert.Single(await f.Db.Certificates.ToListAsync());
    }

    [Fact]
    public async Task QueuedExpiredMaterialIsRebuiltWithoutChangingBatchOrCallingCloudAgain()
    {
        await using var f = await Fixture.CreateAsync();
        await f.QueueAsync();
        var originalDownloads = f.Materials.Downloads;
        var oldSnapshot = (await f.Db.DeploymentTasks.AsNoTracking().SingleAsync()).MaterialSnapshotId;
        await f.Db.DeploymentMaterialSnapshots.ExecuteUpdateAsync(update => update.SetProperty(x => x.ExpiresAtUtc, DateTime.UtcNow.AddDays(-1)));
        Assert.True(await f.Service.ProcessNextAsync(default));
        var task = await f.Db.DeploymentTasks.AsNoTracking().SingleAsync();
        Assert.Equal("Succeeded", task.Status);
        Assert.NotEqual(oldSnapshot, task.MaterialSnapshotId);
        Assert.Equal(f.Plan.BatchId, task.BatchId);
        Assert.Equal(originalDownloads, f.Materials.Downloads);
        Assert.Equal(1, f.Executor.ExecuteCalls);
        Assert.Single(await f.Db.DeploymentBindings.ToListAsync());
    }

    [Fact]
    public async Task InterruptedRunningTaskInspectsAndCompletesWithoutExecutingAgain()
    {
        await using var f = await Fixture.CreateAsync();
        await f.QueueAsync();
        await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Running")
            .SetProperty(x => x.LeaseId, "old-worker").SetProperty(x => x.LeaseUntilUtc, DateTime.UtcNow.AddMinutes(-1))
            .SetProperty(x => x.ReceiptJson, "{\"remoteId\":\"written-before-crash\"}"));
        Assert.True(await f.Service.ProcessNextAsync(default));
        var task = await f.Db.DeploymentTasks.AsNoTracking().SingleAsync();
        Assert.Equal("Succeeded", task.Status);
        Assert.Equal(0, f.Executor.ExecuteCalls);
        Assert.Equal(1, f.Executor.RecoveryCalls);
        Assert.Contains("written-before-crash", f.Executor.ReceiptUsed);
        Assert.Equal(task.Id, (await f.Db.DeploymentBindings.AsNoTracking().SingleAsync()).LastTaskId);
        Assert.Contains("checkpoint", task.ReceiptJson);
    }

    [Theory]
    [InlineData("Retry", "Recovering")]
    [InlineData("Blocked", "NeedsAttention")]
    public async Task RecoveryRetainsUnknownResultsAndDoesNotReplay(string disposition, string expectedStatus)
    {
        await using var f = await Fixture.CreateAsync();
        await f.QueueAsync();
        f.Executor.Disposition = disposition;
        await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Running")
            .SetProperty(x => x.LeaseUntilUtc, DateTime.UtcNow.AddMinutes(-1)));
        Assert.True(await f.Service.ProcessNextAsync(default));
        Assert.Equal(expectedStatus, (await f.Db.DeploymentTasks.AsNoTracking().SingleAsync()).Status);
        Assert.False(await f.Service.ProcessNextAsync(default));
        Assert.Equal(0, f.Executor.ExecuteCalls);
        Assert.Equal(1, f.Executor.RecoveryCalls);
        Assert.Empty(await f.Db.DeploymentBindings.ToListAsync());
    }

    [Fact]
    public async Task RecoveryCannotWriteAfterItsLeaseWasReplaced()
    {
        await using var f = await Fixture.CreateAsync();
        await f.QueueAsync();
        await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Running")
            .SetProperty(x => x.LeaseUntilUtc, DateTime.UtcNow.AddMinutes(-1)));
        f.Executor.BeforeCheckpoint = async () => await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update
            .SetProperty(x => x.Status, "Resolved").SetProperty(x => x.LeaseId, "new-owner"));
        await f.Service.ProcessNextAsync(default);
        Assert.Equal("Resolved", (await f.Db.DeploymentTasks.AsNoTracking().SingleAsync()).Status);
        Assert.Empty(await f.Db.DeploymentBindings.ToListAsync());
    }

    [Fact]
    public async Task RecoveryRequiresTheOriginalRunAssociationAndCurrentLease()
    {
        await using var f = await Fixture.CreateAsync();
        var result = await f.Service.RecoverForScheduleAsync(f.Plan.BatchId, "run", "stale-lease", default);
        Assert.Equal("SCHEDULE_LEASE_LOST", result.Code);
        Assert.Equal(0, f.Executor.RecoveryCalls);
    }

    [Fact]
    public async Task ExpiredDraftCannotAdoptAnOperatorsNewRemoteBaseline()
    {
        await using var f = await Fixture.CreateAsync();
        await f.Db.DeploymentBatches.ExecuteUpdateAsync(update => update.SetProperty(x => x.ExpiresAtUtc, DateTime.UtcNow.AddMinutes(-1)));
        f.Executor.RemoteVersion = 2;
        var result = await f.Service.RecoverForScheduleAsync(f.Plan.BatchId, "run", "run-lease", default);
        Assert.Equal("RECOVERY_CONFLICT", result.Code);
        Assert.Equal(1, (await f.Db.DeploymentBatches.AsNoTracking().SingleAsync()).PlanRevision);
        Assert.Equal(0, f.Executor.ExecuteCalls);
    }

    [Fact]
    public async Task LateRunnerCannotReplaceANewerBindingEvenWhenLatestOriginalStatusIsSucceeded()
    {
        await using var f = await Fixture.CreateAsync();
        await f.QueueAsync();
        f.Executor.BeforeExecuteReturn = async () =>
        {
            var original = await f.Db.DeploymentTasks.AsNoTracking().SingleAsync();
            await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Succeeded").SetProperty(x => x.LeaseId, "new-owner"));
            f.Db.DeploymentBindings.Add(new() { Id = "later-binding", TargetId = original.TargetId, ResourceKey = original.ResourceKey,
                LastTaskId = "later-task", CertificateId = "later-certificate", Fingerprint = "later-fingerprint" });
            await f.Db.SaveChangesAsync();
        };
        await f.Service.ProcessNextAsync(default);
        var binding = await f.Db.DeploymentBindings.AsNoTracking().SingleAsync();
        Assert.Equal("later-task", binding.LastTaskId);
        Assert.Equal("later-certificate", binding.CertificateId);
    }

    [Fact]
    public async Task CancellingRecoveryStopsAutomaticProgressAndProtectsTheUnknownRemoteResource()
    {
        await using var f = await Fixture.CreateAsync();
        await f.QueueAsync();
        await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Recovering")
            .SetProperty(x => x.ReceiptJson, "{\"remoteId\":\"already-uploaded\"}"));
        var task = await f.Db.DeploymentTasks.AsNoTracking().SingleAsync();
        var cancelled = await f.Service.CancelAsync(task.Id, default);
        Assert.True(cancelled.Success);
        Assert.Equal("NeedsAttention", cancelled.Data!.Status);
        Assert.Equal("CANCELLED_NEEDS_ATTENTION", cancelled.Data.Code);
        Assert.True(cancelled.Data.CancelRequested);
        await f.Service.RecoverForScheduleAsync(f.Plan.BatchId, "run", "run-lease", default);
        Assert.False(await f.Service.ProcessNextAsync(default));
        Assert.Equal(0, f.Executor.RecoveryCalls);
        Assert.Contains("already-uploaded", (await f.Db.DeploymentTasks.AsNoTracking().SingleAsync()).ReceiptJson);
    }

    [Fact]
    public async Task OldRecoveryCannotRunCommandsOrReclaimBindingAfterANewerTaskUsingTheSameCertificate()
    {
        await using var f = await Fixture.CreateAsync();
        await f.QueueAsync();
        var old = await f.Db.DeploymentTasks.AsNoTracking().SingleAsync();
        await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Recovering"));
        f.Db.DeploymentTasks.Add(new() { Id = "later-task", BatchId = f.Plan.BatchId, TargetId = old.TargetId, ResourceKey = old.ResourceKey,
            Status = "Succeeded", CreatedAtUtc = old.CreatedAtUtc.AddSeconds(1), Fingerprint = old.Fingerprint });
        f.Db.DeploymentBindings.Add(new() { Id = "later-binding", TargetId = old.TargetId, ResourceKey = old.ResourceKey,
            LastTaskId = "later-task", CertificateId = "cert", Fingerprint = old.Fingerprint });
        await f.Db.SaveChangesAsync();
        await f.Service.ProcessNextAsync(default);
        Assert.Equal(0, f.Executor.RecoveryCalls);
        Assert.Equal("later-task", (await f.Db.DeploymentBindings.AsNoTracking().SingleAsync()).LastTaskId);
        var stopped = await f.Db.DeploymentTasks.AsNoTracking().SingleAsync(x => x.Id == old.Id);
        Assert.Equal("NeedsAttention", stopped.Status);
        Assert.Equal("RECOVERY_CONFLICT", stopped.Code);
    }

    [Fact]
    public async Task HistoricalSuccessCannotRepairBindingFromOnlyALeafCertificateInspection()
    {
        await using var f = await Fixture.CreateAsync();
        f.Executor.InspectionLevel = "FileCertificateReadback";
        await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Succeeded").SetProperty(x => x.Code, "OK")
            .SetProperty(x => x.FinishedAtUtc, DateTime.UtcNow).SetProperty(x => x.VerificationLevel, "FilesChecked"));
        await f.Service.RecoverForScheduleAsync(f.Plan.BatchId, "run", "run-lease", default);
        Assert.Empty(await f.Db.DeploymentBindings.ToListAsync());
    }

    [Fact]
    public async Task MissingSourceSnapshotCannotMixAnOldActivatedContainerWithANewPasswordPackage()
    {
        await using var f = await Fixture.CreateAsync(source: true);
        await f.QueueAsync();
        static string Hash(string text) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
        var receipt = new RemoteFileDeploymentService.FileDeploymentReceipt("fingerprint",
            [new("/ssl/server.pfx", "/ssl/server.pfx.backup", "/ssl/server.pfx.stage", false, "", Hash("original-container")),
             new("/ssl/password.txt", "/ssl/password.txt.backup", "/ssl/password.txt.stage", false, "", Hash("original-password"))]);
        var json = JsonSerializer.Serialize(receipt);
        await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update.SetProperty(x => x.MaterialSnapshotId, "missing")
            .SetProperty(x => x.ReceiptJson, json));
        f.Materials.SourceVersion = "changed";
        var result = await f.Service.RecoverForScheduleAsync(f.Plan.BatchId, "run", "run-lease", default);
        Assert.Equal("MATERIAL_IDENTITY_CHANGED", result.Code);
        Assert.Equal(0, f.Executor.ExecuteCalls);
        Assert.Single(await f.Db.DeploymentBatches.ToListAsync());
    }

    [Fact]
    public async Task EndedScheduleRunStopsRecoveryBeforeAnyExecutorAction()
    {
        await using var f = await Fixture.CreateAsync();
        await f.QueueAsync();
        await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Recovering"));
        await f.Db.CertificateScheduleRuns.ExecuteUpdateAsync(update => update.SetProperty(x => x.Active, false));
        await f.Service.ProcessNextAsync(default);
        var task = await f.Db.DeploymentTasks.AsNoTracking().SingleAsync();
        Assert.Equal("SCHEDULE_RUN_ENDED", task.Code);
        Assert.Equal("NeedsAttention", task.Status);
        Assert.Equal(0, f.Executor.RecoveryCalls);
    }

    [Fact]
    public async Task EndingRunDuringRecoveryRejectsTheNextCheckpointAndStopsFurtherWrites()
    {
        await using var f = await Fixture.CreateAsync();
        await f.QueueAsync();
        await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Recovering"));
        f.Executor.BeforeCheckpoint = async () => await f.Db.CertificateScheduleRuns.ExecuteUpdateAsync(update => update.SetProperty(x => x.Active, false));
        await f.Service.ProcessNextAsync(default);
        var task = await f.Db.DeploymentTasks.AsNoTracking().SingleAsync();
        Assert.Equal("SCHEDULE_RUN_ENDED", task.Code);
        Assert.DoesNotContain("checkpoint", task.ReceiptJson);
        Assert.Empty(await f.Db.DeploymentBindings.ToListAsync());
    }

    [Fact]
    public async Task DisabledScheduleStillAllowsItsAlreadySubmittedActiveRunToRecover()
    {
        await using var f = await Fixture.CreateAsync();
        await f.QueueAsync();
        await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "Recovering"));
        await f.Db.CertificateSchedules.ExecuteUpdateAsync(update => update.SetProperty(x => x.Enabled, false));
        await f.Service.ProcessNextAsync(default);
        Assert.Equal("Succeeded", (await f.Db.DeploymentTasks.AsNoTracking().SingleAsync()).Status);
        Assert.Equal(1, f.Executor.RecoveryCalls);
    }

    [Fact]
    public async Task FailedCompletionTransactionCannotLeakABindingThroughTheRecoverySave()
    {
        var failure = new FailBindingSaveOnce();
        await using var f = await Fixture.CreateAsync(interceptor: failure);
        await f.QueueAsync(); failure.Armed = true;
        await f.Service.ProcessNextAsync(default);
        Assert.Equal("Recovering", (await f.Db.DeploymentTasks.AsNoTracking().SingleAsync()).Status);
        Assert.Empty(await f.Db.DeploymentBindings.ToListAsync());
        await f.Db.DeploymentTasks.ExecuteUpdateAsync(update => update.SetProperty(x => x.LeaseUntilUtc, (DateTime?)null));
        await f.Service.ProcessNextAsync(default);
        Assert.Equal("Succeeded", (await f.Db.DeploymentTasks.AsNoTracking().SingleAsync()).Status);
        Assert.Single(await f.Db.DeploymentBindings.ToListAsync());
    }

    private sealed class FailBindingSaveOnce : SaveChangesInterceptor
    {
        public bool Armed { get; set; }
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (Armed && eventData.Context!.ChangeTracker.Entries<DeploymentBinding>().Any(entry => entry.State is EntityState.Added or EntityState.Modified))
            { Armed = false; throw new InvalidOperationException("模拟绑定保存失败，验证事务外不会重写。"); }
            return base.SavingChangesAsync(eventData, result, cancellationToken);
        }
    }

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, DeploymentService service,
        FakeExecutor executor, FakeMaterials materials, DeploymentPlanView plan) : IAsyncDisposable
    {
        public AppDbContext Db => db;
        public DeploymentService Service => service;
        public FakeExecutor Executor => executor;
        public FakeMaterials Materials => materials;
        public DeploymentPlanView Plan => plan;
        public static async Task<Fixture> CreateAsync(bool source = false, SaveChangesInterceptor? interceptor = null)
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection);
            if (interceptor is not null) options.AddInterceptors(interceptor);
            var db = new AppDbContext(options.Options);
            await db.Database.EnsureCreatedAsync();
            db.Certificates.Add(new() { Id = "cert", Domain = "test.example.com", Status = "Issued" });
            await db.SaveChangesAsync();
            var executor = new FakeExecutor(source ? "linux.files.ssh.v1" : "recovery.fake"); var materials = new FakeMaterials(); var ids = new GuidIdGenerator();
            var protection = new EphemeralDataProtectionProvider(); var resolver = new DeploymentExecutorResolver([executor]);
            var targets = new DeploymentTargetService(db, resolver, protection, ids);
            var service = new DeploymentService(db, targets, resolver, materials, protection, ids);
            var saved = await targets.SaveAsync(null, new() { Name = "测试目标", ExecutorKey = executor.Descriptor.Key, Endpoint = "https://target.invalid",
                Username = "admin", Password = "fake-secret", AuthenticationMode = "Password", Configuration = source
                    ? new() { SourceDomain = "test.example.com", SourceFormat = "tomcat", OutputDirectory = "/ssl",
                        Files = [new("Pfx", "server.pfx", "/ssl", "server.pfx"), new("Password", "password.txt", "/ssl", "password.txt")] } : new() }, default);
            Assert.True(saved.Success, saved.Message);
            var planned = await service.PlanAsync("cert", new([new(saved.Data!.Id)]), "system", default);
            Assert.True(planned.Success, planned.Message);
            db.CertificateSchedules.Add(new() { Id = "schedule", Name = "恢复计划", Domain = "test.example.com", Enabled = true });
            db.CertificateScheduleRuns.Add(new() { Id = "run", ScheduleId = "schedule", CertificateId = "cert", LeaseToken = "run-lease",
                LeaseUntilUtc = DateTime.UtcNow.AddHours(1), TargetsJson = JsonSerializer.Serialize(new[] { new ScheduleTargetProgress
                { TargetId = saved.Data.Id, BatchId = planned.Data!.BatchId, Status = "Draft" } }, new JsonSerializerOptions(JsonSerializerDefaults.Web)) });
            await db.SaveChangesAsync();
            return new(connection, db, service, executor, materials, planned.Data!);
        }
        public async Task QueueAsync() => Assert.True((await Service.SubmitAsync(Plan.BatchId, new(1, "same-run"), "system", default)).Success);
        public async ValueTask DisposeAsync() { await Db.DisposeAsync(); await connection.DisposeAsync(); }
    }
    private sealed class FakeMaterials : ICertificateMaterialService
    {
        public int Downloads { get; private set; }
        public string LastCertificateId { get; private set; } = "";
        public string Fingerprint { get; set; } = "fingerprint";
        public string SourceVersion { get; set; } = "original";
        public Task<ApiResult<CertificateSourcePackage>> GetSourceAsync(string certificateId, string format, CertificateMaterialMetadata expected, CancellationToken ct)
        {
            CertificateSourceFile File(string name, string role, string suffix)
            {
                var content = Encoding.UTF8.GetBytes(SourceVersion + "-" + suffix);
                return new(name, role, content, Convert.ToHexString(SHA256.HashData(content)), true);
            }
            return Task.FromResult(ApiResult<CertificateSourcePackage>.Ok(new(format, [File("server.pfx", "Pfx", "container"), File("password.txt", "Password", "password")])));
        }
        public Task<ApiResult<CertificateMaterial>> GetAsync(string certificateId, CancellationToken ct)
        {
            Downloads++; LastCertificateId = certificateId;
            return Task.FromResult(ApiResult<CertificateMaterial>.Ok(new() { Metadata = new(certificateId, "test.example.com", ["test.example.com"],
                Fingerprint, "material", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30)), CertificatePem = "certificate", FullChainPem = "chain", PrivateKeyPem = "key" }));
        }
    }
    private sealed class FakeExecutor(string key) : IDeploymentExecutor, IDeploymentRecoveryExecutor
    {
        public DeploymentExecutorDescriptor Descriptor => new(key, "假恢复目标", "Fake", "", "HTTPS", AuthenticationModes: ["Password"]);
        public int ExecuteCalls { get; private set; }
        public int RecoveryCalls { get; private set; }
        public string ReceiptUsed { get; private set; } = "";
        public string Disposition { get; set; } = "Completed";
        public int RemoteVersion { get; set; } = 1;
        public string InspectionLevel { get; set; } = "FilesChecked";
        public Func<Task>? BeforeCheckpoint { get; set; }
        public Func<Task>? BeforeExecuteReturn { get; set; }
        public Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct) => Task.FromResult(ApiResult<DeploymentConnectionTest>.Ok(new("test", "可连接")));
        public Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target, CertificateMaterialMetadata material, DeploymentSelection selection, CancellationToken ct) =>
            Task.FromResult(ApiResult<DeploymentTargetPlan>.Ok(new("recovery:" + target.Id, "Update", "替换固定资源", JsonSerializer.Serialize(new { version = RemoteVersion }))));
        public Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct) =>
            Task.FromResult(ApiResult<DeploymentInspection>.Ok(new(true, "远端已核对", context.Material.Fingerprint, InspectionLevel)));
        public async Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct)
        { ExecuteCalls++; if (BeforeExecuteReturn is not null) await BeforeExecuteReturn(); return ApiResult<DeploymentExecutionResult>.Ok(new("完成", "remote", context.Material.Metadata.Fingerprint, "FilesChecked")); }
        public async Task<ApiResult<DeploymentRecoveryResult>> RecoverAsync(DeploymentExecutionContext context, CancellationToken ct)
        {
            Assert.True(context.IsRecovery); RecoveryCalls++; ReceiptUsed = context.ReceiptJson;
            if (BeforeCheckpoint is not null) await BeforeCheckpoint();
            await context.SaveCheckpointAsync!("Verified", "{\"checkpoint\":true}", ct);
            return ApiResult<DeploymentRecoveryResult>.Ok(new(Disposition, "已核对恢复结果", Disposition == "Completed"
                ? new("恢复完成", "remote", context.Material.Metadata.Fingerprint, "FilesChecked", ReceiptJson: "{\"checkpoint\":true}") : null));
        }
    }
}
