using System.Text.Json;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Deployment;
namespace SslManager.Tests;

/// <summary>只使用隔离内存数据库和假执行器，验证部署队列的安全边界，不连接真实目标。</summary>
public sealed class DeploymentManagementTests
{
    [Fact]
    public async Task CredentialsStayEncryptedAndBlankUpdatePreservesPassword()
    {
        await using var fixture = await Fixture.CreateAsync();
        var created = await fixture.Targets.SaveAsync(null, Input("first-secret"), default);
        Assert.True(created.Success);
        var row = await fixture.Db.DeploymentTargets.AsNoTracking().SingleAsync();
        Assert.DoesNotContain("first-secret", row.ProtectedCredentials);
        Assert.DoesNotContain("first-secret", JsonSerializer.Serialize(created));
        var update = Input(""); update.ConfigRevision = created.Data!.ConfigRevision;
        Assert.True((await fixture.Targets.SaveAsync(created.Data.Id, update, default)).Success);
        Assert.Equal("first-secret", (await fixture.Targets.GetContextAsync(created.Data.Id, default)).Data!.Credentials.Password);
        Assert.Equal("CONFLICT", (await fixture.Targets.SaveAsync(created.Data.Id, update, default)).Code);
    }

    [Fact]
    public async Task PlansEncryptMaterialAndTaskCredentialsAndRejectChangedConfiguration()
    {
        await using var fixture = await Fixture.CreateAsync();
        var target = (await fixture.Targets.SaveAsync(null, Input("first-secret"), default)).Data!;
        var plan = await fixture.Service.PlanAsync("cert", new([new(target.Id)]), "admin", default);
        Assert.True(plan.Success);
        var snapshot = await fixture.Db.DeploymentMaterialSnapshots.SingleAsync();
        var task = await fixture.Db.DeploymentTasks.SingleAsync();
        Assert.DoesNotContain("private-material", snapshot.ProtectedPayload);
        Assert.DoesNotContain("first-secret", task.ProtectedCredentials);
        Assert.DoesNotContain("private-material", JsonSerializer.Serialize(plan));
        var update = Input("second-secret"); update.ConfigRevision = target.ConfigRevision;
        Assert.True((await fixture.Targets.SaveAsync(target.Id, update, default)).Success);
        Assert.Equal("PLAN_STALE", (await fixture.Service.SubmitAsync(plan.Data!.BatchId, new(1, "submit-once"), "admin", default)).Code);
    }

    [Fact]
    public async Task SourcePackagesStayEncryptedAndQueuedExecutionUsesTheExactPreviewBytes()
    {
        await using var fixture = await Fixture.CreateAsync("linux.files.ssh.v1");
        var input = Input("secret"); input.ExecutorKey = "linux.files.ssh.v1";
        input.Configuration.SourceCertificateId = "cert";
        input.Configuration.SourceFormat = "tomcat";
        input.Configuration.Files = [new("Pfx", "vpn.pfx", "/ssl", "tomcat/server.pfx")];
        var target = (await fixture.Targets.SaveAsync(null, input, default)).Data!;
        var plan = await fixture.Service.PlanAsync("cert", new([new(target.Id)]), "admin", default);
        Assert.True(plan.Success, plan.Message);
        var snapshot = await fixture.Db.DeploymentMaterialSnapshots.SingleAsync();
        Assert.DoesNotContain("source-container-secret", snapshot.ProtectedPayload);
        Assert.DoesNotContain(Convert.ToBase64String(Encoding.UTF8.GetBytes("source-container-secret")), snapshot.ProtectedPayload);
        Assert.DoesNotContain("source-container-secret", JsonSerializer.Serialize(plan));
        fixture.Materials.SourceContent = "changed-on-later-download";
        Assert.True((await fixture.Service.SubmitAsync(plan.Data!.BatchId, new(1, "source-once"), "admin", default)).Success);
        Assert.True(await fixture.Service.ProcessNextAsync(default));
        Assert.Equal("source-container-secret", fixture.Executor.SourceContentUsed);
        Assert.Equal(1, fixture.Materials.SourceDownloads);
        Assert.Equal("Succeeded", (await fixture.Service.GetTaskAsync(plan.Data.Targets[0].TaskId, default)).Data!.Status);
    }

    [Fact]
    public async Task MissingSourceSelectionIsRejectedBeforeQueueing()
    {
        await using var fixture = await Fixture.CreateAsync("linux.files.ssh.v1");
        var input = Input("secret"); input.ExecutorKey = "linux.files.ssh.v1";
        input.Configuration.SourceCertificateId = "cert";
        input.Configuration.SourceFormat = "tomcat";
        input.Configuration.Files = [new("Pfx", "vpn.pfx", "/ssl", "tomcat/missing.pfx")];
        var target = (await fixture.Targets.SaveAsync(null, input, default)).Data!;
        Assert.Equal("SOURCE_FILE_CHANGED", (await fixture.Service.PlanAsync("cert", new([new(target.Id)]), "admin", default)).Code);
        Assert.Equal(0, await fixture.Db.DeploymentTasks.CountAsync());
    }

    [Fact]
    public async Task RenewedDomainCertificateUsesNewPackageBytesAndKeepsSavedOutputConfiguration()
    {
        await using var fixture = await Fixture.CreateAsync("linux.files.ssh.v1");
        fixture.Db.Certificates.Add(new() { Id = "renewed-cert", Domain = "test.example.com", Status = "Issued" });
        await fixture.Db.SaveChangesAsync();
        var input = SourceInput("old-release/server.pfx");
        input.Configuration.OutputDirectory = "/ssl";
        input.Configuration.PostCommands = [new("systemctl restart example")];
        var saved = await fixture.Targets.SaveAsync(null, input, default);
        Assert.True(saved.Success, saved.Message);
        var target = saved.Data!;
        var originalConfiguration = (await fixture.Db.DeploymentTargets.AsNoTracking().SingleAsync()).ConfigurationJson;
        fixture.Materials.SourceFileNames = ["new-release/server.pfx"];
        fixture.Materials.SourceContent = "renewed-container-from-preview";
        fixture.Materials.Fingerprint = "renewed-fingerprint";

        var planned = await fixture.Service.PlanAsync("renewed-cert", new([new(target.Id)]), "admin", default);

        Assert.True(planned.Success, planned.Message);
        Assert.Equal("renewed-cert", planned.Data!.Certificate.CertificateId);
        Assert.Equal("renewed-fingerprint", planned.Data.Certificate.Fingerprint);
        Assert.Equal("renewed-cert", fixture.Materials.LastSourceCertificateId);
        var task = await fixture.Db.DeploymentTasks.AsNoTracking().SingleAsync();
        var snapshot = JsonSerializer.Deserialize<DeploymentTargetContext>(task.TargetSnapshotJson,
            new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        // ZIP 顶层目录随续签变化时，仅冻结任务实际源路径；服务器输出路径及重启命令沿用已保存配置。
        Assert.Equal("new-release/server.pfx", Assert.Single(snapshot.Configuration.Files).SourceFileName);
        Assert.Equal("stable-output.pfx", snapshot.Configuration.Files[0].FileName);
        Assert.Equal("/ssl", snapshot.Configuration.Files[0].Directory);
        Assert.Equal("/ssl", snapshot.Configuration.OutputDirectory);
        Assert.Equal("systemctl restart example", Assert.Single(snapshot.Configuration.PostCommands).Command);
        Assert.Equal(originalConfiguration, (await fixture.Db.DeploymentTargets.AsNoTracking().SingleAsync()).ConfigurationJson);
        fixture.Materials.SourceContent = "must-not-be-downloaded-in-queue";
        fixture.Materials.SourceFileNames = ["later-release/server.pfx"];

        Assert.True((await fixture.Service.SubmitAsync(planned.Data.BatchId, new(1, "renewed-once"), "admin", default)).Success);
        Assert.True(await fixture.Service.ProcessNextAsync(default));
        Assert.Equal("renewed-container-from-preview", fixture.Executor.SourceContentUsed);
        Assert.Equal("renewed-cert", fixture.Executor.CertificateIdUsed);
        Assert.Equal("renewed-fingerprint", fixture.Executor.FingerprintUsed);
        Assert.Equal("new-release/server.pfx", fixture.Executor.SourceFileNameUsed);
        Assert.Equal(1, fixture.Materials.SourceDownloads);
        Assert.Equal("Succeeded", (await fixture.Service.GetTaskAsync(task.Id, default)).Data!.Status);
        Assert.Equal(originalConfiguration, (await fixture.Db.DeploymentTargets.AsNoTracking().SingleAsync()).ConfigurationJson);
    }

    [Fact]
    public async Task OtherDomainCertificateIsRejectedBeforeDownloadingPackageOrQueueing()
    {
        await using var fixture = await Fixture.CreateAsync("linux.files.ssh.v1");
        var saved = await fixture.Targets.SaveAsync(null, SourceInput("tomcat/server.pfx"), default);
        Assert.True(saved.Success, saved.Message);
        fixture.Db.Certificates.Add(new() { Id = "unrelated-cert", Domain = "other.example.com", Status = "Issued" });
        await fixture.Db.SaveChangesAsync();
        fixture.Materials.Domain = "other.example.com";

        var result = await fixture.Service.PlanAsync("unrelated-cert", new([new(saved.Data!.Id)]), "admin", default);

        Assert.Equal("SOURCE_CERTIFICATE_MISMATCH", result.Code);
        Assert.Equal(0, fixture.Materials.SourceDownloads);
        Assert.Empty(await fixture.Db.DeploymentTasks.ToListAsync());
        Assert.Empty(await fixture.Db.DeploymentMaterialSnapshots.ToListAsync());
        Assert.Equal(0, fixture.Executor.ExecuteCalls);
    }

    [Fact]
    public async Task AmbiguousRenewedPackageBasenameIsRejectedInsteadOfChoosingArbitraryFile()
    {
        await using var fixture = await Fixture.CreateAsync("linux.files.ssh.v1");
        var saved = await fixture.Targets.SaveAsync(null, SourceInput("old-release/server.pfx"), default);
        Assert.True(saved.Success, saved.Message);
        fixture.Materials.SourceFileNames = ["first/server.pfx", "second/server.pfx"];

        var result = await fixture.Service.PlanAsync("cert", new([new(saved.Data!.Id)]), "admin", default);

        Assert.False(result.Success);
        Assert.Equal("SOURCE_FILE_CHANGED", result.Code);
        Assert.Equal(1, fixture.Materials.SourceDownloads);
        Assert.Empty(await fixture.Db.DeploymentTasks.ToListAsync());
        Assert.Empty(await fixture.Db.DeploymentMaterialSnapshots.ToListAsync());
    }

    [Fact]
    public async Task SubmitIsIdempotentAndQueuedTaskUsesFixedCredentials()
    {
        await using var fixture = await Fixture.CreateAsync();
        var target = (await fixture.Targets.SaveAsync(null, Input("first-secret"), default)).Data!;
        var plan = (await fixture.Service.PlanAsync("cert", new([new(target.Id)]), "admin", default)).Data!;
        Assert.True((await fixture.Service.SubmitAsync(plan.BatchId, new(1, "submit-once"), "admin", default)).Success);
        Assert.True((await fixture.Service.SubmitAsync(plan.BatchId, new(1, "submit-once"), "admin", default)).Success);
        Assert.Equal(1, await fixture.Db.DeploymentTasks.CountAsync());
        var update = Input("second-secret"); update.ConfigRevision = target.ConfigRevision;
        Assert.True((await fixture.Targets.SaveAsync(target.Id, update, default)).Success);
        Assert.True(await fixture.Service.ProcessNextAsync(default));
        Assert.Equal("first-secret", fixture.Executor.PasswordUsed);
        Assert.Equal(1, fixture.Executor.ExecuteCalls);
        Assert.Equal("Succeeded", (await fixture.Service.GetTaskAsync(plan.Targets[0].TaskId, default)).Data!.Status);
        Assert.False(await fixture.Service.ProcessNextAsync(default));
        Assert.Equal(1, await fixture.Db.DeploymentBindings.CountAsync());
    }

    [Fact]
    public async Task MaterialChangeAtSubmitAndRemoteChangeInQueueBothPreventWrites()
    {
        await using var fixture = await Fixture.CreateAsync();
        var target = (await fixture.Targets.SaveAsync(null, Input("secret"), default)).Data!;
        var plan = (await fixture.Service.PlanAsync("cert", new([new(target.Id)]), "admin", default)).Data!;
        fixture.Materials.Digest = "changed";
        Assert.Equal("PLAN_STALE", (await fixture.Service.SubmitAsync(plan.BatchId, new(1, "key-1"), "admin", default)).Code);
        fixture.Materials.Digest = "material-v1";
        Assert.True((await fixture.Service.SubmitAsync(plan.BatchId, new(1, "key-1"), "admin", default)).Success);
        fixture.Executor.RemoteVersion = "changed";
        await fixture.Service.ProcessNextAsync(default);
        var task = (await fixture.Service.GetTaskAsync(plan.Targets[0].TaskId, default)).Data!;
        Assert.Equal("Failed", task.Status); Assert.Equal("PLAN_STALE", task.Code); Assert.Equal(0, fixture.Executor.ExecuteCalls);
    }

    [Fact]
    public async Task UnknownResultBlocksPlansUntilExplicitAuditedManualResolution()
    {
        await using var fixture = await Fixture.CreateAsync();
        var target = (await fixture.Targets.SaveAsync(null, Input("secret"), default)).Data!;
        var plan = (await fixture.Service.PlanAsync("cert", new([new(target.Id)]), "admin", default)).Data!;
        await fixture.Service.SubmitAsync(plan.BatchId, new(1, "unknown-key"), "admin", default);
        fixture.Executor.FailureCode = "REMOTE_RESULT_UNKNOWN";
        await fixture.Service.ProcessNextAsync(default);
        Assert.Equal("NeedsAttention", (await fixture.Service.GetTaskAsync(plan.Targets[0].TaskId, default)).Data!.Status);
        Assert.Equal("TARGET_BUSY", (await fixture.Service.PlanAsync("cert", new([new(target.Id)]), "admin", default)).Code);
        Assert.Equal("VALIDATION", (await fixture.Service.ResolveAsync(plan.Targets[0].TaskId, "", "admin", "管理员", default)).Code);
        var resolved = await fixture.Service.ResolveAsync(plan.Targets[0].TaskId, "已在远端核对，允许重新规划", "admin", "管理员", default);
        Assert.Equal("Resolved", resolved.Data!.Status);
        Assert.NotEqual("Succeeded", resolved.Data.Status);
        Assert.Single(await fixture.Db.AuditLogs.Where(x => x.Action == "ResolveDeploymentResult").ToListAsync());
        Assert.True((await fixture.Service.PlanAsync("cert", new([new(target.Id)]), "admin", default)).Success);
        Assert.Equal(1, fixture.Executor.ExecuteCalls);
    }

    [Fact]
    public async Task ExpiredLeaseDoesNotRepeatAnUnknownRemoteAction()
    {
        await using var fixture = await Fixture.CreateAsync();
        var target = (await fixture.Targets.SaveAsync(null, Input("secret"), default)).Data!;
        var plan = (await fixture.Service.PlanAsync("cert", new([new(target.Id)]), "admin", default)).Data!;
        var task = await fixture.Db.DeploymentTasks.SingleAsync();
        task.Status = "Running"; task.LeaseId = "lost-worker"; task.LeaseUntilUtc = DateTime.UtcNow.AddMinutes(-1);
        await fixture.Db.SaveChangesAsync();
        Assert.False(await fixture.Service.ProcessNextAsync(default));
        var current = (await fixture.Service.GetTaskAsync(plan.Targets[0].TaskId, default)).Data!;
        Assert.Equal("NeedsAttention", current.Status); Assert.Equal(0, fixture.Executor.ExecuteCalls);
    }

    [Fact]
    public async Task QueuedCancellationNeverCallsTheExecutor()
    {
        await using var fixture = await Fixture.CreateAsync();
        var target = (await fixture.Targets.SaveAsync(null, Input("secret"), default)).Data!;
        var plan = (await fixture.Service.PlanAsync("cert", new([new(target.Id)]), "admin", default)).Data!;
        await fixture.Service.SubmitAsync(plan.BatchId, new(1, "cancel-key"), "admin", default);
        Assert.Equal("Cancelled", (await fixture.Service.CancelAsync(plan.Targets[0].TaskId, default)).Data!.Status);
        Assert.False(await fixture.Service.ProcessNextAsync(default)); Assert.Equal(0, fixture.Executor.ExecuteCalls);
    }

    [Fact]
    public async Task RollbackCreatesAnIndependentTaskAndCannotOverwriteALaterDeployment()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Executor.RollbackEnabled = true;
        var target = (await fixture.Targets.SaveAsync(null, Input("secret"), default)).Data!;
        var plan = (await fixture.Service.PlanAsync("cert", new([new(target.Id)]), "admin", default)).Data!;
        await fixture.Service.SubmitAsync(plan.BatchId, new(1, "original"), "admin", default);
        await fixture.Service.ProcessNextAsync(default);
        var sourceId = plan.Targets[0].TaskId;
        var recovery = await fixture.Service.RollbackPlanAsync(sourceId, "admin", default);
        Assert.True(recovery.Success);
        Assert.Equal("Rollback", recovery.Data!.Targets[0].Plan.Action);
        Assert.True((await fixture.Service.SubmitAsync(recovery.Data.BatchId, new(1, "restore"), "admin", default)).Success);
        await fixture.Service.ProcessNextAsync(default);
        var restored = (await fixture.Service.GetTaskAsync(recovery.Data.Targets[0].TaskId, default)).Data!;
        Assert.Equal("RolledBack", restored.Status); Assert.Equal(sourceId, restored.SourceTaskId);
        Assert.Equal("Succeeded", (await fixture.Service.GetTaskAsync(sourceId, default)).Data!.Status);
        Assert.Equal(1, fixture.Executor.RollbackCalls);
        Assert.Equal("PLAN_STALE", (await fixture.Service.RollbackPlanAsync(sourceId, "admin", default)).Code);
    }

    [Fact]
    public async Task OldRunnerCannotOverwriteManualResolutionOrWriteABinding()
    {
        await using var fixture = await Fixture.CreateAsync();
        var target = (await fixture.Targets.SaveAsync(null, Input("secret"), default)).Data!;
        var plan = (await fixture.Service.PlanAsync("cert", new([new(target.Id)]), "admin", default)).Data!;
        await fixture.Service.SubmitAsync(plan.BatchId, new(1, "lost-runner"), "admin", default);
        fixture.Executor.BeforeReturn = async () =>
        {
            await fixture.Db.DeploymentTasks.Where(x => x.Id == plan.Targets[0].TaskId).ExecuteUpdateAsync(update => update
                .SetProperty(x => x.Status, "Resolved").SetProperty(x => x.Code, "MANUALLY_RESOLVED"));
        };
        await fixture.Service.ProcessNextAsync(default);
        var task = (await fixture.Service.GetTaskAsync(plan.Targets[0].TaskId, default)).Data!;
        Assert.Equal("Resolved", task.Status); Assert.Equal("MANUALLY_RESOLVED", task.Code);
        Assert.Equal(0, await fixture.Db.DeploymentBindings.CountAsync());
    }

    private static DeploymentTargetInput Input(string password) => new() { Name = "测试目标", ExecutorKey = "fake", Endpoint = "https://target.invalid",
        Username = "admin", Password = password, AuthenticationMode = "Password" };
    private static DeploymentTargetInput SourceInput(string sourceFileName)
    {
        var input = Input("source-target-secret");
        input.ExecutorKey = "linux.files.ssh.v1";
        input.Configuration.SourceCertificateId = "cert";
        input.Configuration.SourceFormat = "tomcat";
        input.Configuration.Files = [new("Pfx", "stable-output.pfx", "/ssl", sourceFileName)];
        return input;
    }
    private sealed class Fixture(SqliteConnection connection, AppDbContext db, DeploymentTargetService targets,
        DeploymentService service, FakeExecutor executor, FakeMaterials materials) : IAsyncDisposable
    {
        public AppDbContext Db => db;
        public DeploymentTargetService Targets => targets;
        public DeploymentService Service => service;
        public FakeExecutor Executor => executor;
        public FakeMaterials Materials => materials;
        public static async Task<Fixture> CreateAsync(string executorKey = "fake")
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            db.Certificates.Add(new() { Id = "cert", Domain = "test.example.com", Status = "Issued" }); await db.SaveChangesAsync();
            var protection = new EphemeralDataProtectionProvider(); var executor = new FakeExecutor(executorKey); var materials = new FakeMaterials();
            var resolver = new DeploymentExecutorResolver([executor]); var targets = new DeploymentTargetService(db, resolver, protection, new GuidIdGenerator());
            var service = new DeploymentService(db, targets, resolver, materials, protection, new GuidIdGenerator());
            return new(connection, db, targets, service, executor, materials);
        }
        public async ValueTask DisposeAsync() { await db.DisposeAsync(); await connection.DisposeAsync(); }
    }
    private sealed class FakeMaterials : ICertificateMaterialService
    {
        public string Digest { get; set; } = "material-v1";
        public string Domain { get; set; } = "test.example.com";
        public string Fingerprint { get; set; } = "fingerprint";
        public string SourceContent { get; set; } = "source-container-secret";
        public string[] SourceFileNames { get; set; } = ["tomcat/server.pfx"];
        public int SourceDownloads { get; private set; }
        public string LastSourceCertificateId { get; private set; } = "";
        public Task<ApiResult<CertificateMaterial>> GetAsync(string certificateId, CancellationToken ct) => Task.FromResult(ApiResult<CertificateMaterial>.Ok(new()
        { Metadata = new(certificateId, Domain, [Domain], Fingerprint, Digest, DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30)),
            CertificatePem = "public-material", FullChainPem = "public-chain", PrivateKeyPem = "private-material" }));
        public Task<ApiResult<CertificateSourcePackage>> GetSourceAsync(string certificateId, string format, CertificateMaterialMetadata expected, CancellationToken ct)
        {
            SourceDownloads++;
            LastSourceCertificateId = certificateId;
            var content = Encoding.UTF8.GetBytes(SourceContent);
            return Task.FromResult(ApiResult<CertificateSourcePackage>.Ok(new(format,
                SourceFileNames.Select(name => new CertificateSourceFile(name, "Pfx", content,
                    Convert.ToHexString(SHA256.HashData(content)), true)).ToArray())));
        }
    }
    private sealed class FakeExecutor(string executorKey) : IDeploymentExecutor, IRollbackDeploymentExecutor
    {
        public DeploymentExecutorDescriptor Descriptor => new(executorKey, "假目标", "Fake", "", "HTTPS", AuthenticationModes: ["Password"], SupportsRollback: RollbackEnabled);
        public string RemoteVersion { get; set; } = "remote-v1";
        public string PasswordUsed { get; private set; } = "";
        public string SourceContentUsed { get; private set; } = "";
        public string SourceFileNameUsed { get; private set; } = "";
        public string CertificateIdUsed { get; private set; } = "";
        public string FingerprintUsed { get; private set; } = "";
        public int ExecuteCalls { get; private set; }
        public string FailureCode { get; set; } = "";
        public bool RollbackEnabled { get; set; }
        public int RollbackCalls { get; private set; }
        public Func<Task>? BeforeReturn { get; set; }
        public Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct) => Task.FromResult(ApiResult<DeploymentConnectionTest>.Ok(new("9.3.9", "连接成功")));
        public Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target, CertificateMaterialMetadata material, DeploymentSelection selection, CancellationToken ct)
            => Task.FromResult(ApiResult<DeploymentTargetPlan>.Ok(new("fake:" + target.Id, "Replace", "替换测试资源", JsonSerializer.Serialize(new { RemoteVersion }))));
        public async Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct)
        {
            ExecuteCalls++; PasswordUsed = context.Target.Credentials.Password;
            SourceContentUsed = context.Material.SourcePackages.Count > 0 ? Encoding.UTF8.GetString(context.Material.SourcePackages[0].Files[0].Content) : "";
            SourceFileNameUsed = context.Target.Configuration.Files.FirstOrDefault()?.SourceFileName ?? "";
            CertificateIdUsed = context.Material.Metadata.CertificateId;
            FingerprintUsed = context.Material.Metadata.Fingerprint;
            await context.ReportProgressAsync("Upload", "正在上传", ct);
            if (BeforeReturn is not null) await BeforeReturn();
            return string.IsNullOrEmpty(FailureCode) ? ApiResult<DeploymentExecutionResult>.Ok(new("平台证书已核对", "remote-id", context.Material.Metadata.Fingerprint, ReceiptJson: "{\"backups\":\"present\"}"))
                : ApiResult<DeploymentExecutionResult>.Fail(FailureCode, "结果未知");
        }
        public Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct)
            => Task.FromResult(ApiResult<DeploymentInspection>.Ok(new(true, "已读回")));
        public Task<ApiResult<DeploymentRollbackResult>> RollbackAsync(DeploymentRollbackContext context, CancellationToken ct)
        {
            RollbackCalls++;
            return Task.FromResult(ApiResult<DeploymentRollbackResult>.Ok(new("原文件已恢复，服务未重新加载。")));
        }
    }
}
