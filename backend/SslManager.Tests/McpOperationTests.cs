using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;
using SslManager.Api.Service.impl.Deployment;
using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Tests;

/// <summary>真实 SQLite 事务加协议假目标，验证崩溃窗口、审批身份、幂等与撤销；不访问云或真实设备。</summary>
public sealed class McpOperationTests
{
    [Fact]
    public async Task PreparationRequiresWebApprovalAndNeverCallsCloud()
    {
        await using var f = await Fixture.CreateAsync();
        var prepared = await f.PrepareAsync();
        Assert.Equal("Prepared", prepared.Status);
        Assert.True(prepared.CanApprove);
        Assert.Equal(0, f.Cloud.ApplyCalls);
        Assert.Empty(await f.Db.Certificates.ToListAsync());
        Assert.Equal("MCP_APPROVAL_REQUIRED", (await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default)).Code);
        Assert.Equal("FORBIDDEN", (await f.Operations.ApproveAsync(prepared.Id, "viewer", true, prepared.Version, default)).Code);
        var approved = await f.Operations.ApproveAsync(prepared.Id, "approver", true, prepared.Version, default);
        Assert.True(approved.Success, approved.Message);
        Assert.Equal("actor", approved.Data!.EffectiveUserId);
        Assert.Equal("actor", approved.Data.PreparedBy);
        Assert.Equal("approver", approved.Data.ApprovedBy);
        Assert.Equal(0, f.Cloud.ApplyCalls);
    }

    [Fact]
    public async Task AtomicIntentIsQueuedBeforeDispatchAndEveryRetryReturnsOriginalIdentity()
    {
        await using var f = await Fixture.CreateAsync(preauthorized: true);
        var prepared = await f.PrepareAsync();
        var submitted = await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default);
        Assert.True(submitted.Success, submitted.Message);
        var original = submitted.Data!;
        var certificate = Assert.Single(await f.Db.Certificates.AsNoTracking().ToListAsync());
        var job = Assert.Single(await f.Db.CertificateJobs.AsNoTracking().ToListAsync());
        Assert.Equal(original.CertificateId, certificate.Id);
        Assert.Equal(original.CertificateJobId, job.Id);
        Assert.Equal("McpQueued", job.Status);
        Assert.Equal(0, f.Cloud.ApplyCalls);
        var repeated = await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default);
        Assert.Equal(original.CertificateId, repeated.Data!.CertificateId);
        Assert.Single(await f.Db.CertificateJobs.ToListAsync());
        f.Cloud.BeforeApply = async () =>
        {
            var persisted = await f.Db.McpOperations.AsNoTracking().SingleAsync();
            Assert.Equal("Dispatching", persisted.Status);
            Assert.False(string.IsNullOrWhiteSpace(persisted.LeaseToken));
            Assert.Equal("Submitting", (await f.Db.CertificateJobs.AsNoTracking().SingleAsync()).Status);
        };
        await f.Certificates.ProcessJobAsync(job.Id, default);
        Assert.Equal(1, f.Cloud.ApplyCalls);
        await f.Certificates.ProcessJobAsync(job.Id, default);
        Assert.Equal(1, f.Cloud.ApplyCalls);
        Assert.Equal("Waiting", (await f.Db.McpOperations.AsNoTracking().SingleAsync()).Status);
    }

    [Fact]
    public async Task SameKeyWithChangedArgumentsOrPrincipalIsRejected()
    {
        await using var f = await Fixture.CreateAsync();
        var prepared = await f.PrepareAsync();
        var changed = await f.Operations.PrepareApplicationAsync(f.Caller, f.Request with { Domain = "other.example.test" }, "application", default);
        Assert.Equal("IDEMPOTENCY_CONFLICT", changed.Code);
        var other = await f.Operations.SubmitAsync(f.Caller with { EffectiveUserId = "another" }, prepared.Id, "application", default);
        Assert.Equal("NOT_FOUND", other.Code);
        var repeated = await f.Operations.PrepareApplicationAsync(f.Caller, f.Request, "application", default);
        Assert.Equal("IDEMPOTENCY_REUSED", repeated.Code);
        Assert.Equal(prepared.Id, repeated.Data!.Id);
        Assert.Single(await f.Db.McpOperations.ToListAsync());
    }

    [Fact]
    public async Task ApiKeyOperationKeepsOriginalCredentialIdentityAcrossApprovalAndRetries()
    {
        await using var f = await Fixture.CreateAsync();
        var caller = f.Caller with { AuthorizationId = "", AuthenticationType = "ApiKey", ApiKeyId = "original-key" };
        var prepared = await f.Operations.PrepareApplicationAsync(caller, f.Request, "api-key-operation", default);
        Assert.True(prepared.Success, prepared.Message);
        var stored = await f.Db.McpOperations.AsNoTracking().SingleAsync();
        Assert.Equal("ApiKey", stored.AuthenticationType); Assert.Equal("original-key", stored.ApiKeyId);
        Assert.Equal("NOT_FOUND", (await f.Operations.GetAsync(caller with { ApiKeyId = "replacement-key" }, stored.Id, default)).Code);
        Assert.Equal("IDEMPOTENCY_CONFLICT", (await f.Operations.PrepareApplicationAsync(caller with { ApiKeyId = "replacement-key" }, f.Request, "api-key-operation", default)).Code);
        var approved = await f.Operations.ApproveAsync(stored.Id, "approver", true, stored.Version, default);
        Assert.True(approved.Success, approved.Message);
        Assert.Equal("NOT_FOUND", (await f.Operations.SubmitAsync(caller with { ApiKeyId = "replacement-key" }, stored.Id, "api-key-operation", default)).Code);
        Assert.True((await f.Operations.SubmitAsync(caller, stored.Id, "api-key-operation", default)).Success);
        Assert.Equal(0, f.Cloud.ApplyCalls);
    }

    [Fact]
    public async Task FailureAfterSqlIntentSaveRollsBackOperationCertificateAndJobTogether()
    {
        var failure = new IntentSaveFailure();
        await using var f = await Fixture.CreateAsync(preauthorized: true, interceptor: failure);
        var prepared = await f.PrepareAsync();
        failure.Armed = true;
        await Assert.ThrowsAsync<InvalidOperationException>(() => f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default));
        f.Db.ChangeTracker.Clear();
        Assert.Empty(await f.Db.Certificates.AsNoTracking().ToListAsync());
        Assert.Empty(await f.Db.CertificateJobs.AsNoTracking().ToListAsync());
        var operation = await f.Db.McpOperations.AsNoTracking().SingleAsync();
        Assert.Equal("Approved", operation.Status);
        Assert.Null(operation.ConsumedAtUtc);
        failure.Armed = false;
        var retried = await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default);
        Assert.True(retried.Success, retried.Message);
        Assert.Single(await f.Db.CertificateJobs.ToListAsync());
        Assert.Equal(0, f.Cloud.ApplyCalls);
    }

    [Fact]
    public async Task FailedSubmissionValidationKeepsApprovalUnconsumed()
    {
        await using var f = await Fixture.CreateAsync(preauthorized: true);
        var prepared = await f.PrepareAsync();
        await f.Db.Domains.ExecuteUpdateAsync(update => update.SetProperty(row => row.Status, "NotPresent"));
        var submitted = await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default);
        Assert.Equal("DNS_ACCOUNT_MISMATCH", submitted.Code);
        var operation = await f.Db.McpOperations.AsNoTracking().SingleAsync();
        Assert.Equal("Approved", operation.Status);
        Assert.Null(operation.ConsumedAtUtc);
        Assert.Empty(await f.Db.CertificateJobs.ToListAsync());
    }

    [Fact]
    public async Task ChangedPolicyAndUnconsumedExpiredApprovalCannotBeSubmitted()
    {
        await using var f = await Fixture.CreateAsync(preauthorized: true);
        var prepared = await f.PrepareAsync();
        f.Authorization.Revision++;
        Assert.Equal("MCP_APPROVAL_STALE", (await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default)).Code);
        f.Authorization.Revision--;
        await f.Db.McpOperations.Where(row => row.Id == prepared.Id).ExecuteUpdateAsync(update => update.SetProperty(row => row.ApprovalExpiresAtUtc, DateTime.UtcNow.AddSeconds(-1)));
        f.Db.ChangeTracker.Clear();
        Assert.Equal("MCP_APPROVAL_STALE", (await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default)).Code);
        Assert.Empty(await f.Db.Certificates.ToListAsync());
    }

    [Fact]
    public async Task NaturalExpiryAfterAcceptanceDoesNotCancelDurableWorkerDispatch()
    {
        await using var f = await Fixture.CreateAsync(preauthorized: true);
        var prepared = await f.PrepareAsync();
        var queued = await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default);
        await f.Db.McpOperations.Where(row => row.Id == prepared.Id).ExecuteUpdateAsync(update => update.SetProperty(row => row.ApprovalExpiresAtUtc, DateTime.UtcNow.AddMinutes(-20)));
        f.Db.ChangeTracker.Clear();
        f.Authorization.RequestTokenExpired = true;
        await f.Certificates.ProcessJobAsync(queued.Data!.CertificateJobId, default);
        Assert.Equal(1, f.Cloud.ApplyCalls);
        Assert.Contains(true, f.Authorization.WorkerChecks);
    }

    [Fact]
    public async Task RevocationBeforeDispatchStopsAcceptedJobWithoutCloudWrite()
    {
        await using var f = await Fixture.CreateAsync(preauthorized: true);
        var prepared = await f.PrepareAsync();
        var queued = await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default);
        f.Authorization.Revoked = true;
        await f.Certificates.ProcessJobAsync(queued.Data!.CertificateJobId, default);
        Assert.Equal(0, f.Cloud.ApplyCalls);
        Assert.Equal("Blocked", (await f.Db.McpOperations.AsNoTracking().SingleAsync()).Status);
        Assert.Equal("Failed", (await f.Db.CertificateJobs.AsNoTracking().SingleAsync()).Status);
    }

    [Fact]
    public async Task WorkerRejectsChangedSnapshotWithoutIssuingCertificate()
    {
        await using var f = await Fixture.CreateAsync(preauthorized: true);
        var prepared = await f.PrepareAsync();
        var queued = await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default);
        await f.Db.McpOperations.Where(row => row.Id == prepared.Id).ExecuteUpdateAsync(update => update.SetProperty(row => row.ArgumentsJson, "{}"));
        f.Db.ChangeTracker.Clear();
        await f.Certificates.ProcessJobAsync(queued.Data!.CertificateJobId, default);
        Assert.Equal(0, f.Cloud.ApplyCalls);
        Assert.Equal("Blocked", (await f.Db.McpOperations.AsNoTracking().SingleAsync()).Status);
    }

    [Fact]
    public async Task CrashAfterDispatchMarkerIsUnknownAndNeverCreatesReplacementApplication()
    {
        await using var f = await Fixture.CreateAsync(preauthorized: true);
        var prepared = await f.PrepareAsync();
        var queued = await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default);
        await f.Db.McpOperations.Where(row => row.Id == prepared.Id).ExecuteUpdateAsync(update => update.SetProperty(row => row.Status, "Dispatching")
            .SetProperty(row => row.LeaseUntilUtc, DateTime.UtcNow.AddMinutes(-1)));
        await f.Db.CertificateJobs.Where(row => row.Id == queued.Data!.CertificateJobId).ExecuteUpdateAsync(update => update.SetProperty(row => row.Status, "Submitting")
            .SetProperty(row => row.LeaseUntilUtc, DateTime.UtcNow.AddMinutes(-1)));
        f.Db.ChangeTracker.Clear();
        await f.Certificates.ProcessJobAsync(queued.Data!.CertificateJobId, default);
        await f.Certificates.ProcessJobAsync(queued.Data.CertificateJobId, default);
        Assert.Equal(0, f.Cloud.ApplyCalls);
        Assert.Equal("Unknown", (await f.Db.McpOperations.AsNoTracking().SingleAsync()).Status);
        Assert.Equal("SubmissionUnknown", (await f.Db.CertificateJobs.AsNoTracking().SingleAsync()).Status);
        var repeated = await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default);
        Assert.Equal(queued.Data.CertificateId, repeated.Data!.CertificateId);
        Assert.Single(await f.Db.Certificates.ToListAsync());
    }

    [Fact]
    public async Task MissingCloudReceiptRemainsUnknownAndDoesNotDispatchAgain()
    {
        await using var f = await Fixture.CreateAsync(preauthorized: true);
        f.Cloud.ApplyFailure = ApiResult<CloudCertificateDetail>.Fail("OutcomeUnknown", "模拟云端回执缺失。");
        var prepared = await f.PrepareAsync();
        var queued = await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default);
        await f.Certificates.ProcessJobAsync(queued.Data!.CertificateJobId, default);
        await f.Certificates.ProcessJobAsync(queued.Data.CertificateJobId, default);
        Assert.Equal(1, f.Cloud.ApplyCalls);
        Assert.Equal("Unknown", (await f.Db.McpOperations.AsNoTracking().SingleAsync()).Status);
    }

    [Fact]
    public async Task DeploymentPreservesEffectiveOwnerAndWorkerRechecksRevocation()
    {
        await using var f = await Fixture.CreateAsync();
        await f.SeedIssuedAsync();
        var plan = await f.Operations.PrepareDeploymentAsync(f.Caller, "issued", new([new("target")]), "deployment", default);
        Assert.True(plan.Success, plan.Message);
        Assert.Equal("actor", (await f.Db.DeploymentBatches.SingleAsync()).CreatedBy);
        var approved = await f.Operations.ApproveAsync(plan.Data!.Id, "approver", true, plan.Data.Version, default);
        var queued = await f.Operations.SubmitAsync(f.Caller, plan.Data.Id, "deployment", default);
        Assert.True(approved.Success, approved.Message);
        Assert.True(queued.Success, queued.Message);
        Assert.Equal("actor", queued.Data!.EffectiveUserId);
        Assert.Equal("approver", queued.Data.ApprovedBy);
        f.Authorization.Revoked = true;
        await f.Deployments.ProcessNextAsync(default);
        Assert.Equal(0, f.Executor.ExecuteCalls);
        Assert.Equal("Failed", (await f.Db.DeploymentTasks.AsNoTracking().SingleAsync()).Status);
    }

    [Fact]
    public async Task RevocationBetweenMutationsStopsNextWriteAndPreservesNeedsAttention()
    {
        await using var f = await Fixture.CreateAsync(preauthorized: true);
        await f.SeedIssuedAsync();
        var plan = await f.Operations.PrepareDeploymentAsync(f.Caller, "issued", new([new("target")]), "deployment", default);
        await f.Operations.SubmitAsync(f.Caller, plan.Data!.Id, "deployment", default);
        f.Executor.RevokeAfterFirstMutation = () => f.Authorization.Revoked = true;
        await f.Deployments.ProcessNextAsync(default);
        Assert.Equal(1, f.Executor.Writes);
        Assert.Equal("NeedsAttention", (await f.Db.DeploymentTasks.AsNoTracking().SingleAsync()).Status);
    }

    [Fact]
    public async Task TargetTestsRequireApprovalAndConsumedRetriesDoNotReconnect()
    {
        await using var f = await Fixture.CreateAsync();
        var prepared = await f.Operations.InvokeTargetTestAsync(f.Caller, "target", "test", null, default);
        Assert.True(prepared.Success, prepared.Message);
        Assert.Equal("Prepared", prepared.Data!.Status);
        Assert.Equal(0, f.Executor.TestCalls);
        await f.Operations.ApproveAsync(prepared.Data.Id, "approver", true, prepared.Data.Version, default);
        var tested = await f.Operations.InvokeTargetTestAsync(f.Caller, "target", "test", prepared.Data.Id, default);
        Assert.Equal("Succeeded", tested.Data!.Status);
        await f.Operations.InvokeTargetTestAsync(f.Caller, "target", "test", prepared.Data.Id, default);
        Assert.Equal(1, f.Executor.TestCalls);
    }

    [Fact]
    public async Task TargetConnectionChangeInvalidatesOldTestApproval()
    {
        await using var f = await Fixture.CreateAsync();
        var prepared = await f.Operations.InvokeTargetTestAsync(f.Caller, "target", "test", null, default);
        await f.Operations.ApproveAsync(prepared.Data!.Id, "approver", true, prepared.Data.Version, default);
        await f.Db.DeploymentTargets.Where(row => row.Id == "target").ExecuteUpdateAsync(update => update.SetProperty(row => row.ConfigRevision, row => row.ConfigRevision + 1));
        var tested = await f.Operations.InvokeTargetTestAsync(f.Caller, "target", "test", prepared.Data.Id, default);
        Assert.Equal("MCP_APPROVAL_STALE", tested.Code);
        Assert.Equal(0, f.Executor.TestCalls);
    }

    [Fact]
    public async Task InspectionAlsoRequiresApprovalAndKeepsRawReceiptOutOfResponse()
    {
        await using var f = await Fixture.CreateAsync();
        await f.SeedIssuedAsync();
        var plan = await f.Deployments.PlanAsync("issued", new([new("target")]), "actor", default);
        var taskId = plan.Data!.Targets.Single().TaskId;
        var prepared = await f.Operations.InvokeInspectionAsync(f.Caller, taskId, "inspect", null, default);
        Assert.Equal("Prepared", prepared.Data!.Status);
        Assert.Equal(0, f.Executor.InspectCalls);
        await f.Operations.ApproveAsync(prepared.Data.Id, "approver", true, prepared.Data.Version, default);
        var inspected = await f.Operations.InvokeInspectionAsync(f.Caller, taskId, "inspect", prepared.Data.Id, default);
        Assert.Equal(1, f.Executor.InspectCalls);
        Assert.DoesNotContain("synthetic-private", JsonSerializer.Serialize(inspected));
        Assert.DoesNotContain("preconditionsJson", JsonSerializer.Serialize(inspected), StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RemoteTestAndInspectionErrorsNeverLeakIntoMcpViewOrSummary(bool inspect)
    {
        await using var f = await Fixture.CreateAsync(preauthorized: true);
        const string secret = "synthetic-remote-secret-message";
        f.Executor.FailureMessage = secret;
        ApiResult<McpOperationView> result;
        if (inspect)
        {
            await f.SeedIssuedAsync();
            var plan = await f.Deployments.PlanAsync("issued", new([new("target")]), "actor", default);
            result = await f.Operations.InvokeInspectionAsync(f.Caller, plan.Data!.Targets.Single().TaskId, "inspect", null, default);
        }
        else result = await f.Operations.InvokeTargetTestAsync(f.Caller, "target", "test", null, default);
        Assert.False(result.Success);
        Assert.Equal(inspect ? "REMOTE_INSPECTION_FAILED" : "REMOTE_TEST_FAILED", result.Code);
        Assert.DoesNotContain(secret, JsonSerializer.Serialize(result));
        var queried = await f.Operations.GetAsync(f.Caller, result.Data!.Id, default);
        Assert.True(queried.Success);
        Assert.DoesNotContain(secret, JsonSerializer.Serialize(queried));
        var retried = inspect
            ? await f.Operations.InvokeInspectionAsync(f.Caller, result.Data.TaskId, "inspect", result.Data.Id, default)
            : await f.Operations.InvokeTargetTestAsync(f.Caller, "target", "test", result.Data.Id, default);
        Assert.False(retried.Success);
        Assert.Equal(result.Code, retried.Code);
        Assert.Equal(1, inspect ? f.Executor.InspectCalls : f.Executor.TestCalls);
        Assert.DoesNotContain(secret, (await f.Db.McpOperations.AsNoTracking().SingleAsync()).ResourceJson);
    }

    [Fact]
    public async Task CloudErrorRemainsAvailableToWebJobButIsNotCopiedToMcpOperationOutput()
    {
        await using var f = await Fixture.CreateAsync(preauthorized: true);
        const string secret = "synthetic-cloud-secret-message";
        f.Cloud.ApplyFailure = ApiResult<CloudCertificateDetail>.Fail("OutcomeUnknown", secret);
        var prepared = await f.PrepareAsync();
        var queued = await f.Operations.SubmitAsync(f.Caller, prepared.Id, "application", default);
        await f.Certificates.ProcessJobAsync(queued.Data!.CertificateJobId, default);
        Assert.Contains(secret, (await f.Db.CertificateJobs.AsNoTracking().SingleAsync()).Message);
        Assert.DoesNotContain(secret, (await f.Db.McpOperations.AsNoTracking().SingleAsync()).Message);
        Assert.DoesNotContain(secret, JsonSerializer.Serialize(await f.Operations.GetAsync(f.Caller, prepared.Id, default)));
    }

    [Fact]
    public async Task UnknownTargetTestIsAToolErrorAndIdempotentRetryNeverReconnects()
    {
        await using var f = await Fixture.CreateAsync(preauthorized: true);
        f.Executor.ThrowOnTest = true;
        var unknown = await f.Operations.InvokeTargetTestAsync(f.Caller, "target", "unknown-test", null, default);
        Assert.False(unknown.Success);
        Assert.Equal("Unknown", unknown.Data!.Status);
        Assert.Equal("RESULT_UNKNOWN", unknown.Code);
        var retried = await f.Operations.InvokeTargetTestAsync(f.Caller, "target", "unknown-test", unknown.Data.Id, default);
        Assert.False(retried.Success);
        Assert.Equal(unknown.Data.Id, retried.Data!.Id);
        Assert.Equal(1, f.Executor.TestCalls);
    }

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, FakeAuthorization authorization, FakeCloud cloud,
        CertificateManagementService certificates, DeploymentService deployments, McpOperationService operations, FakeExecutor executor, string accountId) : IAsyncDisposable
    {
        public AppDbContext Db { get; } = db;
        public FakeAuthorization Authorization { get; } = authorization;
        public FakeCloud Cloud { get; } = cloud;
        public CertificateManagementService Certificates { get; } = certificates;
        public DeploymentService Deployments { get; } = deployments;
        public McpOperationService Operations { get; } = operations;
        public FakeExecutor Executor { get; } = executor;
        public McpCallerContext Caller { get; } = new("client", "actor", "authorization", ["ssl.write", "ssl.read"], "192.0.2.10", "admin");
        public CertificateApplyRequest Request => new(accountId, "vpn.example.test", ValidationMode: "NativeAutoDns", AutoCleanup: false);
        public async Task<McpOperationView> PrepareAsync()
        { var result = await Operations.PrepareApplicationAsync(Caller, Request, "application", default); Assert.True(result.Success, result.Message); return result.Data!; }

        public static async Task<Fixture> CreateAsync(bool preauthorized = false, SaveChangesInterceptor? interceptor = null)
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection);
            if (interceptor is not null) options.AddInterceptors(interceptor);
            var db = new AppDbContext(options.Options);
            await db.Database.EnsureCreatedAsync();
            db.Users.AddRange(new UserAccount { Id = "actor", Username = "actor", NormalizedUsername = "ACTOR", Role = "admin" },
                new UserAccount { Id = "approver", Username = "approver", NormalizedUsername = "APPROVER", Role = "admin" },
                new UserAccount { Id = "viewer", Username = "viewer", NormalizedUsername = "VIEWER", Role = "viewer" });
            var ids = new GuidIdGenerator();
            var protection = new EphemeralDataProtectionProvider();
            var accounts = new CloudAccountStore(db, protection, ids);
            var account = await accounts.CreateAsync(new() { Name = "测试云账号", Provider = "TencentCloud", AccessKeyId = "synthetic-key", AccessKeySecret = "synthetic-secret" }, default);
            var accountId = account.Data!.Id;
            db.Domains.Add(new() { Id = "zone", AccountId = accountId, ZoneId = "cloud-zone", Name = "example.test" });
            await db.SaveChangesAsync();
            var authorization = new FakeAuthorization { Preauthorized = preauthorized };
            var gate = new McpExecutionGate(db, authorization);
            var cloud = new FakeCloud();
            var resolver = new FakeCloudResolver(cloud);
            var domains = new DomainManagementService(db, accounts, resolver, ids);
            var certificates = new CertificateManagementService(db, accounts, resolver, domains, ids, gate);
            var executor = new FakeExecutor();
            var executors = new DeploymentExecutorResolver([executor]);
            var targets = new DeploymentTargetService(db, executors, protection, ids);
            var target = await targets.SaveAsync(null, new()
            {
                Name = "测试目标", ExecutorKey = "test.executor", Endpoint = "ssh.invalid", Username = "test", Password = "synthetic-password",
                Configuration = new() { SourceDomain = "vpn.example.test", OutputDirectory = "/ssl", Shell = "sh" }
            }, default);
            Assert.True(target.Success, target.Message);
            // 测试固定目标身份便于核对关联；凭据的保护用途不依赖这些测试 DTO 的名称。
            var targetRow = await db.DeploymentTargets.SingleAsync();
            var protectedCredentials = protection.CreateProtector("SslManager.Deployment.Target.v1", "target")
                .Protect(JsonSerializer.Serialize(new DeploymentCredentials { Password = "synthetic-password" }, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
            db.Entry(targetRow).State = EntityState.Detached;
            db.DeploymentTargets.Add(new() { Id = "target", Name = "固定目标", ExecutorKey = "test.executor", ExecutorRevision = "1", Endpoint = "ssh.invalid",
                Username = "test", AuthenticationMode = "Password", ProtectedCredentials = protectedCredentials, ConfigurationJson = targetRow.ConfigurationJson, ConfigRevision = 1 });
            await db.SaveChangesAsync();
            var deployments = new DeploymentService(db, targets, executors, new FakeMaterials(), protection, ids, mcpGate: gate);
            var operations = new McpOperationService(db, authorization, certificates, deployments, targets, ids);
            return new(connection, db, authorization, cloud, certificates, deployments, operations, executor, accountId);
        }
        public async Task SeedIssuedAsync()
        { Db.Certificates.Add(new() { Id = "issued", AccountId = accountId, Domain = "vpn.example.test", Status = "Issued", NotAfterUtc = DateTime.UtcNow.AddMonths(3) }); await Db.SaveChangesAsync(); }
        public async ValueTask DisposeAsync() { await Db.DisposeAsync(); await connection.DisposeAsync(); }
    }

    private sealed class IntentSaveFailure : SaveChangesInterceptor
    {
        public bool Armed { get; set; }
        private bool savedIntent;
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            savedIntent = Armed && eventData.Context!.ChangeTracker.Entries<CertificateJob>().Any(entry => entry.State == EntityState.Added);
            return ValueTask.FromResult(result);
        }
        public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        {
            if (savedIntent) { savedIntent = false; throw new InvalidOperationException("模拟意图 SQL 已执行而事务尚未提交时崩溃。"); }
            return ValueTask.FromResult(result);
        }
    }

    private sealed class FakeAuthorization : IMcpAuthorizationService
    {
        public bool Preauthorized { get; set; }
        public bool Revoked { get; set; }
        public bool RequestTokenExpired { get; set; }
        public int Revision { get; set; } = 1;
        public List<bool> WorkerChecks { get; } = [];
        public Task<ApiResult<McpEffectivePermission>> AuthorizeAsync(McpCallerContext caller, string toolName, McpResourceScope? resource, bool worker, CancellationToken ct)
        {
            WorkerChecks.Add(worker);
            return Task.FromResult(Revoked || !worker && RequestTokenExpired
                ? ApiResult<McpEffectivePermission>.Fail("MCP_REVOKED", "模拟授权撤销或请求令牌到期。")
                : ApiResult<McpEffectivePermission>.Ok(new(1, 1, Revision, [], Preauthorized)));
        }
    }
    private sealed class FakeMaterials : ICertificateMaterialService
    {
        public Task<ApiResult<CertificateMaterial>> GetAsync(string id, CancellationToken ct) => Task.FromResult(ApiResult<CertificateMaterial>.Ok(new()
        { Metadata = new(id, "vpn.example.test", ["vpn.example.test"], "fingerprint", "digest", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddMonths(3)),
            CertificatePem = "certificate", FullChainPem = "chain", PrivateKeyPem = "synthetic-private" }));
    }
    private sealed class FakeExecutor : IDeploymentExecutor
    {
        public DeploymentExecutorDescriptor Descriptor => new("test.executor", "测试执行器", "Test", "Linux", "SSH", AuthenticationModes: ["Password"]);
        public int ExecuteCalls { get; private set; }
        public int TestCalls { get; private set; }
        public int InspectCalls { get; private set; }
        public int Writes { get; private set; }
        public Action? RevokeAfterFirstMutation { get; set; }
        public string? FailureMessage { get; set; }
        public bool ThrowOnTest { get; set; }
        public Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct)
        { TestCalls++; if (ThrowOnTest) throw new IOException("模拟连接中断。"); return Task.FromResult(FailureMessage is null ? ApiResult<DeploymentConnectionTest>.Ok(new("2.x", "测试可连接"))
            : ApiResult<DeploymentConnectionTest>.Fail("REMOTE_TEST_FAILED", FailureMessage)); }
        public Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target, CertificateMaterialMetadata material, DeploymentSelection selection, CancellationToken ct) =>
            Task.FromResult(ApiResult<DeploymentTargetPlan>.Ok(new("resource:" + target.Id, "Replace", "测试预览", "{}")));
        public async Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct)
        {
            ExecuteCalls++;
            if (context.BeforeExternalMutationAsync is not null) await context.BeforeExternalMutationAsync(ct);
            Writes++; RevokeAfterFirstMutation?.Invoke();
            if (context.BeforeExternalMutationAsync is not null) await context.BeforeExternalMutationAsync(ct);
            Writes++;
            return ApiResult<DeploymentExecutionResult>.Ok(new("测试完成", Fingerprint: context.Material.Metadata.Fingerprint));
        }
        public Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct)
        { InspectCalls++; return Task.FromResult(FailureMessage is null ? ApiResult<DeploymentInspection>.Ok(new(true, "测试核对一致"))
            : ApiResult<DeploymentInspection>.Fail("REMOTE_INSPECTION_FAILED", FailureMessage)); }
    }
    private sealed class FakeCloudResolver(FakeCloud cloud) : ICloudProviderResolver
    {
        public ApiResult<ICloudCertificateService> ResolveCertificate(string provider) => ApiResult<ICloudCertificateService>.Ok(cloud);
        public ApiResult<IDnsProvider> ResolveDns(string provider) => ApiResult<IDnsProvider>.Ok(cloud);
    }
    private sealed class FakeCloud : ICloudCertificateService, IDnsProvider
    {
        public string Provider => "TencentCloud";
        public int ApplyCalls { get; private set; }
        public Func<Task>? BeforeApply { get; set; }
        public ApiResult<CloudCertificateDetail>? ApplyFailure { get; set; }
        public async Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default)
        { ApplyCalls++; if (BeforeApply is not null) await BeforeApply(); return ApplyFailure ?? Detail(new("cloud-cert")); }
        private static ApiResult<CloudCertificateDetail> Detail(CloudCertificateReference reference) => ApiResult<CloudCertificateDetail>.Ok(new(new(reference,
            "vpn.example.test", "", "PendingValidation", "Pending", true, "83", null, null, "DNS_AUTO", "request"), []));
        public Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default) => Task.FromResult(Detail(reference));
        public Task<ApiResult<CloudConnectionTest>> TestAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudOperation>> RevokeAsync(CloudAccountCredentials account, CloudCertificateReference reference, string reason, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CertificateDownload>> DownloadAsync(CloudAccountCredentials account, CloudCertificateReference reference, string format, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default) => Task.FromResult(ApiResult<IReadOnlyList<DnsRecord>>.Ok([]));
        public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string id, DnsRecordRequest request, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string id, bool enabled, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string id, CancellationToken ct = default) => throw new NotSupportedException();
    }
}
