using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;
using SslManager.Api.Service.impl.Deployment;
using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Tests;

/// <summary>只使用隔离 SQLite 与假云端/假目标，覆盖管理工具的审批、来源变更、凭据保护和队列身份。</summary>
public sealed class McpAdministrationTests
{
    [Fact]
    public async Task CreatingResourcesRequiresExplicitBroadFlagsEvenIfSentinelMatchesRule()
    {
        await using var f = await Fixture.CreateAsync();
        f.Authorization.AllAccounts = false;
        var account = await f.InvokeAsync("ssl_accounts_create", new { account = AccountInput() }, "account-create");
        Assert.Equal("FORBIDDEN", account.Code);
        f.Authorization.AllTargets = false;
        var target = await f.InvokeAsync("ssl_deployment_targets_create", new { target = f.TargetInput() }, "target-create");
        Assert.Equal("FORBIDDEN", target.Code);
        Assert.Empty(await f.Db.McpOperations.ToListAsync());
        Assert.Single(await f.Db.CloudAccounts.ToListAsync());
        Assert.Single(await f.Db.DeploymentTargets.ToListAsync());
    }

    [Fact]
    public async Task AccountCreationIsApprovedEncryptedAndIdempotentWithoutImplicitCloudRegistration()
    {
        await using var f = await Fixture.CreateAsync();
        var input = new { account = AccountInput() };
        var prepared = await f.PrepareAsync("ssl_accounts_create", input, "create-account");
        Assert.Single(await f.Db.CloudAccounts.ToListAsync());
        var operation = await f.Db.McpOperations.SingleAsync();
        Assert.DoesNotContain("synthetic-new-secret", operation.ArgumentsJson);
        Assert.DoesNotContain("synthetic-new-secret", prepared.SummaryJson);
        var result = await f.ConsumeAsync("ssl_accounts_create", input, "create-account", prepared);
        Assert.True(result.Success, result.Message);
        Assert.Equal(2, await f.Db.CloudAccounts.CountAsync());
        Assert.Equal(0, f.Dns.TestCalls);
        var repeated = await f.InvokeAsync("ssl_accounts_create", input, "create-account", prepared.Id);
        Assert.True(repeated.Success, repeated.Message);
        Assert.Equal(2, await f.Db.CloudAccounts.CountAsync());
        Assert.DoesNotContain("synthetic-new-secret", result.Data!.SummaryJson);
    }

    [Fact]
    public async Task ChangedAccountSourceCannotBeOverwrittenAfterApproval()
    {
        await using var f = await Fixture.CreateAsync();
        var input = new { accountId = f.AccountId, account = AccountInput() };
        var prepared = await f.PrepareAsync("ssl_accounts_update", input, "update-account");
        var row = await f.Db.CloudAccounts.SingleAsync();
        row.Name = "后台已修改"; row.UpdatedAtUtc = DateTime.UtcNow.AddSeconds(1);
        await f.Db.SaveChangesAsync();
        var result = await f.ConsumeAsync("ssl_accounts_update", input, "update-account", prepared);
        Assert.Equal("MCP_RESOURCE_CHANGED", result.Code);
        Assert.Equal("后台已修改", (await f.Db.CloudAccounts.SingleAsync()).Name);
    }

    [Fact]
    public async Task AccountTestWaitsForApprovalAndNeverPublishesProviderMessage()
    {
        await using var f = await Fixture.CreateAsync();
        var input = new { accountId = f.AccountId, testKind = "Dns" };
        var prepared = await f.PrepareAsync("ssl_accounts_test", input, "test-account");
        Assert.Equal(0, f.Dns.TestCalls);
        var result = await f.ConsumeAsync("ssl_accounts_test", input, "test-account", prepared);
        Assert.True(result.Success, result.Message);
        Assert.Equal(1, f.Dns.TestCalls);
        Assert.DoesNotContain("provider-secret-response", result.Data!.SummaryJson);
        Assert.DoesNotContain("provider-secret-response", (await f.Db.CloudAccounts.SingleAsync()).LastTestMessage);
    }

    [Fact]
    public async Task NewTargetCannotIntroduceShellCommands()
    {
        await using var f = await Fixture.CreateAsync();
        var target = f.TargetInput();
        target.Configuration.PostCommands.Add(new("arbitrary-shell-command"));
        var result = await f.InvokeAsync("ssl_deployment_targets_create", new { target }, "create-target");
        Assert.Equal("VALIDATION", result.Code);
        Assert.Empty(await f.Db.McpOperations.ToListAsync());
    }

    [Fact]
    public async Task TargetApprovalShowsHostAndPortWithoutUrlCredentialsPathsOrQueries()
    {
        await using var f = await Fixture.CreateAsync();
        var target = f.TargetInput();
        target.Endpoint = "https://user:synthetic-url-secret@node.example.test:8443/private?token=synthetic-url-token";
        var prepared = await f.PrepareAsync("ssl_deployment_targets_create", new { target }, "target-destination");
        Assert.Contains("node.example.test", prepared.SummaryJson);
        Assert.Contains("8443", prepared.SummaryJson);
        Assert.DoesNotContain("synthetic-url-secret", prepared.SummaryJson);
        Assert.DoesNotContain("synthetic-url-token", prepared.SummaryJson);
        Assert.DoesNotContain("/private", prepared.SummaryJson);
    }

    [Fact]
    public async Task TargetUpdateRequiresBothOldAndNewDomainPermissions()
    {
        await using var f = await Fixture.CreateAsync();
        f.Authorization.DeniedDomain = "other.example.test";
        var target = f.TargetInput(); target.Configuration.SourceDomain = "other.example.test";
        var result = await f.InvokeAsync("ssl_deployment_targets_update", new { targetId = f.TargetId, target }, "update-target");
        Assert.Equal("FORBIDDEN", result.Code);
        Assert.Empty(await f.Db.McpOperations.ToListAsync());
    }

    [Fact]
    public async Task UpdatingConnectionPreservesExistingScriptsWithoutExposingThem()
    {
        await using var f = await Fixture.CreateAsync();
        var row = await f.Db.DeploymentTargets.SingleAsync();
        var configuration = JsonSerializer.Deserialize<DeploymentTargetConfiguration>(row.ConfigurationJson, Fixture.Json)!;
        configuration.PostCommands = [new("existing-private-reload-script")];
        row.ConfigurationJson = JsonSerializer.Serialize(configuration, Fixture.Json);
        await f.Db.SaveChangesAsync();
        var input = new { targetId = f.TargetId, target = f.TargetInput() };
        var prepared = await f.PrepareAsync("ssl_deployment_targets_update", input, "update-target");
        Assert.DoesNotContain("existing-private-reload-script", prepared.SummaryJson);
        var result = await f.ConsumeAsync("ssl_deployment_targets_update", input, "update-target", prepared);
        Assert.True(result.Success, result.Message);
        await f.Db.Entry(row).ReloadAsync();
        Assert.Contains("existing-private-reload-script", row.ConfigurationJson);
        Assert.DoesNotContain("existing-private-reload-script", result.Data!.SummaryJson);
        Assert.DoesNotContain("synthetic-target-password", result.Data.SummaryJson);
    }

    [Fact]
    public async Task DiscoveryIsApprovedAndFiltersUnauthorizedDomainsAndRemoteText()
    {
        await using var f = await Fixture.CreateAsync();
        f.Authorization.DeniedDomain = "other.example.test";
        var input = new { targetId = f.TargetId };
        var prepared = await f.PrepareAsync("ssl_deployment_targets_discover", input, "discover-target");
        Assert.Equal(0, f.Executor.DiscoverCalls);
        var result = await f.ConsumeAsync("ssl_deployment_targets_discover", input, "discover-target", prepared);
        Assert.True(result.Success, result.Message);
        Assert.Equal(1, f.Executor.DiscoverCalls);
        Assert.Contains("visible-cert", result.Data!.SummaryJson);
        Assert.DoesNotContain("hidden-cert", result.Data.SummaryJson);
        Assert.DoesNotContain("remote-private-name", result.Data.SummaryJson);
    }

    [Fact]
    public async Task TaskCancellationOnlyExecutesAfterApproval()
    {
        await using var f = await Fixture.CreateAsync();
        var task = await f.SeedDeploymentAsync("Draft");
        var input = new { taskId = task.Id };
        var prepared = await f.PrepareAsync("ssl_deployment_tasks_cancel", input, "cancel-task");
        Assert.Equal("Draft", (await f.Db.DeploymentTasks.SingleAsync()).Status);
        var result = await f.ConsumeAsync("ssl_deployment_tasks_cancel", input, "cancel-task", prepared);
        Assert.True(result.Success, result.Message);
        Assert.Equal("Cancelled", (await f.Db.DeploymentTasks.AsNoTracking().SingleAsync()).Status);
    }

    [Fact]
    public async Task RunningTaskHeartbeatDoesNotInvalidateCancellationIdentity()
    {
        await using var f = await Fixture.CreateAsync();
        var task = await f.SeedDeploymentAsync("Running");
        var input = new { taskId = task.Id };
        var prepared = await f.PrepareAsync("ssl_deployment_tasks_cancel", input, "cancel-running");
        task.LeaseUntilUtc = DateTime.UtcNow.AddMinutes(1); task.Phase = "Uploading";
        await f.Db.SaveChangesAsync();
        var result = await f.ConsumeAsync("ssl_deployment_tasks_cancel", input, "cancel-running", prepared);
        Assert.True(result.Success, result.Message);
        var current = await f.Db.DeploymentTasks.AsNoTracking().SingleAsync();
        Assert.True(current.CancelRequested);
        Assert.Equal("Running", current.Status);
    }

    [Theory]
    [InlineData("ssl_deployment_tasks_retry_plan", "Failed")]
    [InlineData("ssl_deployment_tasks_rollback_plan", "Succeeded")]
    public async Task ManagementPlansCreateSeparateApprovedDeploymentSourceAndOriginalKeyGuardsQueue(string tool, string sourceStatus)
    {
        await using var f = await Fixture.CreateAsync();
        var task = await f.SeedDeploymentAsync(sourceStatus);
        var input = new { taskId = task.Id };
        var prepared = await f.PrepareAsync(tool, input, "management-plan");
        var result = await f.ConsumeAsync(tool, input, "management-plan", prepared);
        Assert.True(result.Success, result.Message);
        var parent = await f.Db.McpOperations.AsNoTracking().SingleAsync(x => x.Id == prepared.Id);
        var child = await f.Db.McpOperations.AsNoTracking().SingleAsync(x => x.Kind == "Deployment");
        Assert.Equal(parent.BatchId, child.BatchId);
        Assert.NotEqual(task.BatchId, child.BatchId);
        Assert.Equal("Prepared", child.Status);
        Assert.Equal(f.Caller.ApiKeyId, child.ApiKeyId);
        Assert.Equal("Draft", (await f.Db.DeploymentBatches.AsNoTracking().SingleAsync(x => x.Id == child.BatchId)).Status);
        var approved = await f.Operations.ApproveAsync(child.Id, "approver", true, child.Version, default);
        Assert.True(approved.Success, approved.Message);
        var submitted = await f.Operations.SubmitAsync(f.Caller, child.Id, child.IdempotencyKey, default);
        Assert.True(submitted.Success, submitted.Message);
        f.Authorization.Blocked = true;
        await f.Deployments.ProcessNextAsync(default);
        Assert.Equal(0, f.Executor.ExecuteCalls);
    }

    [Fact]
    public async Task ManualResolutionKeepsOriginalNoteEncryptedAndDoesNotClaimRemoteSuccess()
    {
        await using var f = await Fixture.CreateAsync();
        var task = await f.SeedDeploymentAsync("NeedsAttention");
        var input = new { taskId = task.Id, note = "人工核对记录 synthetic-sensitive-note" };
        var prepared = await f.PrepareAsync("ssl_deployment_tasks_resolve", input, "resolve-task");
        var result = await f.ConsumeAsync("ssl_deployment_tasks_resolve", input, "resolve-task", prepared);
        Assert.True(result.Success, result.Message);
        Assert.DoesNotContain("synthetic-sensitive-note", result.Data!.SummaryJson);
        Assert.All(await f.Db.AuditLogs.ToArrayAsync(), entry => Assert.DoesNotContain("synthetic-sensitive-note", entry.Message));
        Assert.Equal("Resolved", (await f.Db.DeploymentTasks.AsNoTracking().SingleAsync()).Status);
        Assert.Contains("\"remoteSuccessConfirmed\":false", result.Data.SummaryJson);
    }

    private static CloudAccountInput AccountInput() => new() { Name = "新账号", Provider = "TencentCloud", AccessKeyId = "synthetic-new-id", AccessKeySecret = "synthetic-new-secret" };

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, Authorization authorization,
        Dns dns, Executor executor, DeploymentService deployments, McpOperationService operations, string accountId, string targetId) : IAsyncDisposable
    {
        public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
        public AppDbContext Db { get; } = db;
        public Authorization Authorization { get; } = authorization;
        public Dns Dns { get; } = dns;
        public Executor Executor { get; } = executor;
        public DeploymentService Deployments { get; } = deployments;
        public McpOperationService Operations { get; } = operations;
        public string AccountId { get; } = accountId;
        public string TargetId { get; } = targetId;
        public McpCallerContext Caller { get; } = new("client", "actor", "", ["mcp.read", "mcp.write"], "192.0.2.10", "admin", "ApiKey", "source-key");
        public DeploymentTargetInput TargetInput() => new() { Name = "测试目标", ExecutorKey = "test.executor", Endpoint = "ssh.invalid", Username = "tester", Password = "synthetic-target-password", Configuration = new() { SourceDomain = "vpn.example.test", OutputDirectory = "/ssl", Shell = "sh" } };
        public Task<ApiResult<McpOperationView>> InvokeAsync(string tool, object input, string key, string? operationId = null) =>
            Operations.InvokeBusinessAsync(Caller, tool, JsonSerializer.SerializeToElement(input, Json), key, operationId, default);
        public async Task<McpOperationView> PrepareAsync(string tool, object input, string key)
        {
            var result = await InvokeAsync(tool, input, key);
            Assert.True(result.Success, result.Message);
            Assert.Equal("Prepared", result.Data!.Status);
            return result.Data;
        }
        public async Task<ApiResult<McpOperationView>> ConsumeAsync(string tool, object input, string key, McpOperationView prepared)
        {
            var approved = await Operations.ApproveAsync(prepared.Id, "approver", true, prepared.Version, default);
            Assert.True(approved.Success, approved.Message);
            return await InvokeAsync(tool, input, key, prepared.Id);
        }
        public async Task<DeploymentTask> SeedDeploymentAsync(string status)
        {
            Db.Certificates.Add(new() { Id = "issued", AccountId = AccountId, Domain = "vpn.example.test", Status = "Issued", NotAfterUtc = DateTime.UtcNow.AddMonths(3) });
            await Db.SaveChangesAsync();
            var plan = await Deployments.PlanAsync("issued", new([new(TargetId)]), "web-user", default);
            Assert.True(plan.Success, plan.Message);
            var task = await Db.DeploymentTasks.SingleAsync();
            task.Status = status; task.ReceiptJson = "{\"schemaVersion\":1,\"executionState\":\"Completed\"}";
            await Db.SaveChangesAsync();
            return task;
        }
        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            db.Users.AddRange(new UserAccount { Id = "actor", Username = "actor", NormalizedUsername = "ACTOR", Role = "admin" },
                new UserAccount { Id = "approver", Username = "approver", NormalizedUsername = "APPROVER", Role = "admin" });
            await db.SaveChangesAsync();
            var ids = new GuidIdGenerator(); var protection = new EphemeralDataProtectionProvider();
            var accounts = new CloudAccountStore(db, protection, ids);
            var account = await accounts.CreateAsync(AccountInput(), default); Assert.True(account.Success, account.Message);
            var dns = new Dns(); var providers = new Providers(dns);
            var authorization = new Authorization(); var gate = new McpExecutionGate(db, authorization);
            var domains = new DomainManagementService(db, accounts, providers, ids);
            var certificates = new CertificateManagementService(db, accounts, providers, domains, ids, gate);
            var executor = new Executor(); var executors = new DeploymentExecutorResolver([executor]);
            var targets = new DeploymentTargetService(db, executors, protection, ids);
            var target = await targets.SaveAsync(null, new() { Name = "已存目标", ExecutorKey = "test.executor", Endpoint = "ssh.invalid", Username = "tester", Password = "synthetic-target-password", Configuration = new() { SourceDomain = "vpn.example.test", OutputDirectory = "/ssl", Shell = "sh" } }, default);
            Assert.True(target.Success, target.Message);
            var deployments = new DeploymentService(db, targets, executors, new Materials(), protection, ids, mcpGate: gate);
            var operations = new McpOperationService(db, authorization, certificates, deployments, targets, ids,
                businessProtection: protection, businessAccounts: accounts, businessProviders: providers);
            return new(connection, db, authorization, dns, executor, deployments, operations, account.Data!.Id, target.Data!.Id);
        }
        public async ValueTask DisposeAsync() { await Db.DisposeAsync(); await connection.DisposeAsync(); }
    }

    private sealed class Authorization : IMcpAuthorizationService
    {
        public bool AllAccounts { get; set; } = true;
        public bool AllTargets { get; set; } = true;
        public bool Blocked { get; set; }
        public string DeniedDomain { get; set; } = "";
        public Task<ApiResult<McpEffectivePermission>> AuthorizeAsync(McpCallerContext caller, string toolName, McpResourceScope? resource, bool worker, CancellationToken ct) =>
            Task.FromResult(Blocked || resource?.Domain.Length > 0 && resource.Domain == DeniedDomain
                ? ApiResult<McpEffectivePermission>.Fail("FORBIDDEN", "模拟原Key撤销或域名不允许。")
                : ApiResult<McpEffectivePermission>.Ok(new(1, 1, 1, [new() { AllAccounts = AllAccounts, AllTargets = AllTargets, AllDomains = true }], false)));
    }
    private sealed class Materials : ICertificateMaterialService
    {
        public Task<ApiResult<CertificateMaterial>> GetAsync(string id, CancellationToken ct) => Task.FromResult(ApiResult<CertificateMaterial>.Ok(new()
        { Metadata = new(id, "vpn.example.test", ["vpn.example.test"], "fingerprint", "digest", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddMonths(3)), CertificatePem = "certificate", FullChainPem = "chain", PrivateKeyPem = "synthetic-private" }));
    }
    private sealed class Executor : IDeploymentExecutor, IDeploymentDiscoveryExecutor, IRollbackDeploymentExecutor
    {
        public DeploymentExecutorDescriptor Descriptor => new("test.executor", "假执行器", "Test", "Linux", "SSH", AuthenticationModes: ["Password"], SupportsRollback: true);
        public int DiscoverCalls { get; private set; }
        public int ExecuteCalls { get; private set; }
        public Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct) => Task.FromResult(ApiResult<DeploymentConnectionTest>.Ok(new("1.0", "connected")));
        public Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target, CertificateMaterialMetadata material, DeploymentSelection selection, CancellationToken ct) => Task.FromResult(ApiResult<DeploymentTargetPlan>.Ok(new("resource:" + target.Id, "Replace", "test plan")));
        public Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct) { ExecuteCalls++; return Task.FromResult(ApiResult<DeploymentExecutionResult>.Ok(new("done"))); }
        public Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct) => Task.FromResult(ApiResult<DeploymentInspection>.Ok(new(true, "checked")));
        public Task<ApiResult<DeploymentRollbackResult>> RollbackAsync(DeploymentRollbackContext context, CancellationToken ct) { ExecuteCalls++; return Task.FromResult(ApiResult<DeploymentRollbackResult>.Ok(new("rollback"))); }
        public Task<ApiResult<DeploymentDiscovery>> DiscoverAsync(DeploymentTargetContext target, CancellationToken ct)
        { DiscoverCalls++; return Task.FromResult(ApiResult<DeploymentDiscovery>.Ok(new([new("visible-cert", "remote-private-name", ["vpn.example.test"]), new("hidden-cert", "remote-private-name", ["other.example.test"])], []))); }
    }
    private sealed class Providers(Dns dns) : ICloudProviderResolver
    {
        public ApiResult<ICloudCertificateService> ResolveCertificate(string provider) => ApiResult<ICloudCertificateService>.Fail("UNSUPPORTED", "not used");
        public ApiResult<IDnsProvider> ResolveDns(string provider) => ApiResult<IDnsProvider>.Ok(dns);
    }
    private sealed class Dns : IDnsProvider
    {
        public string Provider => "TencentCloud";
        public int TestCalls { get; private set; }
        public Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default) { TestCalls++; return Task.FromResult(ApiResult<CloudConnectionTest>.Ok(new(Provider, "request", "provider-secret-response"))); }
        public Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string recordId, DnsRecordRequest request, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string recordId, bool enabled, CancellationToken ct = default) => throw new NotSupportedException();
        public Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string recordId, CancellationToken ct = default) => throw new NotSupportedException();
    }
}
