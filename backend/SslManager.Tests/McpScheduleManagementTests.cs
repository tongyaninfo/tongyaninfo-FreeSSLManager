using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;
using SslManager.Api.Service.impl.Deployment;
using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Tests;

/// <summary>真实SQLite、授权及计划服务验证跨轮次来源；云适配器只使用内存替身。</summary>
public sealed class McpScheduleManagementTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task CreateUpdateAndStatusOnlyMutateAfterApproval()
    {
        await using var f = await Fixture.CreateAsync();
        var input = JsonSerializer.SerializeToElement(new { schedule = f.Input() }, Json);
        var prepared = await f.Invoke("ssl_schedules_create", input, "create");
        Assert.True(prepared.Success, prepared.Message); Assert.Equal("Prepared", prepared.Data!.Status);
        Assert.Empty(await f.Db.CertificateSchedules.ToListAsync()); Assert.Equal(0, f.Cloud.ApplyCalls);
        var early = await f.Invoke("ssl_schedules_create", input, "create", prepared.Data.Id);
        Assert.Equal("MCP_APPROVAL_REQUIRED", early.Code);
        await f.Approve(prepared.Data);
        var created = await f.Invoke("ssl_schedules_create", input, "create", prepared.Data.Id);
        Assert.True(created.Success, created.Message); Assert.Equal("Succeeded", created.Data!.Status);
        var row = await f.Db.CertificateSchedules.SingleAsync();
        Assert.Equal(prepared.Data.Id, await McpScheduleOrigin.FindForScheduleAsync(f.Db, row.Id, default));
        var update = f.Input(); update.Name = "修订后的计划"; update.ConfigRevision = row.ConfigRevision;
        await f.Execute("ssl_schedules_update", new { scheduleId = row.Id, schedule = update }, "update");
        f.Db.ChangeTracker.Clear(); row = await f.Db.CertificateSchedules.SingleAsync();
        Assert.Equal("修订后的计划", row.Name); Assert.True(row.ConfigRevision > 1);
        await f.Execute("ssl_schedules_status", new { scheduleId = row.Id, enabled = false }, "disable");
        Assert.False((await f.Db.CertificateSchedules.AsNoTracking().SingleAsync()).Enabled);
        Assert.Equal(0, f.Cloud.ApplyCalls); Assert.Empty(await f.Db.CertificateScheduleRuns.ToListAsync());
    }

    [Fact]
    public async Task RunIsIdempotentAndCannotBeConsumedByReplacementKey()
    {
        await using var f = await Fixture.CreateAsync(); var schedule = await f.CreateSchedule();
        var input = JsonSerializer.SerializeToElement(new { scheduleId = schedule.Id }, Json);
        var prepared = await f.Invoke("ssl_schedules_run", input, "run");
        Assert.True(prepared.Success, prepared.Message); Assert.Empty(await f.Db.CertificateScheduleRuns.ToListAsync());
        await f.Approve(prepared.Data!);
        Assert.True((await f.Invoke("ssl_schedules_run", input, "run", prepared.Data!.Id)).Success);
        var run = await f.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync();
        Assert.Equal(prepared.Data.Id, McpScheduleOrigin.ReadOperationId(run.ConfigSnapshotJson));
        Assert.True((await f.Invoke("ssl_schedules_run", input, "run", prepared.Data.Id)).Success);
        Assert.Single(await f.Db.CertificateScheduleRuns.ToListAsync()); Assert.Equal(0, f.Cloud.ApplyCalls);
        var replacement = await f.Operations.InvokeBusinessAsync(f.Caller with { ApiKeyId = "replacement-key" }, "ssl_schedules_run", input, "run", prepared.Data.Id, default);
        Assert.Equal("IDEMPOTENCY_CONFLICT", replacement.Code);
    }

    [Theory]
    [InlineData("target")]
    [InlineData("account")]
    public async Task ResourceChangedAfterApprovalPreventsScheduleCreation(string changed)
    {
        await using var f = await Fixture.CreateAsync();
        var input = JsonSerializer.SerializeToElement(new { schedule = f.Input() }, Json);
        var prepared = await f.Invoke("ssl_schedules_create", input, "create"); await f.Approve(prepared.Data!);
        if (changed == "target") await f.Db.DeploymentTargets.Where(x => x.Id == "target").ExecuteUpdateAsync(update => update.SetProperty(x => x.ConfigRevision, x => x.ConfigRevision + 1));
        else await f.Db.CloudAccounts.Where(x => x.Id == f.AccountId).ExecuteUpdateAsync(update => update.SetProperty(x => x.UpdatedAtUtc, DateTime.UtcNow.AddDays(1)));
        f.Db.ChangeTracker.Clear();
        var result = await f.Invoke("ssl_schedules_create", input, "create", prepared.Data!.Id);
        Assert.Equal("MCP_RESOURCE_CHANGED", result.Code); Assert.Empty(await f.Db.CertificateSchedules.ToListAsync());
        Assert.Null((await f.Db.McpOperations.AsNoTracking().SingleAsync()).ConsumedAtUtc); Assert.Equal(0, f.Cloud.ApplyCalls);
    }

    [Fact]
    public async Task UpdateRequiresBothOldAndNewAccountAndTargetScope()
    {
        await using var f = await Fixture.CreateAsync();
        var original = f.Input(); original.AccountId = f.OtherAccountId;
        var saved = await f.Schedules.SaveAsync(null, original, "actor", default); Assert.True(saved.Success, saved.Message);
        var rule = await f.Db.McpAllowRules.SingleAsync(); rule.AllAccounts = false; rule.AccountIdsJson = JsonSerializer.Serialize(new[] { f.AccountId });
        rule.AllTargets = false; rule.TargetIdsJson = "[\"target\"]"; await f.Db.SaveChangesAsync();
        var input = f.Input(); input.ConfigRevision = saved.Data!.ConfigRevision;
        var result = await f.Invoke("ssl_schedules_update", JsonSerializer.SerializeToElement(new { scheduleId = saved.Data.Id, schedule = input }, Json), "old-account-denied");
        Assert.Equal("FORBIDDEN", result.Code);
        var moved = await f.Schedules.SaveAsync(saved.Data.Id, input, "actor", default); Assert.True(moved.Success, moved.Message);
        var outside = f.Input(); outside.ConfigRevision = moved.Data!.ConfigRevision; outside.TargetIds = ["outside-target"];
        var denied = await f.Invoke("ssl_schedules_update", JsonSerializer.SerializeToElement(new { scheduleId = moved.Data.Id, schedule = outside }, Json), "new-target-denied");
        Assert.Equal("FORBIDDEN", denied.Code); Assert.Empty(await f.Db.McpOperations.ToListAsync());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task OriginalKeyRevocationStopsMcpRoundsAndLeavesLegacySchedulesWorking(bool mcpOrigin)
    {
        await using var f = await Fixture.CreateAsync();
        var schedule = mcpOrigin ? await f.CreateSchedule() : (await f.Schedules.SaveAsync(null, f.Input(), "actor", default)).Data!;
        await f.Db.McpApiKeys.Where(x => x.Id == "original-key").ExecuteUpdateAsync(update => update.SetProperty(x => x.Enabled, false).SetProperty(x => x.RevokedAtUtc, DateTime.UtcNow));
        var queued = await f.Schedules.RunNowAsync(schedule.Id, default); Assert.True(queued.Success, queued.Message);
        await f.Step();
        var run = await f.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync();
        if (mcpOrigin)
        { Assert.Equal("NeedsAttention", run.Status); Assert.Equal("API_KEY_REVOKED", run.Code); Assert.Equal(0, f.Cloud.ApplyCalls); }
        else
        { Assert.Equal("WaitingForIssuance", run.Status); Assert.Equal("", McpScheduleOrigin.ReadOperationId(run.ConfigSnapshotJson)); Assert.Equal(1, f.Cloud.ApplyCalls); }
    }

    [Fact]
    public async Task RecoverySerializationKeepsOriginalOperationAndRevocationStopsFollowingStep()
    {
        await using var f = await Fixture.CreateAsync(); var schedule = await f.CreateSchedule();
        Assert.True((await f.Schedules.RunNowAsync(schedule.Id, default)).Success); await f.Step();
        var run = await f.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync();
        var source = McpScheduleOrigin.ReadOperationId(run.ConfigSnapshotJson); Assert.NotEmpty(source);
        await f.Db.Certificates.Where(x => x.Id == run.CertificateId).ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, "SubmissionUnknown"));
        f.Cloud.GetFailure = ApiResult<CloudCertificateDetail>.Fail("NETWORK_ERROR", "合成查询暂不可用");
        await f.Step();
        run = await f.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync();
        Assert.Equal(source, McpScheduleOrigin.ReadOperationId(run.ConfigSnapshotJson));
        using var snapshot = JsonDocument.Parse(run.ConfigSnapshotJson);
        Assert.True(snapshot.RootElement.GetProperty("recoveryAttempts").GetInt32() > 0);
        Assert.True(f.Cloud.GetCalls > 0);
        await f.Db.McpApiKeys.Where(x => x.Id == "original-key").ExecuteUpdateAsync(update => update.SetProperty(x => x.Enabled, false));
        var queries = f.Cloud.GetCalls; await f.Step();
        Assert.Equal("API_KEY_REVOKED", (await f.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync()).Code);
        Assert.Equal(queries, f.Cloud.GetCalls); Assert.Equal(1, f.Cloud.ApplyCalls);
    }

    [Fact]
    public async Task SourceLookupsFindExactScheduleCertificateAndBatch()
    {
        await using var f = await Fixture.CreateAsync(); var schedule = await f.CreateSchedule();
        var source = await McpScheduleOrigin.FindForScheduleAsync(f.Db, schedule.Id, default); Assert.NotNull(source);
        Assert.True((await f.Schedules.RunNowAsync(schedule.Id, default)).Success);
        var run = await f.Db.CertificateScheduleRuns.SingleAsync(); run.CertificateId = "linked-certificate";
        run.TargetsJson = "[{\"batchId\":\"linked-batch\"}]"; await f.Db.SaveChangesAsync();
        Assert.Equal(source, await McpScheduleOrigin.FindForCertificateAsync(f.Db, "linked-certificate", default));
        Assert.Equal(source, await McpScheduleOrigin.FindForBatchAsync(f.Db, "linked-batch", default));
        Assert.Null(await McpScheduleOrigin.FindForScheduleAsync(f.Db, schedule.Id + "-other", default));
        Assert.Null(await McpScheduleOrigin.FindForCertificateAsync(f.Db, "other-certificate", default));
        Assert.Equal("mcp-invalid-snapshot", McpScheduleOrigin.ReadOperationId("invalid-json"));
        Assert.Equal("mcp-invalid-snapshot", McpScheduleOrigin.ReadOperationId("[]"));
        Assert.Equal("mcp-invalid-snapshot", McpScheduleOrigin.ReadOperationId("null"));
        Assert.Equal("", McpScheduleOrigin.ReadOperationId("{}"));
        Assert.Equal("source", McpScheduleOrigin.ReadOperationId(McpScheduleOrigin.WriteOperationId("{\"domain\":\"vpn.example.test\"}", "source")));
    }

    [Fact]
    public async Task ResumeUsesOriginalKeyAndApprovedResolveEndsExistingRound()
    {
        await using var f = await Fixture.CreateAsync(); var schedule = await f.CreateSchedule();
        Assert.True((await f.Schedules.RunNowAsync(schedule.Id, default)).Success);
        var run = await f.Db.CertificateScheduleRuns.SingleAsync(); run.Status = "NeedsAttention"; run.CertificateId = "existing-certificate";
        f.Db.Certificates.Add(new() { Id = run.CertificateId, AccountId = f.AccountId, Domain = "vpn.example.test", Provider = "TencentCloud", Status = "PendingValidation" });
        await f.Db.SaveChangesAsync();
        var input = JsonSerializer.SerializeToElement(new { runId = run.Id }, Json);
        var denied = await f.Operations.InvokeBusinessAsync(f.Caller with { ApiKeyId = "replacement-key" }, "ssl_schedule_runs_resume", input, "replacement-resume", null, default);
        Assert.Equal("FORBIDDEN", denied.Code);
        await f.Execute("ssl_schedule_runs_resume", new { runId = run.Id }, "resume");
        f.Db.ChangeTracker.Clear(); run = await f.Db.CertificateScheduleRuns.SingleAsync(); Assert.Equal("WaitingForIssuance", run.Status);
        run.Status = "NeedsAttention"; await f.Db.SaveChangesAsync();
        await f.Execute("ssl_schedule_runs_resolve", new { runId = run.Id, note = "合成核对已完成" }, "resolve");
        run = await f.Db.CertificateScheduleRuns.AsNoTracking().SingleAsync();
        Assert.Equal("Resolved", run.Status); Assert.False(run.Active); Assert.Equal(0, f.Cloud.ApplyCalls);
    }

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, CertificateScheduleService schedules,
        McpOperationService operations, FakeCloud cloud, string accountId, string otherAccountId) : IAsyncDisposable
    {
        public AppDbContext Db => db;
        public CertificateScheduleService Schedules => schedules;
        public McpOperationService Operations => operations;
        public FakeCloud Cloud => cloud;
        public string AccountId => accountId;
        public string OtherAccountId => otherAccountId;
        public McpCallerContext Caller { get; } = new("client", "actor", "", ["mcp.read", "mcp.write"], "127.0.0.1", "admin", AuthenticationType: "ApiKey", ApiKeyId: "original-key");
        public CertificateScheduleInput Input() => new() { Name = "合成续签计划", AccountId = accountId, Domain = "vpn.example.test", ValidationMode = "NativeAutoDns",
            TargetIds = ["target"], AutoCleanup = false, RevokeOldCertificates = false, FirstRunAtUtc = DateTime.UtcNow.AddMonths(1), IntervalUnit = "month", IntervalValue = 1, Enabled = true };
        public Task<ApiResult<McpOperationView>> Invoke(string tool, JsonElement input, string key, string? operation = null) => operations.InvokeBusinessAsync(Caller, tool, input, key, operation, default);
        public async Task Approve(McpOperationView operation)
        { var result = await operations.ApproveAsync(operation.Id, "approver", true, operation.Version, default); Assert.True(result.Success, result.Message); }
        public async Task<McpOperationView> Execute(string tool, object input, string key)
        {
            var json = JsonSerializer.SerializeToElement(input, Json); var prepared = await Invoke(tool, json, key);
            Assert.True(prepared.Success, prepared.Message); await Approve(prepared.Data!);
            var result = await Invoke(tool, json, key, prepared.Data!.Id);
            Assert.True(result.Success, result.Code + ": " + result.Message); Assert.Equal("Succeeded", result.Data!.Status); return result.Data;
        }
        public async Task<CertificateScheduleView> CreateSchedule()
        { await Execute("ssl_schedules_create", new { schedule = Input() }, "create"); return (await schedules.ListAsync(1, 20, null, default)).Data!.Items.Single(); }
        public async Task Step()
        { db.ChangeTracker.Clear(); await db.CertificateScheduleRuns.Where(x => x.Active).ExecuteUpdateAsync(update => update.SetProperty(x => x.NextCheckAtUtc, DateTime.UtcNow.AddSeconds(-1))); Assert.True(await schedules.ProcessNextAsync(default)); }
        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options); await db.Database.EnsureCreatedAsync();
            var ids = new GuidIdGenerator(); var protection = new EphemeralDataProtectionProvider();
            var accounts = new CloudAccountStore(db, protection, ids);
            var first = (await accounts.CreateAsync(new() { Name = "合成账号甲", Provider = "TencentCloud", AccessKeyId = "synthetic-key-a", AccessKeySecret = "synthetic-secret-a" }, default)).Data!;
            var second = (await accounts.CreateAsync(new() { Name = "合成账号乙", Provider = "TencentCloud", AccessKeyId = "synthetic-key-b", AccessKeySecret = "synthetic-secret-b" }, default)).Data!;
            db.Users.AddRange(new UserAccount { Id = "actor", Username = "actor", NormalizedUsername = "ACTOR", Role = "admin" }, new UserAccount { Id = "approver", Username = "approver", NormalizedUsername = "APPROVER", Role = "admin" });
            var tools = new[] { "ssl_schedules_create", "ssl_schedules_update", "ssl_schedules_status", "ssl_schedules_run", "ssl_schedule_runs_resume", "ssl_schedule_runs_resolve" };
            db.McpSettings.Add(new() { Enabled = true, Mode = "ControlledWrite", AllowedToolsJson = JsonSerializer.Serialize(tools), AllowedCidrsJson = "[\"127.0.0.0/8\"]" });
            db.McpClients.Add(new() { Id = "client-row", ClientId = "client", OAuthApplicationId = "unused", BoundUserId = "actor", Enabled = true, ScopesJson = "[\"mcp.read\",\"mcp.write\"]" });
            db.McpApiKeys.AddRange(new McpApiKey { Id = "original-key", ClientId = "client", Prefix = "synthetic-original", SecretHash = "synthetic-hash" }, new McpApiKey { Id = "replacement-key", ClientId = "client", Prefix = "synthetic-replacement", SecretHash = "synthetic-hash" });
            db.McpAllowRules.Add(new() { Id = "rule", ClientId = "client", ToolNamesJson = JsonSerializer.Serialize(tools), ScopesJson = "[\"mcp.read\",\"mcp.write\"]", AllowedCidrsJson = "[\"127.0.0.0/8\"]", AllAccounts = true, AllDomains = true, AllTargets = true });
            db.Domains.AddRange(new ManagedDomain { Id = "zone-a", AccountId = first.Id, Name = "example.test", ZoneId = "zone-a" }, new ManagedDomain { Id = "zone-b", AccountId = second.Id, Name = "example.test", ZoneId = "zone-b" });
            foreach (var id in new[] { "target", "outside-target" }) db.DeploymentTargets.Add(new() { Id = id, Name = id, ExecutorKey = "linux.files.ssh.v1", ConfigurationJson = JsonSerializer.Serialize(new DeploymentTargetConfiguration { SourceDomain = "vpn.example.test" }, Json) });
            await db.SaveChangesAsync();
            var authorization = new McpAuthorizationService(db, new(true, false, "isolated")); var gate = new McpExecutionGate(db, authorization);
            var cloud = new FakeCloud(); var providers = new FakeProviders(cloud); var domains = new DomainManagementService(db, accounts, providers, ids);
            var certificates = new CertificateManagementService(db, accounts, providers, domains, ids, gate);
            var resolver = new DeploymentExecutorResolver([]); var targets = new DeploymentTargetService(db, resolver, protection, ids);
            var deployments = new DeploymentService(db, targets, resolver, new FakeMaterials(), protection, ids, mcpGate: gate);
            var schedules = new CertificateScheduleService(db, certificates, accounts, providers, deployments, targets, ids, mcpGate: gate);
            var operations = new McpOperationService(db, authorization, certificates, deployments, targets, ids, businessDomains: domains,
                businessProtection: protection, businessSchedules: schedules, businessAccounts: accounts, businessProviders: providers);
            return new(connection, db, schedules, operations, cloud, first.Id, second.Id);
        }
        public async ValueTask DisposeAsync() { await db.DisposeAsync(); await connection.DisposeAsync(); }
    }
    private sealed class FakeMaterials : ICertificateMaterialService
    { public Task<ApiResult<CertificateMaterial>> GetAsync(string id, CancellationToken ct) => throw new InvalidOperationException("此专项不能进入远端部署。"); }
    private sealed class FakeProviders(FakeCloud cloud) : ICloudProviderResolver
    {
        public ApiResult<ICloudCertificateService> ResolveCertificate(string provider) => ApiResult<ICloudCertificateService>.Ok(cloud);
        public ApiResult<IDnsProvider> ResolveDns(string provider) => ApiResult<IDnsProvider>.Ok(cloud);
    }
    private sealed class FakeCloud : ICloudCertificateService, IDnsProvider
    {
        public string Provider => "TencentCloud";
        public int ApplyCalls { get; private set; }
        public int GetCalls { get; private set; }
        public ApiResult<CloudCertificateDetail>? GetFailure { get; set; }
        public Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default)
        { ApplyCalls++; return Task.FromResult(Detail(new("cloud-certificate"))); }
        public Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
        { GetCalls++; return Task.FromResult(GetFailure ?? Detail(reference)); }
        private static ApiResult<CloudCertificateDetail> Detail(CloudCertificateReference reference) => ApiResult<CloudCertificateDetail>.Ok(new(new(reference,
            "vpn.example.test", "", "PendingValidation", "Pending", true, "83", null, null, "DNS_AUTO", "synthetic-request"), []));
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
