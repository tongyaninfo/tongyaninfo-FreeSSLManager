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

/// <summary>使用真实 SQLite 查询验证白名单在 Count/分页前生效，响应只投影允许的业务字段。</summary>
public sealed class McpToolQueryTests
{
    private static readonly McpCallerContext Caller = new("client", "user", "grant", ["mcp.read", "mcp.write"], "127.0.0.1");
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Fact]
    public void CatalogHasExactlyReviewedToolsAndNoSecretOrArbitraryCommandEntry()
    {
        Assert.Equal(50, McpToolCatalog.All.Count);
        Assert.Equal(17, McpToolCatalog.All.Count(x => x.ReadOnly));
        Assert.Equal(50, McpToolCatalog.All.Select(x => x.Name).Distinct().Count());
        foreach (var tool in McpToolCatalog.All)
        {
            Assert.False(tool.InputSchema.GetProperty("additionalProperties").GetBoolean());
            if (tool.Name is not ("ssl_accounts_create" or "ssl_accounts_update" or "ssl_deployment_targets_create" or "ssl_deployment_targets_update"))
            {
                Assert.DoesNotContain("password", tool.InputSchema.GetRawText(), StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain("privateKey", tool.InputSchema.GetRawText(), StringComparison.OrdinalIgnoreCase);
            }
            void CheckCommands(JsonElement schema)
            {
                if (schema.ValueKind == JsonValueKind.Object)
                {
                    if (schema.TryGetProperty("properties", out var properties))
                        foreach (var property in properties.EnumerateObject())
                            if (property.Name.Contains("command", StringComparison.OrdinalIgnoreCase))
                            {
                                Assert.Equal("harborComposeCommand", property.Name);
                                Assert.Equal(new[] { "docker compose", "docker-compose" }, property.Value.GetProperty("enum").EnumerateArray().Select(x => x.GetString()).ToArray());
                            }
                    foreach (var property in schema.EnumerateObject()) CheckCommands(property.Value);
                }
                else if (schema.ValueKind == JsonValueKind.Array) foreach (var item in schema.EnumerateArray()) CheckCommands(item);
            }
            CheckCommands(tool.InputSchema);
        }
        Assert.True(McpToolCatalog.RequiresAdmin("ssl_deployment_targets_list"));
        Assert.False(McpToolCatalog.RequiresAdmin("ssl_certificates_list"));
        foreach (var tool in McpToolCatalog.All.Where(tool => !tool.ReadOnly))
            Assert.Contains(tool.InputSchema.GetProperty("required").EnumerateArray(), value => value.GetString() == "systemInstanceId");
    }

    [Fact]
    public async Task AgentSeesDistinctSystemIdentityAndCannotWriteToAnotherInstance()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Db.McpSettings.Add(new() { InstanceId = "production-instance", SystemName = "生产证书中心", PublicBaseUrl = "https://ssl.example.test" });
        await fixture.Db.SaveChangesAsync();
        var tools = await fixture.Tools.ListAsync(Caller, default);
        Assert.All(tools, tool => Assert.Contains("生产证书中心", tool.Title));
        Assert.All(tools, tool => Assert.Contains("production-instance", tool.Description));
        var status = JsonSerializer.SerializeToElement((await fixture.Call("ssl_system_status_get", new { })).Data, Json);
        Assert.Equal("生产证书中心", status.GetProperty("systemName").GetString());
        Assert.Equal("production-instance", status.GetProperty("systemInstanceId").GetString());
        Assert.Equal("https://ssl.example.test/mcp", status.GetProperty("mcpUrl").GetString());
        var rejected = await fixture.Call("ssl_deployment_targets_test", new
        { targetId = "allowed", idempotencyKey = "test-instance-key", systemInstanceId = "other-instance" }, false);
        Assert.Equal("INSTANCE_MISMATCH", rejected.Code);
        Assert.Equal(0, fixture.Provider.Calls);
    }

    [Fact]
    public async Task StagingCertificateAndAcmeReadinessAreVisibleWithoutCredentials()
    {
        await using var fixture = await Fixture.CreateAsync();
        var account = await fixture.Db.CloudAccounts.SingleAsync();
        account.Provider = "Acme"; account.AcmeDirectoryUrl = AcmeProtocolClient.StagingDirectory;
        account.AcmeRegistrationStatus = "Registered";
        fixture.Db.Certificates.Add(new() { Id = "staging", AccountId = "a", Domain = "api.example.test", Provider = "Acme",
            Status = "Issued", IsStaging = true, HasPrivateKey = true });
        await fixture.Db.SaveChangesAsync();
        var accounts = JsonSerializer.SerializeToElement((await fixture.Call("ssl_accounts_list", new { })).Data, Json);
        var row = Assert.Single(accounts.GetProperty("items").EnumerateArray());
        Assert.Equal("Staging", row.GetProperty("acmeEnvironment").GetString());
        Assert.True(row.GetProperty("acmeReady").GetBoolean());
        Assert.DoesNotContain("synthetic", accounts.GetRawText());
        Assert.DoesNotContain("protected", accounts.GetRawText(), StringComparison.OrdinalIgnoreCase);
        var list = JsonSerializer.SerializeToElement((await fixture.Call("ssl_certificates_list", new { })).Data, Json);
        var certificate = Assert.Single(list.GetProperty("items").EnumerateArray());
        Assert.True(certificate.GetProperty("isStaging").GetBoolean());
        Assert.False(certificate.GetProperty("canDeploy").GetBoolean());
        var detail = JsonSerializer.SerializeToElement((await fixture.Call("ssl_certificates_get", new { certificateId = "staging" })).Data, Json);
        Assert.False(detail.GetProperty("certificate").GetProperty("canDeploy").GetBoolean());
    }

    [Theory]
    [InlineData(false, "ManualDns")]
    [InlineData(true, "ManagedDns")]
    public async Task AcmeDefaultValidationUsesDns01WithoutRegisteringAccount(bool explicitZone, string expectedMode)
    {
        await using var fixture = await Fixture.CreateAsync();
        var account = await fixture.Db.CloudAccounts.SingleAsync(); account.Provider = "Acme";
        fixture.Db.McpSettings.Add(new() { InstanceId = "test-instance" });
        await fixture.Db.SaveChangesAsync();
        var arguments = new Dictionary<string, object> { ["accountId"] = "a", ["domain"] = "api.example.test",
            ["idempotencyKey"] = "acme-prepare-key", ["systemInstanceId"] = "test-instance" };
        if (explicitZone) arguments["dnsZoneId"] = "cross-account-zone";
        await fixture.Call("ssl_certificate_application_prepare", arguments, false);
        Assert.Equal(expectedMode, fixture.Operations.LastApplication?.ValidationMode);
        Assert.Equal(0, fixture.Provider.Calls);
    }

    [Fact]
    public async Task CrossAccountDnsScheduleRequiresSameRuleToCoverBothAccounts()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Db.Domains.Add(new() { Id = "dns-zone", AccountId = "b", Name = "example.test" });
        fixture.Db.CertificateSchedules.Add(new() { Id = "plan", Name = "跨账号续签", AccountId = "a", Domain = "api.example.test",
            DnsZoneId = "dns-zone", TargetIdsJson = "[]" });
        await fixture.Db.SaveChangesAsync();
        var hidden = JsonSerializer.SerializeToElement((await fixture.Call("ssl_schedules_list", new { })).Data, Json);
        Assert.Equal(0, hidden.GetProperty("total").GetInt32());
        fixture.Authorization.Rules = [new() { AccountIds = ["a", "b"], Domains = ["api.example.test"], AllTargets = true }];
        var visible = JsonSerializer.SerializeToElement((await fixture.Call("ssl_schedules_list", new { })).Data, Json);
        Assert.Equal("dns-zone", Assert.Single(visible.GetProperty("items").EnumerateArray()).GetProperty("dnsZoneId").GetString());
    }

    [Theory]
    [InlineData("{\"page\":\"1\"}")]
    [InlineData("{\"pageSize\":101}")]
    [InlineData("{\"userId\":\"admin\"}")]
    [InlineData("{\"page\":1,\"page\":2}")]
    public async Task InvalidArgumentsNeverReachBusinessOperation(string json)
    {
        await using var fixture = await Fixture.CreateAsync();
        var result = await fixture.Tools.CallAsync(Caller, "ssl_certificates_list", JsonDocument.Parse(json).RootElement, default);
        Assert.False(result.Success); Assert.Equal("INVALID_ARGUMENTS", result.Code);
        Assert.Equal(0, fixture.Provider.Calls);
    }

    [Fact]
    public async Task CertificateFilteringRunsBeforeTotalAndPaginationAndExcludesMaterial()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Db.Certificates.AddRange(
            new() { Id = "hidden-first", AccountId = "b", Domain = "api.example.test", NotAfterUtc = DateTime.UtcNow.AddYears(2) },
            new() { Id = "allowed-first", AccountId = "a", Domain = "api.example.test", NotAfterUtc = DateTime.UtcNow.AddDays(5) },
            new() { Id = "allowed-second", AccountId = "a", Domain = "api.example.test", NotAfterUtc = DateTime.UtcNow.AddDays(4) },
            new() { Id = "wrong-domain", AccountId = "a", Domain = "other.example.test" });
        await fixture.Db.SaveChangesAsync();
        var result = await fixture.Call("ssl_certificates_list", new { page = 1, pageSize = 1 });
        var body = JsonSerializer.SerializeToElement(result.Data, Json);
        Assert.Equal(2, body.GetProperty("total").GetInt32());
        Assert.Equal("allowed-first", Assert.Single(body.GetProperty("items").EnumerateArray()).GetProperty("id").GetString());
        Assert.DoesNotContain("hidden-first", body.GetRawText());
        Assert.DoesNotContain("protected", body.GetRawText(), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task DistinctRulesCannotBeCombinedToInventAnAccountDomainGrant()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Authorization.Rules = [new() { AccountIds = ["a"], Domains = ["api.example.test"] },
            new() { AccountIds = ["b"], Domains = ["other.example.test"] }];
        fixture.Db.Certificates.Add(new() { Id = "cross-rule", AccountId = "a", Domain = "other.example.test" });
        await fixture.Db.SaveChangesAsync();
        var result = await fixture.Call("ssl_certificates_list", new { });
        Assert.Equal(0, JsonSerializer.SerializeToElement(result.Data, Json).GetProperty("total").GetInt32());
        Assert.Equal("NOT_FOUND", (await fixture.Call("ssl_certificates_get", new { certificateId = "cross-rule" }, false)).Code);
    }

    [Fact]
    public async Task DomainWildcardRespectsLabelBoundaryAndDoesNotIncludeApex()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Authorization.Rules = [new() { AccountIds = ["a"], Domains = ["*.example.test"] }];
        fixture.Db.Certificates.AddRange(new() { Id = "child", AccountId = "a", Domain = "api.example.test" },
            new() { Id = "apex", AccountId = "a", Domain = "example.test" },
            new() { Id = "lookalike", AccountId = "a", Domain = "evilexample.test" });
        await fixture.Db.SaveChangesAsync();
        var body = JsonSerializer.SerializeToElement((await fixture.Call("ssl_certificates_list", new { })).Data, Json);
        Assert.Equal(1, body.GetProperty("total").GetInt32());
        Assert.Equal("child", Assert.Single(body.GetProperty("items").EnumerateArray()).GetProperty("id").GetString());
    }

    [Fact]
    public async Task DnsChildGrantCanReadOnlyThatNameWithinParentZone()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Db.Domains.Add(new() { Id = "zone", AccountId = "a", Name = "example.test", ZoneId = "cloud-zone" });
        fixture.Provider.Records = [new("1", "example.test", "api", "A", "192.0.2.1", 600, "Enabled", "default", ""),
            new("2", "example.test", "private", "TXT", "forbidden-record-value", 600, "Enabled", "default", "")];
        await fixture.Db.SaveChangesAsync();
        var body = JsonSerializer.SerializeToElement((await fixture.Call("ssl_dns_records_list", new { zoneId = "zone" })).Data, Json);
        Assert.Equal(1, body.GetProperty("total").GetInt32());
        Assert.DoesNotContain("forbidden-record-value", body.GetRawText());
        Assert.Equal(1, fixture.Provider.Calls);
    }

    [Fact]
    public async Task DnsAbsoluteNameOutsideZoneIsNotReinterpretedAsRelative()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Authorization.Rules = [new() { AllAccounts = true, AllDomains = true }];
        fixture.Db.Domains.Add(new() { Id = "zone", AccountId = "a", Name = "example.test", ZoneId = "cloud-zone" });
        fixture.Provider.Records = [new("1", "example.test", "api.example.test.", "A", "192.0.2.1", 600, "Enabled", "default", ""),
            new("2", "example.test", "outside.other.test.", "TXT", "outside-value", 600, "Enabled", "default", "")];
        await fixture.Db.SaveChangesAsync();
        var body = JsonSerializer.SerializeToElement((await fixture.Call("ssl_dns_records_list", new { zoneId = "zone" })).Data, Json);
        Assert.Equal(1, body.GetProperty("total").GetInt32());
        Assert.DoesNotContain("outside-value", body.GetRawText());
    }

    [Fact]
    public async Task BatchWithAnyUnauthorizedTargetIsHiddenIncludingItsTotals()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Db.Certificates.Add(new() { Id = "cert", AccountId = "a", Domain = "api.example.test" });
        fixture.Db.DeploymentTargets.AddRange(new() { Id = "allowed", ConfigurationJson = "{\"sourceDomain\":\"api.example.test\"}" },
            new() { Id = "forbidden", ConfigurationJson = "{}", ProtectedCredentials = "forbidden-secret" });
        fixture.Db.DeploymentBatches.AddRange(new() { Id = "safe", CertificateId = "cert" }, new() { Id = "mixed", CertificateId = "cert" });
        fixture.Db.DeploymentTasks.AddRange(new() { Id = "safe-task", BatchId = "safe", TargetId = "allowed", ReceiptJson = "forbidden-receipt" },
            new() { Id = "mixed-a", BatchId = "mixed", TargetId = "allowed" }, new() { Id = "mixed-b", BatchId = "mixed", TargetId = "forbidden" });
        await fixture.Db.SaveChangesAsync();
        var body = JsonSerializer.SerializeToElement((await fixture.Call("ssl_deployments_list", new { })).Data, Json);
        Assert.Equal(1, body.GetProperty("total").GetInt32());
        Assert.Equal("NOT_FOUND", (await fixture.Call("ssl_deployments_get", new { batchId = "mixed" }, false)).Code);
        var detail = await fixture.Call("ssl_deployment_tasks_get", new { taskId = "safe-task" });
        Assert.DoesNotContain("forbidden-receipt", JsonSerializer.Serialize(detail, Json));
    }

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, StubAuthorization authorization, DnsProvider dns, McpToolDispatcher tools, Operations operations) : IAsyncDisposable
    {
        public AppDbContext Db => db; public StubAuthorization Authorization => authorization; public DnsProvider Provider => dns; public McpToolDispatcher Tools => tools;
        public Operations Operations => operations;
        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            var protection = new EphemeralDataProtectionProvider();
            var protector = protection.CreateProtector("SslManager.CloudAccount.v1", "a");
            db.CloudAccounts.Add(new() { Id = "a", Provider = "TencentCloud", Name = "allowed", Enabled = true, UseForDns = true,
                ProtectedAccessKeyId = protector.Protect("synthetic-key"), ProtectedAccessKeySecret = protector.Protect("synthetic-secret") });
            await db.SaveChangesAsync();
            var accounts = new CloudAccountStore(db, protection, new GuidIdGenerator()); var dns = new DnsProvider();
            var domains = new DomainManagementService(db, accounts, new Resolver(dns), new GuidIdGenerator());
            var auth = new StubAuthorization();
            var operations = new Operations();
            return new(connection, db, auth, dns, new(db, auth, domains, new DeploymentExecutorResolver([]), operations), operations);
        }
        public async Task<ApiResult<object>> Call(string name, object arguments, bool success = true)
        {
            var result = await Tools.CallAsync(Caller, name, JsonSerializer.SerializeToElement(arguments, Json), default);
            if (success) Assert.True(result.Success, result.Message); return result;
        }
        public async ValueTask DisposeAsync() { await db.DisposeAsync(); await connection.DisposeAsync(); }
    }
    private sealed class StubAuthorization : IMcpAuthorizationService
    {
        public IReadOnlyList<McpAllowRuleInput> Rules { get; set; } = [new() { AccountIds = ["a"], Domains = ["api.example.test"], TargetIds = ["allowed"] }];
        public Task<ApiResult<McpEffectivePermission>> AuthorizeAsync(McpCallerContext caller, string toolName, McpResourceScope? resource, bool worker, CancellationToken ct)
            => Task.FromResult(ApiResult<McpEffectivePermission>.Ok(new(1, 1, 1, Rules)));
    }
    private sealed class Resolver(DnsProvider dns) : ICloudProviderResolver
    {
        public ApiResult<ICloudCertificateService> ResolveCertificate(string provider) => ApiResult<ICloudCertificateService>.Fail("UNSUPPORTED", "测试不调用云端证书。");
        public ApiResult<IDnsProvider> ResolveDns(string provider) => ApiResult<IDnsProvider>.Ok(dns);
    }
    private sealed class DnsProvider : IDnsProvider
    {
        public string Provider => "TencentCloud"; public int Calls { get; private set; }
        public IReadOnlyList<DnsRecord> Records { get; set; } = [];
        public Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default)
        { Calls++; return Task.FromResult(ApiResult<IReadOnlyList<DnsRecord>>.Ok(Records)); }
        public Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string recordId, DnsRecordRequest request, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string recordId, bool enabled, CancellationToken ct = default) => throw new InvalidOperationException();
        public Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string recordId, CancellationToken ct = default) => throw new InvalidOperationException();
    }
    private sealed class Operations : IMcpOperationService
    {
        public CertificateApplyRequest? LastApplication { get; private set; }
        private static Task<ApiResult<McpOperationView>> Deny() => Task.FromResult(ApiResult<McpOperationView>.Fail("NOT_EXPECTED", "查询不应触发写操作。"));
        public Task<ApiResult<McpOperationView>> PrepareApplicationAsync(McpCallerContext c, CertificateApplyRequest r, string k, CancellationToken t)
        { LastApplication = r; return Deny(); }
        public Task<ApiResult<McpOperationView>> PrepareDeploymentAsync(McpCallerContext c, string id, DeploymentPlanRequest r, string k, CancellationToken t) => Deny();
        public Task<ApiResult<McpOperationView>> SubmitAsync(McpCallerContext c, string id, string k, CancellationToken t) => Deny();
        public Task<ApiResult<McpOperationView>> GetAsync(McpCallerContext c, string id, CancellationToken t) => Deny();
        public Task<ApiResult<McpOperationView>> InvokeTargetTestAsync(McpCallerContext c, string id, string k, string? op, CancellationToken t) => Deny();
        public Task<ApiResult<McpOperationView>> InvokeInspectionAsync(McpCallerContext c, string id, string k, string? op, CancellationToken t) => Deny();
        public Task<ApiResult<McpOperationView>> InvokeBusinessAsync(McpCallerContext c, string tool, JsonElement input, string k, string? op, CancellationToken t) => Deny();
        public Task<ApiResult<McpOperationView>> ApproveAsync(string id, string user, bool approve, int version, CancellationToken t) => Deny();
        public Task<ApiResult<PageResult<McpOperationView>>> ListForAdminAsync(int page, int size, string? status, CancellationToken t) => throw new InvalidOperationException();
        public Task<ApiResult<McpOperationView>> GetForAdminAsync(string id, CancellationToken t) => Deny();
    }
}
