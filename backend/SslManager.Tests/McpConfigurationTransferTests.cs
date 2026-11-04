using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;
using SslManager.Api.Service.impl.Deployment;

namespace SslManager.Tests;

/// <summary>独立内存 SQLite 和真实 OpenIddict 存储，验证配置迁移不恢复源实例身份或权限。</summary>
public sealed class McpConfigurationTransferTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task ExportOnlyContainsPortableDisabledConfigurationWithoutIdentitySecretsOrHistory()
    {
        await using var f = await Fixture.CreateAsync();
        var application = await f.SeedClientAsync("source-real-client", "source-private-user-id", "synthetic-client-secret");
        f.Db.McpSettings.Add(new() { Enabled = true, PublicBaseUrl = "https://source.example.test", Mode = "ControlledWrite" });
        f.Db.McpAllowRules.Add(new() { Id = "source-rule", ClientId = "source-real-client", ToolNamesJson = "[\"ssl_certificates_list\"]",
            AllAccounts = true, AllDomains = true, AllTargets = true, Enabled = true });
        var authorization = new McpOAuthAuthorization { Application = application, Subject = "source-private-user-id", Status = "valid", Type = "permanent" };
        f.Db.Add(authorization);
        f.Db.Add(new McpOAuthToken { Application = application, Authorization = authorization, Subject = "source-private-user-id",
            Status = "valid", Type = "refresh_token", Payload = "synthetic-refresh-token-payload" });
        f.Db.McpInvocationLogs.Add(new() { Id = "source-log", Message = "source-history-marker" });
        f.Db.McpOperations.Add(new() { Id = "source-operation", ClientId = "source-real-client", IdempotencyKey = "source-operation-key", ArgumentsJson = "{\"history\":\"source-history-marker\"}" });
        f.Db.McpApiKeys.Add(new() { Id = "source-key", ClientId = "source-real-client", Name = "source-key-name",
            Prefix = "sslm_source_selector", SecretHash = "synthetic-key-hash-marker" });
        await f.Db.SaveChangesAsync();
        var exported = await f.Transfer.ExportAsync(default);
        Assert.True(exported.Success, exported.Message);
        var json = JsonSerializer.Serialize(exported.Data, Json);
        foreach (var excluded in new[] { "source-real-client", "source-private-user-id", "synthetic-client-secret", "synthetic-refresh-token-payload",
            "source-history-marker", "boundUserId", "oauthApplicationId", "clientSecret", "authorizationId", "mcpOperations", "mcpInvocationLogs",
            "source-key-name", "sslm_source_selector", "synthetic-key-hash-marker", "mcpApiKeys" })
            Assert.DoesNotContain(excluded, json, StringComparison.OrdinalIgnoreCase);
        Assert.False(exported.Data!.McpSettings!.Enabled);
        var client = Assert.Single(exported.Data.McpClients);
        Assert.Equal("mcp-client-1", client.SourceId);
        Assert.False(Assert.Single(client.AllowRules).Enabled);
    }

    [Theory]
    [InlineData("public")]
    [InlineData("confidential")]
    public async Task ImportCreatesNewCorrectOAuthTypeDisablesEverythingAndMapsResources(string clientType)
    {
        await using var f = await Fixture.CreateAsync();
        var package = Package(clientType);
        await f.ImportAsync(package);
        var settings = await f.Db.McpSettings.SingleAsync();
        Assert.False(settings.Enabled);
        Assert.Equal("", settings.PublicBaseUrl);
        var client = await f.Db.McpClients.SingleAsync();
        Assert.False(client.Enabled);
        Assert.Equal("", client.BoundUserId);
        Assert.NotEqual("portable-client", client.ClientId);
        var application = await f.Db.Set<McpOAuthApplication>().SingleAsync();
        Assert.Equal(client.OAuthApplicationId, application.Id);
        Assert.Equal(client.ClientId, application.ClientId);
        Assert.Equal(clientType, application.ClientType);
        Assert.Equal(clientType == "confidential", !string.IsNullOrEmpty(application.ClientSecret));
        Assert.True(string.IsNullOrEmpty(application.Permissions) || application.Permissions == "[]");
        var rule = await f.Db.McpAllowRules.SingleAsync();
        Assert.False(rule.Enabled);
        Assert.Equal(client.ClientId, rule.ClientId);
        Assert.Equal((await f.Db.CloudAccounts.SingleAsync()).Id, Assert.Single(JsonSerializer.Deserialize<string[]>(rule.AccountIdsJson)!));
        Assert.Equal((await f.Db.DeploymentTargets.SingleAsync()).Id, Assert.Single(JsonSerializer.Deserialize<string[]>(rule.TargetIdsJson)!));
        Assert.DoesNotContain("source-account", rule.AccountIdsJson);
        Assert.DoesNotContain("source-target", rule.TargetIdsJson);
        Assert.Empty(await f.Db.Set<McpOAuthAuthorization>().ToListAsync());
        Assert.Empty(await f.Db.Set<McpOAuthToken>().ToListAsync());
        Assert.Empty(await f.Db.McpOperations.ToListAsync());
        Assert.Empty(await f.Db.McpInvocationLogs.ToListAsync());
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task MissingAccountOrTargetReferenceRejectsPreview(bool account)
    {
        await using var f = await Fixture.CreateAsync();
        var package = Package();
        if (account) package.CloudAccounts.Clear(); else package.DeploymentTargets.Clear();
        var preview = await f.Transfer.PreviewAsync(Request(package), "admin", default);
        Assert.True(preview.Success, preview.Message);
        Assert.False(preview.Data!.CanImport);
        Assert.Contains(preview.Data.Errors, error => error.Path.EndsWith(account ? ".accountIds" : ".targetIds", StringComparison.Ordinal));
        Assert.Empty(await f.Db.McpClients.ToListAsync());
    }

    [Theory]
    [InlineData("settings")]
    [InlineData("client")]
    [InlineData("rule")]
    public async Task ConfigurationRevisionChangesInvalidateExistingPreview(string changed)
    {
        await using var f = await Fixture.CreateAsync();
        await f.ImportAsync(Package());
        var request = Request(Package(), "UpdateByName");
        var preview = await f.Transfer.PreviewAsync(request, "admin", default);
        Assert.True(preview.Data!.CanImport);
        request.PreviewToken = preview.Data.PreviewToken;
        if (changed == "settings") (await f.Db.McpSettings.SingleAsync()).ConfigRevision++;
        else if (changed == "client") (await f.Db.McpClients.SingleAsync()).ConfigRevision++;
        else (await f.Db.McpAllowRules.SingleAsync()).ApprovalMode = "Manual";
        await f.Db.SaveChangesAsync();
        var imported = await f.Transfer.ImportAsync(request, "admin", default);
        Assert.False(imported.Success);
        Assert.Equal("CONFLICT", imported.Code);
        Assert.Single(await f.Db.McpClients.ToListAsync());
        Assert.Single(await f.Db.Set<McpOAuthApplication>().ToListAsync());
    }

    [Fact]
    public async Task ClientOnlyImportAlsoClosesExistingServiceAndRequiresPublicAddressReview()
    {
        await using var f = await Fixture.CreateAsync();
        f.Db.McpSettings.Add(new() { Enabled = true, PublicBaseUrl = "https://existing.example.test" });
        await f.Db.SaveChangesAsync();
        var package = Package(); package.McpSettings = null;
        var request = Request(package);
        var preview = await f.Transfer.PreviewAsync(request, "admin", default);
        Assert.True(preview.Data!.CanImport);
        Assert.Contains(preview.Data.Items, item => item.Kind == "McpSettings" && item.Action == "Update");
        request.PreviewToken = preview.Data.PreviewToken;
        Assert.True((await f.Transfer.ImportAsync(request, "admin", default)).Success);
        var settings = await f.Db.McpSettings.SingleAsync();
        Assert.False(settings.Enabled);
        Assert.Equal("", settings.PublicBaseUrl);
    }

    [Fact]
    public async Task UpdateByNameReplacesOAuthIdentityAndRevokesOldEntriesWithoutDeletingHistory()
    {
        await using var f = await Fixture.CreateAsync();
        await f.ImportAsync(Package("confidential"));
        var original = await f.Db.McpClients.SingleAsync();
        var oldClientId = original.ClientId; var oldApplicationId = original.OAuthApplicationId;
        var oldApplication = await f.Db.Set<McpOAuthApplication>().SingleAsync();
        var authorization = new McpOAuthAuthorization { Application = oldApplication, Subject = "admin", Status = "valid", Type = "permanent" };
        f.Db.Add(authorization);
        var token = new McpOAuthToken { Application = oldApplication, Authorization = authorization, Subject = "admin", Status = "valid", Type = "access_token" };
        f.Db.Add(token);
        f.Db.McpInvocationLogs.Add(new() { Id = "existing-log", ClientId = oldClientId, Message = "保留本地历史" });
        f.Db.McpApiKeys.Add(new() { Id = "old-key", ClientId = oldClientId, Name = "旧身份", Prefix = "sslm_old_identity", SecretHash = "synthetic-hash" });
        var oldInstanceId = (await f.Db.McpSettings.SingleAsync()).InstanceId;
        await f.Db.SaveChangesAsync();
        await f.ImportAsync(Package("confidential"), "UpdateByName");
        f.Db.ChangeTracker.Clear();
        var updated = await f.Db.McpClients.SingleAsync();
        Assert.Equal(original.Id, updated.Id);
        Assert.NotEqual(oldClientId, updated.ClientId);
        Assert.NotEqual(oldApplicationId, updated.OAuthApplicationId);
        Assert.False(updated.Enabled);
        Assert.Equal("", updated.BoundUserId);
        Assert.Equal("revoked", (await f.Db.Set<McpOAuthAuthorization>().SingleAsync()).Status);
        Assert.Equal("revoked", (await f.Db.Set<McpOAuthToken>().SingleAsync()).Status);
        Assert.Equal(2, await f.Db.Set<McpOAuthApplication>().CountAsync());
        Assert.Single(await f.Db.McpInvocationLogs.ToListAsync());
        Assert.Single(await f.Db.McpAllowRules.ToListAsync());
        var oldKey = await f.Db.McpApiKeys.SingleAsync();
        Assert.False(oldKey.Enabled); Assert.NotNull(oldKey.RevokedAtUtc); Assert.Equal(oldClientId, oldKey.ClientId);
        Assert.Equal(oldInstanceId, (await f.Db.McpSettings.SingleAsync()).InstanceId);
    }

    [Fact]
    public async Task ClientWithActiveOrUnknownOperationCannotBeReplaced()
    {
        await using var f = await Fixture.CreateAsync();
        await f.ImportAsync(Package());
        var client = await f.Db.McpClients.SingleAsync();
        f.Db.McpOperations.Add(new() { Id = "active", ClientId = client.ClientId, IdempotencyKey = "active", Status = "Unknown", ConsumedAtUtc = DateTime.UtcNow });
        await f.Db.SaveChangesAsync();
        var preview = await f.Transfer.PreviewAsync(Request(Package(), "UpdateByName"), "admin", default);
        Assert.False(preview.Data!.CanImport);
        Assert.Contains(preview.Data.Errors, error => error.Path == "mcpClients");
    }

    [Theory]
    [InlineData("clientSecret")]
    [InlineData("clientId")]
    [InlineData("boundUserId")]
    [InlineData("accessToken")]
    public async Task CredentialAndIdentityFieldsAreNotAcceptedInPortableClient(string forbidden)
    {
        await using var f = await Fixture.CreateAsync();
        var node = JsonSerializer.SerializeToNode(Package(), Json)!;
        node["mcpClients"]![0]!["settings"]![forbidden] = "must-not-be-imported";
        var preview = await f.Transfer.PreviewAsync(new() { Package = JsonSerializer.SerializeToElement(node, Json) }, "admin", default);
        Assert.True(preview.Success, preview.Message);
        Assert.False(preview.Data!.CanImport);
        Assert.Empty(await f.Db.Set<McpOAuthApplication>().ToListAsync());
    }

    [Fact]
    public async Task FailureAfterOAuthSaveRollsBackAllBusinessAndOAuthRows()
    {
        var failure = new OAuthSaveFailure();
        await using var f = await Fixture.CreateAsync(failure);
        var request = Request(Package("confidential"));
        var preview = await f.Transfer.PreviewAsync(request, "admin", default);
        Assert.True(preview.Data!.CanImport);
        request.PreviewToken = preview.Data.PreviewToken;
        failure.Armed = true;
        var imported = await f.Transfer.ImportAsync(request, "admin", default);
        Assert.False(imported.Success);
        Assert.Empty(await f.Db.CloudAccounts.ToListAsync());
        Assert.Empty(await f.Db.DeploymentTargets.ToListAsync());
        Assert.Empty(await f.Db.McpSettings.ToListAsync());
        Assert.Empty(await f.Db.McpClients.ToListAsync());
        Assert.Empty(await f.Db.Set<McpOAuthApplication>().ToListAsync());
    }

    private static ConfigurationPackage Package(string clientType = "public") => new()
    {
        CloudAccounts = [new() { SourceId = "source-account", Settings = new()
            { Name = "Portable account", Provider = "TencentCloud", AccessKeyId = "synthetic-account-key", AccessKeySecret = "synthetic-account-secret" } }],
        DeploymentTargets = [new() { SourceId = "source-target", Settings = new()
            { Name = "Portable target", ExecutorKey = "linux.files.ssh.v1", Endpoint = "ssh.invalid", Username = "test", Password = "synthetic-password",
                Configuration = new() { OutputDirectory = "/ssl", SourceDomain = "example.test", Shell = "sh", Files = [new("FullChain", "fullchain.pem"), new("PrivateKey", "private.key")] } } }],
        McpSettings = new() { Enabled = true, PublicBaseUrl = "https://source.example.test", Mode = "ControlledWrite",
            AllowedCidrs = ["192.0.2.0/24"], AllowedOrigins = ["https://source.example.test"], AllowedTools = ["ssl_certificates_list"] },
        McpClients = [new() { SourceId = "portable-client", Settings = new() { Name = "Portable client", ClientType = clientType,
            GrantType = clientType == "public" ? "authorization_code" : "client_credentials", Scopes = ["mcp.read", "mcp.write"],
            RedirectUris = clientType == "public" ? ["https://client.example.test/callback"] : [] }, AllowRules = [new()
            { ToolNames = ["ssl_certificate_application_prepare", "ssl_certificate_application_submit", "ssl_operations_get"], AccountIds = ["source-account"],
                TargetIds = ["source-target"], Domains = ["example.test", "*.example.test"], AllowedCidrs = ["192.0.2.0/24"], Scopes = ["mcp.read", "mcp.write"],
                ApprovalMode = "Preauthorized", Enabled = true }] }]
    };
    private static ConfigurationImportRequest Request(ConfigurationPackage package, string mode = "CreateOnly") => new()
        { Package = JsonSerializer.SerializeToElement(package, Json), Mode = mode };

    private sealed class Fixture(ServiceProvider provider, AsyncServiceScope scope, SqliteConnection connection) : IAsyncDisposable
    {
        public AppDbContext Db => scope.ServiceProvider.GetRequiredService<AppDbContext>();
        public ConfigurationTransferService Transfer => scope.ServiceProvider.GetRequiredService<ConfigurationTransferService>();
        public static async Task<Fixture> CreateAsync(SaveChangesInterceptor? interceptor = null)
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var services = new ServiceCollection(); services.AddLogging();
            services.AddSingleton<IIdGenerator, GuidIdGenerator>();
            services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
            services.AddDbContext<AppDbContext>(options => { options.UseSqlite(connection); if (interceptor is not null) options.AddInterceptors(interceptor); });
            services.AddOpenIddict().AddCore(options => { options.UseEntityFrameworkCore().UseDbContext<AppDbContext>()
                .ReplaceDefaultEntities<McpOAuthApplication, McpOAuthAuthorization, McpOAuthScope, McpOAuthToken, string>(); options.DisableEntityCaching(); });
            services.AddSingleton<IDeploymentExecutorResolver>(new DeploymentExecutorResolver([new NeverConnectExecutor()]));
            services.AddScoped<ConfigurationTransferService>();
            var provider = services.BuildServiceProvider(); var scope = provider.CreateAsyncScope();
            var fixture = new Fixture(provider, scope, connection);
            await fixture.Db.Database.EnsureCreatedAsync();
            fixture.Db.Users.Add(new() { Id = "admin", Username = "admin", NormalizedUsername = "ADMIN", Role = "admin" });
            await fixture.Db.SaveChangesAsync(); return fixture;
        }
        public async Task<McpOAuthApplication> SeedClientAsync(string clientId, string userId, string secret)
        {
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            var application = (McpOAuthApplication)await manager.CreateAsync(new OpenIddictApplicationDescriptor
                { ClientId = clientId, ClientSecret = secret, DisplayName = "Source client", ClientType = "confidential", ConsentType = "explicit" });
            Db.McpClients.Add(new() { Id = "source-business-client", ClientId = clientId, OAuthApplicationId = application.Id!, Name = "Source client",
                ClientType = "confidential", GrantType = "client_credentials", BoundUserId = userId, Enabled = true, ScopesJson = "[\"mcp.read\"]" });
            await Db.SaveChangesAsync(); return application;
        }
        public async Task ImportAsync(ConfigurationPackage package, string mode = "CreateOnly")
        {
            var request = Request(package, mode); var preview = await Transfer.PreviewAsync(request, "admin", default);
            Assert.True(preview.Success, preview.Message);
            Assert.True(preview.Data!.CanImport, JsonSerializer.Serialize(preview.Data.Errors)); request.PreviewToken = preview.Data.PreviewToken;
            var imported = await Transfer.ImportAsync(request, "admin", default); Assert.True(imported.Success, imported.Message);
        }
        public async ValueTask DisposeAsync() { await scope.DisposeAsync(); await provider.DisposeAsync(); await connection.DisposeAsync(); }
    }
    private sealed class NeverConnectExecutor : IDeploymentExecutor
    {
        public DeploymentExecutorDescriptor Descriptor => new("linux.files.ssh.v1", "Linux", "ServerFiles", "Linux", "SSH", AuthenticationModes: ["Password"]);
        public Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct) => throw new InvalidOperationException("迁移不能连接远端。");
        public Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target, CertificateMaterialMetadata material, DeploymentSelection selection, CancellationToken ct) => throw new InvalidOperationException("迁移不能生成远端计划。");
        public Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct) => throw new InvalidOperationException("迁移不能执行部署。");
        public Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct) => throw new InvalidOperationException("迁移不能核对远端。");
    }
    private sealed class OAuthSaveFailure : SaveChangesInterceptor
    {
        public bool Armed { get; set; }
        private bool insertedApplication;
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        { insertedApplication = Armed && eventData.Context!.ChangeTracker.Entries<McpOAuthApplication>().Any(entry => entry.State == EntityState.Added); return ValueTask.FromResult(result); }
        public override ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken cancellationToken = default)
        { if (insertedApplication) throw new InvalidOperationException("模拟 OAuth 占位应用 SQL 已保存、导入事务尚未提交时故障。"); return ValueTask.FromResult(result); }
    }
}
