using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenIddict.Abstractions;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service;

namespace SslManager.Tests;

/// <summary>只使用独立内存数据库和测试密钥提供器验证配置、角色、资源隔离及 OAuth 引用一致性。</summary>
public sealed class McpConfigurationAndAuthorizationTests
{
    [Theory]
    [InlineData("127.0.0.0/8", "127.0.0.1", true)]
    [InlineData("127.0.0.0/8", "::ffff:127.0.0.1", true)]
    [InlineData("10.0.0.0/24", "10.0.1.1", false)]
    [InlineData("2001:db8::/32", "2001:db8::1", true)]
    public void CidrChecksCanonicalAddresses(string range, string address, bool expected) => Assert.Equal(expected, McpNetwork.Contains([range], address));

    [Fact]
    public void DomainRulesCannotMatchSiblingSuffixes()
    {
        Assert.True(McpNetwork.DomainMatches("*.example.com", "a.example.com"));
        Assert.False(McpNetwork.DomainMatches("*.example.com", "example.com"));
        Assert.False(McpNetwork.DomainMatches("*.example.com", "a.example.com.attacker.test"));
        Assert.False(McpNetwork.DomainMatches("example.com", "a.example.com"));
    }

    [Fact]
    public async Task DefaultIsDisabledAndApiKeyCanEnableWithoutOAuthMaterials()
    {
        await using var f = await Fixture.CreateAsync(ready: false);
        var service = f.Services.GetRequiredService<IMcpConfigurationService>();
        Assert.False((await service.GetAsync(default)).Data!.Enabled);
        var result = await service.SaveAsync(new() { Enabled = true, PublicBaseUrl = "https://ssl.example.com", AllowedCidrs = ["127.0.0.0/8"] }, default);
        Assert.True(result.Success, result.Message);
        var status = (await service.StatusAsync(default)).Data!;
        Assert.True(status.ApiKeyReady); Assert.False(status.OAuthReady);
        Assert.NotEmpty(result.Data!.InstanceId);
    }

    [Fact]
    public async Task StaleSettingsUpdateIsRejected()
    {
        await using var f = await Fixture.CreateAsync();
        var service = f.Services.GetRequiredService<IMcpConfigurationService>();
        var first = await service.SaveAsync(new() { PublicBaseUrl = "https://ssl.example.com" }, default);
        Assert.True(first.Success);
        Assert.Equal("CONFLICT", (await service.SaveAsync(new() { ConfigRevision = 0 }, default)).Code);
    }

    [Fact]
    public async Task SystemNameIsValidatedAndRenamingKeepsStableLocalInstanceId()
    {
        await using var f = await Fixture.CreateAsync(ready: false);
        var service = f.Services.GetRequiredService<IMcpConfigurationService>();
        Assert.Equal("VALIDATION", (await service.SaveAsync(new() { SystemName = " " }, default)).Code);
        Assert.Equal("VALIDATION", (await service.SaveAsync(new() { SystemName = "证书\n生产" }, default)).Code);
        var first = (await service.SaveAsync(new() { SystemName = "生产证书服务" }, default)).Data!;
        Assert.NotEmpty(first.InstanceId);
        var renamed = (await service.SaveAsync(new() { SystemName = "运营证书服务", ConfigRevision = first.ConfigRevision }, default)).Data!;
        Assert.Equal(first.InstanceId, renamed.InstanceId); Assert.Equal("运营证书服务", renamed.SystemName);
        var status = (await service.StatusAsync(default)).Data!;
        Assert.Equal(renamed.InstanceId, status.InstanceId); Assert.Equal(renamed.SystemName, status.SystemName);
    }

    [Fact]
    public async Task PublicClientHasNoSecretAndViewerCannotGainWriteScope()
    {
        await using var f = await Fixture.CreateAsync();
        var clients = f.Services.GetRequiredService<IMcpClientService>();
        var result = await clients.CreateAsync(Input("viewer"), default);
        Assert.True(result.Success, result.Message);
        Assert.Null(result.Data!.ClientSecret);
        Assert.False(result.Data.Client.Enabled);
        var input = Input("viewer"); input.Scopes = ["mcp.write"];
        Assert.Equal("VALIDATION", (await clients.CreateAsync(input, default)).Code);
        input = Input("admin"); input.GrantType = "client_credentials";
        Assert.Equal("VALIDATION", (await clients.CreateAsync(input, default)).Code);
    }

    [Fact]
    public async Task OAuthApplicationAuthorizationAndTokenKeepProjectIdsAndReferences()
    {
        await using var f = await Fixture.CreateAsync();
        var clients = f.Services.GetRequiredService<IMcpClientService>();
        var created = (await clients.CreateAsync(Input("admin"), default)).Data!;
        var application = await f.Db.Set<McpOAuthApplication>().SingleAsync();
        Assert.StartsWith("project-", application.Id);
        var authorization = new McpOAuthAuthorization { Application = application, Subject = "admin", Status = "valid", Type = "permanent", Scopes = "[\"mcp.read\"]" };
        var token = new McpOAuthToken { Application = application, Authorization = authorization, Status = "valid", Type = "access_token" };
        f.Db.Add(authorization); f.Db.Add(token); await f.Db.SaveChangesAsync();
        Assert.StartsWith("project-", authorization.Id); Assert.StartsWith("project-", token.Id);
        var authorizationId = authorization.Id; var tokenId = token.Id;
        await f.Db.SaveChangesAsync(); f.Db.ChangeTracker.Clear();
        var stored = await f.Db.Set<McpOAuthToken>().Include(x => x.Application).Include(x => x.Authorization).SingleAsync();
        Assert.Equal(application.Id, stored.Application!.Id); Assert.Equal(authorizationId, stored.Authorization!.Id); Assert.Equal(tokenId, stored.Id);
        Assert.True((await clients.RevokeAsync(created.Client.Id, default)).Success);
        f.Db.ChangeTracker.Clear();
        Assert.Equal("revoked", (await f.Db.Set<McpOAuthToken>().SingleAsync()).Status);
        Assert.Equal("revoked", (await f.Db.Set<McpOAuthAuthorization>().SingleAsync()).Status);
    }

    [Fact]
    public async Task EveryCallRechecksClientUserGrantAndCompleteResourceRule()
    {
        await using var f = await Fixture.CreateAsync();
        var caller = await f.AuthorizeClientAsync();
        var gate = f.Services.GetRequiredService<IMcpAuthorizationService>();
        var allowed = new McpResourceScope("account-a", "app.example.com");
        Assert.True((await gate.AuthorizeAsync(caller, "ssl_certificates_list", allowed, false, default)).Success);
        Assert.Equal("FORBIDDEN", (await gate.AuthorizeAsync(caller, "ssl_certificates_list", allowed with { AccountId = "account-b" }, false, default)).Code);
        Assert.Equal("FORBIDDEN", (await gate.AuthorizeAsync(caller, "ssl_certificates_list", allowed with { Domain = "attacker.test" }, false, default)).Code);
        Assert.False((await gate.AuthorizeAsync(caller with { EffectiveUserId = "viewer" }, "ssl_certificates_list", allowed, false, default)).Success);
        Assert.False((await gate.AuthorizeAsync(caller with { SourceIp = "10.0.0.1" }, "ssl_certificates_list", allowed, false, default)).Success);
        var grant = await f.Db.Set<McpOAuthAuthorization>().SingleAsync(); grant.Status = "revoked"; await f.Db.SaveChangesAsync();
        Assert.Equal("AUTHORIZATION_REVOKED", (await gate.AuthorizeAsync(caller, "ssl_certificates_list", allowed, true, default)).Code);
    }

    [Fact]
    public async Task ToolLogOnlyStoresMetadataAndRequestIdDigest()
    {
        await using var f = await Fixture.CreateAsync();
        var log = f.Services.GetRequiredService<IMcpInvocationLogService>();
        var id = await log.StartAsync(new("client", "admin", "grant", ["mcp.read"], "127.0.0.1"), "tools/call", "ssl_certificates_list", "synthetic-request-secret", "2026-07-28", default);
        await log.CompleteAsync(id, false, "FORBIDDEN", false, default);
        var row = (await log.GetAsync(id, default)).Data!;
        Assert.Equal("Denied", row.Status); Assert.DoesNotContain("synthetic-request-secret", row.RequestId);
        Assert.NotNull(row.FinishedAtUtc); Assert.Equal("FORBIDDEN", row.Code);
    }

    private static McpClientInput Input(string user) => new() { Name = "测试客户端", BoundUserId = user,
        Scopes = ["mcp.read"], RedirectUris = ["https://client.example.com/callback"] };

    private sealed class Fixture(SqliteConnection connection, ServiceProvider provider, IServiceScope scope) : IAsyncDisposable
    {
        public IServiceProvider Services => scope.ServiceProvider;
        public AppDbContext Db => Services.GetRequiredService<AppDbContext>();
        public static async Task<Fixture> CreateAsync(bool ready = true)
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var services = new ServiceCollection(); services.AddLogging(); services.AddSingleton<IIdGenerator, TestIds>();
            services.AddDbContext<AppDbContext>(options => options.UseSqlite(connection));
            services.AddDataProtection().UseEphemeralDataProtectionProvider();
            services.AddSslManagerMcp(new ConfigurationBuilder().Build(), false);
            services.RemoveAll<McpRuntimeOptions>(); services.AddSingleton(new McpRuntimeOptions(true, ready, "测试实例"));
            var provider = services.BuildServiceProvider(); var scope = provider.CreateScope(); var f = new Fixture(connection, provider, scope);
            await f.Db.Database.EnsureCreatedAsync();
            f.Db.Users.AddRange(new UserAccount { Id = "admin", Username = "admin", NormalizedUsername = "ADMIN", Role = "admin", Enabled = true },
                new UserAccount { Id = "viewer", Username = "viewer", NormalizedUsername = "VIEWER", Role = "viewer", Enabled = true });
            await f.Db.SaveChangesAsync(); return f;
        }
        public async Task<McpCallerContext> AuthorizeClientAsync()
        {
            var config = Services.GetRequiredService<IMcpConfigurationService>();
            Assert.True((await config.SaveAsync(new() { Enabled = true, PublicBaseUrl = "https://ssl.example.com", AllowedCidrs = ["127.0.0.0/8"], AllowedTools = ["ssl_certificates_list"] }, default)).Success);
            var clients = Services.GetRequiredService<IMcpClientService>(); var created = (await clients.CreateAsync(Input("admin"), default)).Data!.Client;
            var enabled = (await clients.SetStatusAsync(created.Id, new(true, created.ConfigRevision), default)).Data!;
            Assert.True((await clients.SaveRulesAsync(created.Id, new([new() { ToolNames = ["ssl_certificates_list"], AccountIds = ["account-a"], Domains = ["*.example.com"], Scopes = ["mcp.read"], AllowedCidrs = ["127.0.0.0/8"] }], enabled.ConfigRevision), default)).Success);
            var app = await Db.Set<McpOAuthApplication>().SingleAsync();
            var grant = new McpOAuthAuthorization { Application = app, Subject = "admin", Status = "valid", Type = "permanent", Scopes = "[\"mcp.read\"]" };
            Db.Add(grant); await Db.SaveChangesAsync();
            return new(created.ClientId, "admin", grant.Id!, ["mcp.read"], "127.0.0.1");
        }
        public async ValueTask DisposeAsync() { scope.Dispose(); await provider.DisposeAsync(); await connection.DisposeAsync(); }
    }
    private sealed class TestIds : IIdGenerator { private int number; public string NewId() => "project-" + Interlocked.Increment(ref number); }
}
