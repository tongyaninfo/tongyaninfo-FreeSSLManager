using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using ModelContextProtocol.Client;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Tests;

/// <summary>仅用独立内存 SQLite/TestServer 与合成密钥，覆盖无 OAuth 的真实 SDK 接入和撤销边界。</summary>
public sealed class McpApiKeyTests
{
    [Theory]
    [InlineData("2026-07-28", false)]
    [InlineData("2025-11-25", false)]
    [InlineData("2026-07-28", true)]
    [InlineData("2025-11-25", true)]
    public async Task OfficialSdkCallsWithApiKeyWithoutOAuthCertificate(string version, bool customHeader)
    {
        await using var f = await Fixture.CreateAsync();
        using var http = f.App.GetTestClient(); http.BaseAddress = new("https://ssl.example.test");
        var transport = new HttpClientTransport(new() { Endpoint = new("https://ssl.example.test/mcp"),
            TransportMode = HttpTransportMode.StreamableHttp,
            AdditionalHeaders = new Dictionary<string, string> { [customHeader ? "X-API-Key" : "Authorization"] = customHeader ? f.Created.ApiKey : "Bearer " + f.Created.ApiKey } }, http);
        await using var client = await ModelContextProtocol.Client.McpClient.CreateAsync(transport, new() { ProtocolVersion = version });
        Assert.Single(await client.ListToolsAsync());
        Assert.False((await client.CallToolAsync("ssl_system_status_get")).IsError);
        await using var scope = f.App.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var key = await db.McpApiKeys.SingleAsync(); Assert.NotNull(key.LastUsedAtUtc);
        var logs = await db.McpInvocationLogs.Where(x => x.Method == "tools/call").ToArrayAsync();
        Assert.Contains(logs, row => row.AuthenticationType == "ApiKey" && row.ApiKeyId == key.Id);
        Assert.DoesNotContain(f.Created.ApiKey, JsonSerializer.Serialize(logs));
        var revoked = await scope.ServiceProvider.GetRequiredService<IMcpApiKeyService>().RevokeAsync(key.Id, default, key.ConfigRevision);
        Assert.True(revoked.Success);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp") { Content = JsonContent("{}") };
        request.Headers.Authorization = new("Bearer", f.Created.ApiKey);
        using var rejected = await http.SendAsync(request); Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
    }

    [Fact]
    public async Task KeyIsHashedAndOnlyExplicitIssuanceReturnsSecret()
    {
        await using var f = await Fixture.CreateAsync(); await using var scope = f.App.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var stored = await db.McpApiKeys.SingleAsync();
        Assert.NotEqual(f.Created.ApiKey, stored.SecretHash); Assert.Equal(64, stored.SecretHash.Length);
        var service = scope.ServiceProvider.GetRequiredService<IMcpApiKeyService>();
        Assert.NotNull(await service.ValidateAsync(f.Created.ApiKey, default));
        Assert.Null(await service.ValidateAsync(f.Created.ApiKey[..^1] + (f.Created.ApiKey[^1] == '0' ? '1' : '0'), default));
        Assert.Null(await service.ValidateAsync("sslm_invalid", default));
        var list = (await service.ListAsync(f.Client.Id, default)).Data!;
        Assert.Single(list); Assert.DoesNotContain(f.Created.ApiKey, JsonSerializer.Serialize(list));
        Assert.DoesNotContain(stored.SecretHash, JsonSerializer.Serialize(stored));
        Assert.DoesNotContain(f.Created.ApiKey, f.Created.ToString());
    }

    [Fact]
    public async Task RotationRevokesOldIdentityAndCannotBeReactivated()
    {
        await using var f = await Fixture.CreateAsync(); await using var scope = f.App.Services.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<IMcpApiKeyService>();
        Assert.Equal("CONFLICT", (await service.RotateAsync(f.Created.Key.Id, default, 0)).Code);
        var rotated = await service.RotateAsync(f.Created.Key.Id, default, f.Created.Key.ConfigRevision);
        Assert.True(rotated.Success, rotated.Message); Assert.NotEqual(f.Created.Key.Id, rotated.Data!.Key.Id);
        Assert.Null(await service.ValidateAsync(f.Created.ApiKey, default));
        Assert.NotNull(await service.ValidateAsync(rotated.Data.ApiKey, default));
        var old = (await service.ListAsync(f.Client.Id, default)).Data!.Single(x => x.Id == f.Created.Key.Id);
        Assert.Equal("KEY_REVOKED", (await service.SetStatusAsync(old.Id, new(true, old.ConfigRevision), default)).Code);
    }

    [Fact]
    public async Task DisabledExpiredAndClientRevokedKeysStopAuthorization()
    {
        await using var f = await Fixture.CreateAsync(); await using var scope = f.App.Services.CreateAsyncScope();
        var service = scope.ServiceProvider.GetRequiredService<IMcpApiKeyService>();
        var auth = scope.ServiceProvider.GetRequiredService<IMcpAuthorizationService>();
        var caller = f.Caller;
        Assert.True((await auth.AuthorizeAsync(caller, "ssl_system_status_get", null, false, default)).Success);
        var disabled = await service.SetStatusAsync(f.Created.Key.Id, new(false, f.Created.Key.ConfigRevision), default);
        Assert.True(disabled.Success); Assert.Null(await service.ValidateAsync(f.Created.ApiKey, default));
        Assert.Equal("API_KEY_REVOKED", (await auth.AuthorizeAsync(caller, "ssl_system_status_get", null, true, default)).Code);
        var enabled = await service.SetStatusAsync(f.Created.Key.Id, new(true, disabled.Data!.ConfigRevision), default);
        Assert.True(enabled.Success);
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.McpApiKeys.Where(x => x.Id == f.Created.Key.Id).ExecuteUpdateAsync(update => update.SetProperty(x => x.ExpiresAtUtc, DateTime.UtcNow.AddSeconds(-1)));
        Assert.Equal("API_KEY_REVOKED", (await auth.AuthorizeAsync(caller, "ssl_system_status_get", null, false, default)).Code);
        await db.McpApiKeys.Where(x => x.Id == f.Created.Key.Id).ExecuteUpdateAsync(update => update.SetProperty(x => x.ExpiresAtUtc, (DateTime?)null));
        Assert.True((await scope.ServiceProvider.GetRequiredService<IMcpClientService>().RevokeAsync(f.Client.Id, default)).Success);
        Assert.Null(await service.ValidateAsync(f.Created.ApiKey, default));
        Assert.Equal("API_KEY_REVOKED", (await auth.AuthorizeAsync(caller, "ssl_system_status_get", null, true, default)).Code);
    }

    [Theory]
    [InlineData("key")]
    [InlineData("client")]
    [InlineData("user")]
    [InlineData("global")]
    public async Task AcceptedBackgroundOperationRechecksOriginalKeyAndEveryOwner(string revoked)
    {
        await using var f = await Fixture.CreateAsync(); await using var scope = f.App.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.McpOperations.Add(new() { Id = "accepted", ClientId = f.Client.ClientId, EffectiveUserId = "admin", AuthenticationType = "ApiKey",
            ApiKeyId = f.Created.Key.Id, Kind = "TargetTest", ToolName = "ssl_deployment_targets_test", Status = "Queued", ConsumedAtUtc = DateTime.UtcNow,
            ScopesJson = "[\"mcp.write\"]", SourceIp = "127.0.0.1", IdempotencyKey = "accepted",
            ResourceJson = "{\"resources\":[{\"targetId\":\"target\"}]}" });
        await db.SaveChangesAsync();
        var gate = new McpExecutionGate(db, scope.ServiceProvider.GetRequiredService<IMcpAuthorizationService>());
        Assert.True((await gate.CheckOperationAsync("accepted", default)).Success);
        if (revoked == "key") await scope.ServiceProvider.GetRequiredService<IMcpApiKeyService>().RevokeAsync(f.Created.Key.Id, default, 1);
        if (revoked == "client") await db.McpClients.Where(x => x.Id == f.Client.Id).ExecuteUpdateAsync(update => update.SetProperty(x => x.Enabled, false));
        if (revoked == "user") await db.Users.Where(x => x.Id == "admin").ExecuteUpdateAsync(update => update.SetProperty(x => x.Enabled, false));
        if (revoked == "global") await db.McpSettings.ExecuteUpdateAsync(update => update.SetProperty(x => x.Enabled, false));
        Assert.False((await gate.CheckOperationAsync("accepted", default)).Success);
    }

    [Fact]
    public async Task ApiKeyCannotBypassScopeRoleResourceOrCredentialType()
    {
        await using var f = await Fixture.CreateAsync(); await using var scope = f.App.Services.CreateAsyncScope();
        var auth = scope.ServiceProvider.GetRequiredService<IMcpAuthorizationService>();
        Assert.False((await auth.AuthorizeAsync(f.Caller with { AuthenticationType = "OAuth" }, "ssl_system_status_get", null, false, default)).Success);
        Assert.False((await auth.AuthorizeAsync(f.Caller with { AuthorizationId = "fake-grant" }, "ssl_system_status_get", null, false, default)).Success);
        Assert.False((await auth.AuthorizeAsync(f.Caller with { ApiKeyId = "another-key" }, "ssl_system_status_get", null, false, default)).Success);
        Assert.False((await auth.AuthorizeAsync(f.Caller with { Scopes = [] }, "ssl_system_status_get", null, false, default)).Success);
        Assert.False((await auth.AuthorizeAsync(f.Caller, "ssl_deployment_targets_test", new(TargetId: "another-target"), false, default)).Success);
        Assert.False((await auth.AuthorizeAsync(f.Caller with { SourceIp = "203.0.113.7" }, "ssl_system_status_get", null, false, default)).Success);
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        await db.Users.Where(x => x.Id == "admin").ExecuteUpdateAsync(update => update.SetProperty(x => x.Role, "viewer"));
        Assert.False((await auth.AuthorizeAsync(f.Caller, "ssl_deployment_targets_test", new(TargetId: "target"), false, default)).Success);
    }

    [Theory]
    [InlineData("query", HttpStatusCode.BadRequest)]
    [InlineData("conflict", HttpStatusCode.Unauthorized)]
    [InlineData("multiple", HttpStatusCode.Unauthorized)]
    [InlineData("wrong", HttpStatusCode.Unauthorized)]
    [InlineData("oauth", HttpStatusCode.Unauthorized)]
    public async Task AmbiguousAndInvalidCredentialsAreRejected(string kind, HttpStatusCode expected)
    {
        await using var f = await Fixture.CreateAsync(); using var http = f.App.GetTestClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://ssl.example.test/mcp" + (kind == "query" ? "?api_key=forbidden" : "")) { Content = JsonContent("{}") };
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", kind == "wrong" ? "sslm_invalid" : kind == "oauth" ? "unconfigured-oauth" : f.Created.ApiKey);
        if (kind == "conflict") request.Headers.Add("X-API-Key", f.Created.ApiKey);
        if (kind == "multiple") request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + f.Created.ApiKey);
        using var response = await http.SendAsync(request); Assert.Equal(expected, response.StatusCode);
    }

    private static StringContent JsonContent(string json) => new(json, System.Text.Encoding.UTF8, "application/json");

    private sealed class Fixture(WebApplication app, SqliteConnection connection, McpClientView client, McpApiKeyCreated created) : IAsyncDisposable
    {
        public WebApplication App => app;
        public McpClientView Client => client;
        public McpApiKeyCreated Created => created;
        public McpCallerContext Caller => new(client.ClientId, "admin", "", ["mcp.read", "mcp.write"], "127.0.0.1", AuthenticationType: "ApiKey", ApiKeyId: created.Key.Id);
        public static async Task<Fixture> CreateAsync()
        {
            // 握手通知与调用审计可能并发完成；只共享命名内存库，绝不跨请求共享连接对象。
            var connectionString = new SqliteConnectionStringBuilder { DataSource = "mcp-api-key-" + Guid.NewGuid().ToString("N"),
                Mode = SqliteOpenMode.Memory, Cache = SqliteCacheMode.Shared, Pooling = false, DefaultTimeout = 5 }.ConnectionString;
            var connection = new SqliteConnection(connectionString); await connection.OpenAsync();
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development" }); builder.WebHost.UseTestServer();
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            { ["AllowedHosts"] = "ssl.example.test", ["Mcp:OAuth:Issuer"] = "", ["Mcp:OAuth:CertificatePath"] = "",
                ["Mcp:OAuth:CertificatePemPath"] = "", ["Mcp:OAuth:PrivateKeyPemPath"] = "" });
            builder.Services.AddSingleton<IIdGenerator, GuidIdGenerator>();
            builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlite(connectionString));
            builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
            builder.Services.AddAuthentication("Cookies").AddCookie("Cookies");
            builder.Services.AddSslManagerMcp(builder.Configuration, false);
            builder.Services.AddScoped<IMcpToolDispatcher, TestDispatcher>();
            var app = builder.Build();
            app.Use((context, next) => { context.Connection.RemoteIpAddress = IPAddress.Loopback; return next(context); });
            app.UseRouting(); app.UseSslManagerMcpBoundary(); app.UseAuthentication(); app.UseAuthorization(); app.MapSslManagerMcp();
            await using var scope = app.Services.CreateAsyncScope(); var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            await db.Database.EnsureCreatedAsync();
            db.Users.Add(new UserAccount { Id = "admin", Username = "admin", NormalizedUsername = "ADMIN", Role = "admin", Enabled = true }); await db.SaveChangesAsync();
            var settings = await scope.ServiceProvider.GetRequiredService<IMcpConfigurationService>().SaveAsync(new()
            { Enabled = true, PublicBaseUrl = "https://ssl.example.test", SystemName = "隔离证书服务", Mode = "ControlledWrite", AllowedCidrs = ["127.0.0.0/8"],
                AllowedTools = ["ssl_system_status_get", "ssl_deployment_targets_test"] }, default);
            Assert.True(settings.Success, settings.Message);
            var clients = scope.ServiceProvider.GetRequiredService<IMcpClientService>();
            var issued = await clients.CreateAsync(new() { Name = "合成 Agent", ClientType = "confidential", GrantType = "client_credentials", BoundUserId = "admin", Scopes = ["mcp.read", "mcp.write"] }, default);
            Assert.True(issued.Success, issued.Message); var client = issued.Data!.Client;
            var enabled = (await clients.SetStatusAsync(client.Id, new(true, client.ConfigRevision), default)).Data!;
            Assert.True((await clients.SaveRulesAsync(client.Id, new([new() { ToolNames = ["ssl_system_status_get", "ssl_deployment_targets_test"],
                Scopes = ["mcp.read", "mcp.write"], AllowedCidrs = ["127.0.0.0/8"], TargetIds = ["target"] }], enabled.ConfigRevision), default)).Success);
            var created = await scope.ServiceProvider.GetRequiredService<IMcpApiKeyService>().CreateAsync(client.Id, new("合成 Key"), default);
            Assert.True(created.Success, created.Message);
            await app.StartAsync(); return new(app, connection, client, created.Data!);
        }
        public async ValueTask DisposeAsync() { await app.StopAsync(); await app.DisposeAsync(); await connection.DisposeAsync(); }
    }

    private sealed class TestDispatcher(IMcpAuthorizationService authorization) : IMcpToolDispatcher
    {
        public IReadOnlyList<McpToolDescriptor> Catalog => McpToolCatalog.All.Where(x => x.Name == "ssl_system_status_get").ToArray();
        public async Task<IReadOnlyList<McpToolDescriptor>> ListAsync(McpCallerContext caller, CancellationToken ct)
            => (await authorization.AuthorizeAsync(caller, "ssl_system_status_get", null, false, ct)).Success ? Catalog : [];
        public async Task<ApiResult<object>> CallAsync(McpCallerContext caller, string toolName, JsonElement arguments, CancellationToken ct)
        {
            var allowed = await authorization.AuthorizeAsync(caller, toolName, null, false, ct);
            return allowed.Success ? ApiResult<object>.Ok(new { status = "isolated" }) : ApiResult<object>.Fail(allowed.Code, allowed.Message);
        }
    }
}
