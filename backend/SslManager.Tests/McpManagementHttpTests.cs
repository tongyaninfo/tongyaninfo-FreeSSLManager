using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SslManager.Api.Data;
using SslManager.Api.Common.Mcp;

namespace SslManager.Tests;

/// <summary>真实 Program 流水线；全部用户、密钥与迁移限于新临时目录，后台任务不连接外部系统。</summary>
public sealed class McpManagementHttpTests
{
    [Theory]
    [InlineData(false, HttpStatusCode.Forbidden)]
    [InlineData(true, HttpStatusCode.Unauthorized)]
    public async Task OnlyExplicitTrustedProxyCanChangeClientSource(bool trustProxy, HttpStatusCode expected)
    {
        await using var factory = new IsolatedFactory(mcpReady: true, trustProxy: trustProxy);
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new("https://localhost") });
        await using (var scope = factory.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.McpSettings.Add(new() { Enabled = true, PublicBaseUrl = "https://localhost", AllowedCidrsJson = "[\"127.0.0.1/32\"]" });
            await db.SaveChangesAsync();
        }
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp");
        request.Headers.Add("X-Forwarded-For", "127.0.0.1");
        request.Headers.Add("X-Forwarded-Proto", "https");
        request.Content = JsonContent.Create(new { });
        using var response = await client.SendAsync(request);
        Assert.Equal(expected, response.StatusCode);
        await using var inspection = factory.Services.CreateAsyncScope();
        var log = await inspection.ServiceProvider.GetRequiredService<AppDbContext>().McpInvocationLogs.SingleAsync();
        Assert.Equal("203.0.113.10", log.RemoteIp);
        Assert.Equal(trustProxy ? "127.0.0.1" : "203.0.113.10", log.SourceIp);
    }
    [Fact]
    public async Task DefaultUnconfiguredMcpDoesNotPreventNormalSiteStartup()
    {
        await using var factory = new IsolatedFactory();
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { BaseAddress = new("https://localhost") });
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/api/health")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/api/mcp/settings")).StatusCode);
        Assert.Equal(HttpStatusCode.ServiceUnavailable, (await client.PostAsJsonAsync("/mcp", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await client.GetAsync("/swagger/index.html")).StatusCode);
    }

    [Fact]
    public async Task ManagementRequiresAdminCookieAndCsrfAndSupportsApiKeyWithoutOAuthMaterials()
    {
        await using var factory = new IsolatedFactory(); using var client = factory.CreateClient();
        await CsrfAsync(client);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/setup", new
            { username = "admin", password = "synthetic-pass", displayName = "隔离管理员" })).StatusCode);
        await CsrfAsync(client);
        var status = (await ReadAsync(await client.GetAsync("/api/mcp/status"))).GetProperty("data");
        Assert.False(status.GetProperty("enabled").GetBoolean());
        Assert.False(status.GetProperty("oAuthReady").GetBoolean());
        var tools = (await ReadAsync(await client.GetAsync("/api/mcp/tools"))).GetProperty("data");
        Assert.Equal(50, tools.GetArrayLength());
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PutAsJsonAsync("/api/mcp/settings", new { enabled = false })).StatusCode);
        await CsrfAsync(client);
        var enable = await ReadAsync(await client.PutAsJsonAsync("/api/mcp/settings", new
            { enabled = true, publicBaseUrl = "https://mcp.example.test", allowedCidrs = new[] { "127.0.0.1/32" } }));
        Assert.True(enable.GetProperty("success").GetBoolean());
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/users", new
            { username = "viewer", password = "synthetic-pass", displayName = "隔离只读用户", role = "viewer", enabled = true })).StatusCode);
        using var viewer = factory.CreateClient(); await CsrfAsync(viewer);
        Assert.Equal(HttpStatusCode.OK, (await viewer.PostAsJsonAsync("/api/auth/login", new { username = "viewer", password = "synthetic-pass" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync("/api/mcp/settings")).StatusCode);
        using var machine = factory.CreateClient(); machine.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "synthetic-untrusted");
        Assert.Equal(HttpStatusCode.Unauthorized, (await machine.GetAsync("/api/mcp/clients")).StatusCode);
    }

    private static async Task CsrfAsync(HttpClient client)
    {
        var result = await ReadAsync(await client.GetAsync("/api/auth/csrf"));
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", result.GetProperty("data").GetProperty("token").GetString());
    }

    [Fact]
    public async Task ApiKeyManagementRequiresAdminCsrfAndNeverListsSecret()
    {
        await using var factory = new IsolatedFactory(); using var client = factory.CreateClient();
        await CsrfAsync(client);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/setup", new
            { username = "admin", password = "synthetic-pass", displayName = "隔离管理员" })).StatusCode);
        await CsrfAsync(client);
        var createdClient = await ReadAsync(await client.PostAsJsonAsync("/api/mcp/clients", new
        { name = "合成 Agent", clientType = "confidential", grantType = "client_credentials", boundUserId = "unused", scopes = new[] { "mcp.read" } }));
        // 用户 ID 由真实管理列表取得，不能让调用方自报任意绑定身份。
        Assert.False(createdClient.GetProperty("success").GetBoolean());
        var users = await ReadAsync(await client.GetAsync("/api/users"));
        var userId = users.GetProperty("data").GetProperty("items").EnumerateArray().Single().GetProperty("id").GetString();
        createdClient = await ReadAsync(await client.PostAsJsonAsync("/api/mcp/clients", new
        { name = "合成 Agent", clientType = "confidential", grantType = "client_credentials", boundUserId = userId, scopes = new[] { "mcp.read" } }));
        Assert.True(createdClient.GetProperty("success").GetBoolean());
        var clientId = createdClient.GetProperty("data").GetProperty("client").GetProperty("id").GetString();
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync($"/api/mcp/clients/{clientId}/api-keys", new { name = "合成 Key" })).StatusCode);
        await CsrfAsync(client);
        using var issued = await client.PostAsJsonAsync($"/api/mcp/clients/{clientId}/api-keys", new { name = "合成 Key" });
        Assert.Contains("no-store", issued.Headers.CacheControl?.ToString() ?? "");
        var issue = await ReadAsync(issued); Assert.True(issue.GetProperty("success").GetBoolean());
        var data = issue.GetProperty("data"); var secret = data.GetProperty("apiKey").GetString()!;
        var key = data.GetProperty("key"); var id = key.GetProperty("id").GetString();
        var list = await client.GetStringAsync($"/api/mcp/clients/{clientId}/api-keys");
        Assert.DoesNotContain(secret, list); Assert.DoesNotContain("secretHash", list, StringComparison.OrdinalIgnoreCase);
        using var machine = factory.CreateClient(); machine.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", secret);
        Assert.Equal(HttpStatusCode.Unauthorized, (await machine.GetAsync($"/api/mcp/clients/{clientId}/api-keys")).StatusCode);
        var rotated = await ReadAsync(await client.PostAsJsonAsync($"/api/mcp/api-keys/{id}/rotate", new { configRevision = key.GetProperty("configRevision").GetInt32() }));
        Assert.True(rotated.GetProperty("success").GetBoolean());
        Assert.NotEqual(secret, rotated.GetProperty("data").GetProperty("apiKey").GetString());
        var replacement = rotated.GetProperty("data").GetProperty("key");
        var revoked = await ReadAsync(await client.PostAsJsonAsync($"/api/mcp/api-keys/{replacement.GetProperty("id").GetString()}/revoke", new
            { configRevision = replacement.GetProperty("configRevision").GetInt32() }));
        Assert.True(revoked.GetProperty("success").GetBoolean());
        Assert.False(revoked.GetProperty("data").GetProperty("enabled").GetBoolean());
    }
    private static async Task<JsonElement> ReadAsync(HttpResponseMessage response)
    { using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); return json.RootElement.Clone(); }
    private sealed class IsolatedFactory(bool mcpReady = false, bool trustProxy = false) : WebApplicationFactory<Program>
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "ssl-mcp-management-" + Guid.NewGuid().ToString("N"));
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            Directory.CreateDirectory(directory);
            var connection = "Data Source=" + Path.Combine(directory, "test.db");
            builder.UseContentRoot(Path.GetFullPath("../../../../SslManager.Api", AppContext.BaseDirectory));
            builder.UseSetting("ConnectionStrings:Default", connection);
            builder.UseSetting("Storage:KeyDirectory", Path.Combine(directory, "keys"));
            if (trustProxy) builder.UseSetting("Mcp:TrustedProxyAddresses:0", "203.0.113.10");
            builder.ConfigureTestServices(services =>
            {
                if (mcpReady)
                {
                    // 此用例只验证真实 Program 的代理边界；OAuth 协议另由真实签名材料集成测试覆盖。
                    services.RemoveAll<McpRuntimeOptions>();
                    services.AddSingleton(new McpRuntimeOptions(true, true, "isolated proxy test", "https://localhost"));
                    services.AddTransient<IStartupFilter, SetPeerFilter>();
                }
                services.RemoveAll<AppDbContext>(); services.RemoveAll<DbContextOptions<AppDbContext>>();
                foreach (var item in services.Where(x => x.ServiceType.IsGenericType && x.ServiceType.Name == "IDbContextOptionsConfiguration`1"
                    && x.ServiceType.GenericTypeArguments.Contains(typeof(AppDbContext))).ToArray()) services.Remove(item);
                services.AddDbContext<AppDbContext>(options => options.UseSqlite(connection));
                foreach (var item in services.Where(x => x.ServiceType == typeof(IHostedService) && x.ImplementationType?.Namespace == "SslManager.Api.Workers").ToArray())
                    services.Remove(item);
            });
        }
    }
    private sealed class SetPeerFilter : IStartupFilter
    {
        public Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> Configure(Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> next) => app =>
        {
            app.Use(async (context, continuation) => { context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.10"); await continuation(); });
            next(app);
        };
    }
}
