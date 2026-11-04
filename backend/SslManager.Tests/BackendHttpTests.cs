using System.Net;
using System.Net.Http.Json;
using System.Reflection;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SslManager.Api.Data;
using SslManager.Api.Workers;
using Xunit;

namespace SslManager.Tests;

/// <summary>通过真实路由、中间件、Cookie 和 CSRF 验证权限；测试数据库和密钥目录保留在临时目录。</summary>
public sealed class BackendHttpTests
{
    [Fact]
    public async Task HealthReportsTheCompiledApiVersionWithoutAuthentication()
    {
        await using var factory = new IsolatedFactory();
        using var client = factory.CreateClient();
        using var response = await client.GetAsync("/api/health");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = await ReadAsync(response);
        Assert.True(result.GetProperty("success").GetBoolean());
        Assert.Equal("Healthy", result.GetProperty("data").GetProperty("status").GetString());
        // 从实际 API 程序集校验版本，避免测试固定旧版本号后阻碍后续封版。
        var expected = typeof(AppDbContext).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()!
            .InformationalVersion.Split('+')[0];
        Assert.Equal(expected, result.GetProperty("data").GetProperty("version").GetString());
    }

    [Fact]
    public async Task InitializationIsSingleUseAndUnsafeRequestsRequireCsrf()
    {
        await using var factory = new IsolatedFactory();
        using var client = factory.CreateClient();
        var status = await ReadAsync(await client.GetAsync("/api/auth/setup-status"));
        Assert.True(status.GetProperty("data").GetProperty("needsSetup").GetBoolean());
        var denied = await client.PostAsJsonAsync("/api/auth/setup", new { username = "admin", password = "test-pass", displayName = "管理员" });
        Assert.Equal(HttpStatusCode.BadRequest, denied.StatusCode);
        Assert.Equal("CSRF_INVALID", (await ReadAsync(denied)).GetProperty("code").GetString());
        await CsrfAsync(client);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/setup", new { username = "admin", password = "test-pass", displayName = "管理员" })).StatusCode);
        await CsrfAsync(client);
        var repeated = await client.PostAsJsonAsync("/api/auth/setup", new { username = "admin2", password = "test-pass", displayName = "管理员2" });
        Assert.Equal(HttpStatusCode.Conflict, repeated.StatusCode);
        Assert.False((await ReadAsync(await client.GetAsync("/api/auth/setup-status"))).GetProperty("data").GetProperty("needsSetup").GetBoolean());
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsJsonAsync("/api/auth/logout", new { })).StatusCode);
    }

    [Fact]
    public async Task AuthenticatedUserCanChangeOwnPassword()
    {
        await using var factory = new IsolatedFactory();
        using var client = factory.CreateClient();
        await SetupAsync(client);

        var wrong = await client.PostAsJsonAsync("/api/auth/change-password", new
        {
            currentPassword = "wrong-pass",
            newPassword = "new-pass"
        });
        Assert.Equal(HttpStatusCode.BadRequest, wrong.StatusCode);
        Assert.Equal("VALIDATION", (await ReadAsync(wrong)).GetProperty("code").GetString());

        await CsrfAsync(client);
        var changed = await client.PostAsJsonAsync("/api/auth/change-password", new
        {
            currentPassword = "test-pass",
            newPassword = "new-pass"
        });
        Assert.Equal(HttpStatusCode.OK, changed.StatusCode);

        await client.PostAsJsonAsync("/api/auth/logout", new { });
        await CsrfAsync(client);
        var login = await client.PostAsJsonAsync("/api/auth/login", new { username = "admin", password = "new-pass" });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
    }

    [Fact]
    public async Task ViewerCannotManageCloudSecretsDnsCertificatesOrDownload()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync("/api/users", new { username = "viewer", password = "viewer-pass", displayName = "只读用户", role = "viewer", enabled = true })).StatusCode);
        using var viewer = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await viewer.GetAsync("/api/cloud-accounts/options")).StatusCode);
        await CsrfAsync(viewer);
        Assert.Equal(HttpStatusCode.OK, (await viewer.PostAsJsonAsync("/api/auth/login", new { username = "viewer", password = "viewer-pass" })).StatusCode);
        await CsrfAsync(viewer);
        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync("/api/cloud-accounts/options")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync("/api/domains")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync("/api/certificates")).StatusCode);
        foreach (var path in new[] { "/api/users", "/api/cloud-accounts", "/api/cloud-accounts/fake/secrets", "/api/certificates/fake/download", "/api/certificates/fake/deployment-files" })
        {
            var response = await viewer.GetAsync(path);
            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Equal("FORBIDDEN", (await ReadAsync(response)).GetProperty("code").GetString());
        }
        foreach (var path in new[] { "/api/cloud-accounts", "/api/domains/fake/records", "/api/certificates/apply", "/api/certificates/fake/revoke" })
            Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PostAsJsonAsync(path, new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PutAsJsonAsync("/api/domains/fake/records/fake", new { })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.DeleteAsync("/api/domains/fake/records/fake")).StatusCode);
    }

    [Fact]
    public async Task ExistingCookieObservesRoleChangesAndUserDisableImmediately()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var created = await ReadAsync(await admin.PostAsJsonAsync("/api/users", new { username = "viewer", password = "viewer-pass", displayName = "只读用户", role = "viewer", enabled = true }));
        var userId = created.GetProperty("data").GetProperty("id").GetString();
        using var viewer = factory.CreateClient();
        await CsrfAsync(viewer);
        Assert.Equal(HttpStatusCode.OK, (await viewer.PostAsJsonAsync("/api/auth/login", new { username = "viewer", password = "viewer-pass" })).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync("/api/users")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync("/api/users/" + userId, new { username = "viewer", password = "", displayName = "现任管理员", role = "admin", enabled = true })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync("/api/users")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync("/api/users/" + userId, new { username = "viewer", password = "", displayName = "已停用", role = "admin", enabled = false })).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await viewer.GetAsync("/api/users")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await viewer.GetAsync("/api/auth/current-user")).StatusCode);
    }

    [Fact]
    public async Task ServerFilteringRunsBeforePaginationForUsersAndAccounts()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        foreach (var name in new[] { "first", "target", "last" })
            Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync("/api/users", new { username = name, password = "user-pass", displayName = name, role = "viewer", enabled = name != "last" })).StatusCode);
        var users = (await ReadAsync(await admin.GetAsync("/api/users?page=1&pageSize=1&search=target&role=viewer&enabled=true"))).GetProperty("data");
        Assert.Equal(1, users.GetProperty("total").GetInt32());
        Assert.Equal("target", users.GetProperty("items")[0].GetProperty("username").GetString());
        foreach (var name in new[] { "first", "target", "last" })
            Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync("/api/cloud-accounts", new { name, provider = name == "target" ? "Aliyun" : "TencentCloud", accessKeyId = "fake-key", accessKeySecret = "fake-secret", enabled = true })).StatusCode);
        var accounts = (await ReadAsync(await admin.GetAsync("/api/cloud-accounts?page=1&pageSize=1&search=target&provider=Aliyun&enabled=true"))).GetProperty("data");
        Assert.Equal(1, accounts.GetProperty("total").GetInt32());
        Assert.Equal("target", accounts.GetProperty("items")[0].GetProperty("name").GetString());
    }

    private static async Task SetupAsync(HttpClient client)
    {
        await CsrfAsync(client);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/setup", new { username = "admin", password = "test-pass", displayName = "管理员" })).StatusCode);
        await CsrfAsync(client);
    }

    private static async Task CsrfAsync(HttpClient client)
    {
        var result = await ReadAsync(await client.GetAsync("/api/auth/csrf"));
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", result.GetProperty("data").GetProperty("token").GetString());
    }

    private static async Task<JsonElement> ReadAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.Clone();
    }

    private sealed class IsolatedFactory : WebApplicationFactory<Program>
    {
        private readonly string artifacts = Path.Combine(Path.GetTempPath(), "ssl-manager-http-tests-" + Guid.NewGuid().ToString("N"));
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            Directory.CreateDirectory(artifacts);
            builder.UseContentRoot(Path.GetFullPath("../../../../SslManager.Api", AppContext.BaseDirectory));
            // Host 设置在顶层入口读取配置前生效，连目录初始化也指向临时路径。
            builder.UseSetting("ConnectionStrings:Default", "Data Source=" + Path.Combine(artifacts, "test.db"));
            builder.UseSetting("Storage:KeyDirectory", Path.Combine(artifacts, "keys"));
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Default"] = "Data Source=" + Path.Combine(artifacts, "test.db"),
                ["Storage:KeyDirectory"] = Path.Combine(artifacts, "keys")
            }));
            builder.ConfigureTestServices(services =>
            {
                // 顶层 Program 会提前读取配置，必须直接替换数据库服务，确保测试不能写入默认应用数据。
                services.RemoveAll<AppDbContext>();
                services.RemoveAll<DbContextOptions<AppDbContext>>();
                foreach (var descriptor in services.Where(x => x.ServiceType.IsGenericType &&
                    x.ServiceType.Name == "IDbContextOptionsConfiguration`1" && x.ServiceType.GenericTypeArguments.Contains(typeof(AppDbContext))).ToArray())
                    services.Remove(descriptor);
                services.AddDbContext<AppDbContext>(options => options.UseSqlite("Data Source=" + Path.Combine(artifacts, "test.db")));
                services.RemoveAll<IDataProtectionProvider>();
                var keys = Path.Combine(artifacts, "keys");
                Directory.CreateDirectory(keys);
                services.AddSingleton<IDataProtectionProvider>(DataProtectionProvider.Create(new DirectoryInfo(keys)));
                // 集成测试不启动后台证书轮询，不调用真实云端。
                foreach (var descriptor in services.Where(x => x.ServiceType == typeof(IHostedService) && x.ImplementationType == typeof(CertificateWorker)).ToArray())
                    services.Remove(descriptor);
            });
        }
    }
}
