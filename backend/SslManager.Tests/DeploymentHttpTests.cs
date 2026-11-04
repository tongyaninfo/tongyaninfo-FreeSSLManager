using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SslManager.Api.Data;
using SslManager.Api.Workers;
namespace SslManager.Tests;

/// <summary>真实 HTTP 中间件验证部署路由权限与 CSRF；数据库和密钥仅使用隔离测试目录。</summary>
public sealed class DeploymentHttpTests
{
    private static readonly (string Method, string Path, object? Body)[] Routes =
    [
        ("GET", "/api/deployment-executors", null), ("GET", "/api/deployment-targets", null),
        ("GET", "/api/deployment-targets/missing", null), ("POST", "/api/deployment-targets", new { name = "test" }),
        ("PUT", "/api/deployment-targets/missing", new { name = "test" }),
        ("POST", "/api/deployment-targets/missing/status", new { enabled = false }),
        ("POST", "/api/deployment-targets/missing/test", new { }), ("POST", "/api/deployment-targets/missing/discover", new { }),
        ("POST", "/api/deployment-targets/browse", new { endpoint = "linux.invalid", username = "root", path = "/" }),
        ("POST", "/api/certificates/missing/deployments/plan", new { targets = new[] { new { targetId = "missing" } } }),
        ("POST", "/api/deployments/missing/submit", new { planRevision = 1, idempotencyKey = "test" }),
        ("GET", "/api/deployments", null), ("GET", "/api/deployments/missing", null),
        ("GET", "/api/deployment-tasks/missing", null), ("GET", "/api/deployment-tasks/missing/steps", null),
        ("POST", "/api/deployment-tasks/missing/cancel", new { }), ("POST", "/api/deployment-tasks/missing/inspect", new { }),
        ("POST", "/api/deployment-tasks/missing/resolve", new { note = "已人工核对" }),
        ("POST", "/api/deployment-tasks/missing/retry-plan", new { }), ("POST", "/api/deployment-tasks/missing/rollback-plan", new { })
    ];

    [Fact]
    public async Task AnonymousAndViewerCannotAccessAnyDeploymentRoute()
    {
        await using var factory = new IsolatedFactory();
        using var anonymous = factory.CreateClient();
        foreach (var route in Routes) Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(anonymous, route)).StatusCode);
        using var admin = factory.CreateClient();
        await CsrfAsync(admin);
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync("/api/auth/setup", new { username = "admin", password = "admin-test" })).StatusCode);
        await CsrfAsync(admin);
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync("/api/users", new { username = "viewer", password = "viewer-test", role = "viewer", enabled = true, displayName = "只读" })).StatusCode);
        using var viewer = factory.CreateClient(); await CsrfAsync(viewer);
        Assert.Equal(HttpStatusCode.OK, (await viewer.PostAsJsonAsync("/api/auth/login", new { username = "viewer", password = "viewer-test" })).StatusCode);
        await CsrfAsync(viewer);
        foreach (var route in Routes) Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(viewer, route)).StatusCode);
    }

    [Fact]
    public async Task AdminMutationsRequireCsrfAndInputSecretsNeverReturn()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient(); await CsrfAsync(admin);
        await admin.PostAsJsonAsync("/api/auth/setup", new { username = "admin", password = "admin-test" });
        admin.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        foreach (var route in Routes.Where(route => route.Method != "GET"))
        {
            var response = await SendAsync(admin, route);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("CSRF_INVALID", await response.Content.ReadAsStringAsync());
        }
        await CsrfAsync(admin);
        var descriptor = await admin.GetFromJsonAsync<JsonElement>("/api/deployment-executors");
        Assert.True(descriptor.GetProperty("success").GetBoolean());
        var input = new { name = "HTTP 权限测试", executorKey = "safeline.ce.9.x", endpoint = "https://safeline.invalid:9443",
            username = "admin", authenticationMode = "Password", password = "never-return-this-secret", apiToken = "never-return-token", enabled = true,
            configuration = new { siteIds = Array.Empty<string>(), files = Array.Empty<object>(), validationCommands = Array.Empty<object>(), postCommands = Array.Empty<object>() } };
        var created = await admin.PostAsJsonAsync("/api/deployment-targets", input);
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var json = await created.Content.ReadAsStringAsync();
        Assert.DoesNotContain("never-return-this-secret", json); Assert.DoesNotContain("never-return-token", json);
        var list = await admin.GetStringAsync("/api/deployment-targets");
        Assert.DoesNotContain("never-return-this-secret", list); Assert.DoesNotContain("never-return-token", list);
        var invalid = await admin.PostAsJsonAsync("/api/deployment-targets", new { name = "too-long", executorKey = "safeline.ce.9.x",
            endpoint = "https://safeline.invalid", username = "admin", password = "short", tlsFingerprint = new string('A', 257) });
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
    }
    [Fact]
    public async Task SynologyTargetUsesExistingStorageAndKeepsPasswordOnEdit()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await CsrfAsync(admin);
        await admin.PostAsJsonAsync("/api/auth/setup", new { username = "admin", password = "admin-test" });
        await CsrfAsync(admin);
        var descriptors = await admin.GetFromJsonAsync<JsonElement>("/api/deployment-executors");
        var synology = descriptors.GetProperty("data").EnumerateArray().Single(row => row.GetProperty("key").GetString() == "synology.dsm.7.x");
        Assert.Equal("Password", synology.GetProperty("authenticationModes")[0].GetString());
        Assert.False(synology.GetProperty("supportsRollback").GetBoolean());
        var created = await admin.PostAsJsonAsync("/api/deployment-targets", new
        {
            name = "群晖测试", executorKey = "synology.dsm.7.x", endpoint = "https://nas.invalid",
            username = "deployer", password = "dsm-secret-never-return", authenticationMode = "Password", tlsFingerprint = "legacy-unused-value",
            configuration = new { certificateDescription = "NAS 证书" }
        });
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var body = await created.Content.ReadAsStringAsync();
        Assert.DoesNotContain("dsm-secret-never-return", body);
        var row = JsonDocument.Parse(body).RootElement.GetProperty("data");
        Assert.Equal(5001, row.GetProperty("port").GetInt32());
        Assert.Equal("NAS 证书", row.GetProperty("configuration").GetProperty("certificateDescription").GetString());
        var edited = await admin.PutAsJsonAsync("/api/deployment-targets/" + row.GetProperty("id").GetString(), new
        {
            name = "群晖测试", executorKey = "synology.dsm.7.x", endpoint = "https://nas.invalid:443",
            username = "deployer", password = "", authenticationMode = "Password", configRevision = row.GetProperty("configRevision").GetInt32(),
            configuration = new { remoteCertificateId = "dsm-cert-id", certificateDescription = "NAS 证书" }
        });
        Assert.Equal(HttpStatusCode.OK, edited.StatusCode);
        var updated = (await edited.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("data");
        Assert.Equal(443, updated.GetProperty("port").GetInt32());
        Assert.True(updated.GetProperty("passwordConfigured").GetBoolean());
    }

    [Theory]
    [InlineData("http://nas.invalid:5000", "", false)]
    [InlineData("https://nas.invalid?redirect=other", "", false)]
    [InlineData("https://nas.invalid", "", true)]
    public async Task SynologyRejectsUnsupportedTargetConfiguration(string endpoint, string fingerprint, bool bindSites)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await CsrfAsync(admin);
        await admin.PostAsJsonAsync("/api/auth/setup", new { username = "admin", password = "admin-test" });
        await CsrfAsync(admin);
        var response = await admin.PostAsJsonAsync("/api/deployment-targets", new
        {
            name = "无效群晖", executorKey = "synology.dsm.7.x", endpoint, tlsFingerprint = fingerprint,
            username = "deployer", password = "not-returned", configuration = new { bindSites }
        });
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("VALIDATION", await response.Content.ReadAsStringAsync());
    }

    private static Task<HttpResponseMessage> SendAsync(HttpClient client, (string Method, string Path, object? Body) route)
    {
        var request = new HttpRequestMessage(new HttpMethod(route.Method), route.Path);
        if (route.Body is not null) request.Content = JsonContent.Create(route.Body);
        return client.SendAsync(request);
    }
    private static async Task CsrfAsync(HttpClient client)
    {
        var result = await client.GetFromJsonAsync<JsonElement>("/api/auth/csrf");
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", result.GetProperty("data").GetProperty("token").GetString());
    }
    private sealed class IsolatedFactory : WebApplicationFactory<Program>
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "ssl-deployment-http-" + Guid.NewGuid().ToString("N"));
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            Directory.CreateDirectory(directory);
            builder.UseContentRoot(Path.GetFullPath("../../../../SslManager.Api", AppContext.BaseDirectory));
            builder.UseSetting("ConnectionStrings:Default", "Data Source=" + Path.Combine(directory, "test.db"));
            builder.UseSetting("Storage:KeyDirectory", Path.Combine(directory, "keys"));
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            { ["ConnectionStrings:Default"] = "Data Source=" + Path.Combine(directory, "test.db"), ["Storage:KeyDirectory"] = Path.Combine(directory, "keys") }));
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<AppDbContext>(); services.RemoveAll<DbContextOptions<AppDbContext>>();
                foreach (var descriptor in services.Where(x => x.ServiceType.IsGenericType && x.ServiceType.Name == "IDbContextOptionsConfiguration`1" && x.ServiceType.GenericTypeArguments.Contains(typeof(AppDbContext))).ToArray()) services.Remove(descriptor);
                services.AddDbContext<AppDbContext>(options => options.UseSqlite("Data Source=" + Path.Combine(directory, "test.db")));
                services.RemoveAll<IDataProtectionProvider>(); services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
                foreach (var descriptor in services.Where(x => x.ServiceType == typeof(IHostedService) &&
                    (x.ImplementationType == typeof(CertificateWorker) || x.ImplementationType == typeof(DeploymentWorker))).ToArray()) services.Remove(descriptor);
            });
        }
    }
}
