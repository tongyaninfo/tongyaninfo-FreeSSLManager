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
using SslManager.Api.Models;
using SslManager.Api.Service;

namespace SslManager.Tests;

/// <summary>真实 HTTP 验证周期计划权限、CSRF 和默认值；所有任务及凭据仅进入隔离测试库。</summary>
public sealed class CertificateScheduleHttpTests
{
    private static readonly (string Method, string Path, object? Body)[] Routes =
    [
        ("GET", "/api/certificate-schedules", null),
        ("GET", "/api/certificate-schedules/missing", null),
        ("GET", "/api/certificate-schedules/missing/runs", null),
        ("POST", "/api/certificate-schedules", new { name = "schedule" }),
        ("PUT", "/api/certificate-schedules/missing", new { name = "schedule" }),
        ("POST", "/api/certificate-schedules/missing/status", new { enabled = false }),
        ("POST", "/api/certificate-schedules/missing/run", new { }),
        ("POST", "/api/certificate-schedules/runs/missing/resume", new { }),
        ("POST", "/api/certificate-schedules/runs/missing/resolve", new { note = "人工核对完成" })
    ];

    [Fact]
    public async Task AnonymousAndViewerCannotAccessAnyScheduleRoute()
    {
        await using var factory = new IsolatedFactory();
        using var anonymous = factory.CreateClient();
        foreach (var route in Routes)
            Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(anonymous, route)).StatusCode);

        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync("/api/users", new
        {
            username = "schedule-viewer", password = "viewer-test", role = "viewer", enabled = true, displayName = "只读"
        })).StatusCode);
        using var viewer = factory.CreateClient();
        await CsrfAsync(viewer);
        Assert.Equal(HttpStatusCode.OK, (await viewer.PostAsJsonAsync("/api/auth/login", new
        {
            username = "schedule-viewer", password = "viewer-test"
        })).StatusCode);
        await CsrfAsync(viewer);
        foreach (var route in Routes)
            Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(viewer, route)).StatusCode);
    }

    [Fact]
    public async Task AdminScheduleMutationsRequireCsrf()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        admin.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");

        foreach (var route in Routes.Where(route => route.Method != "GET"))
        {
            var response = await SendAsync(admin, route);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("CSRF_INVALID", await response.Content.ReadAsStringAsync());
        }
    }

    [Fact]
    public async Task NewDisabledScheduleDefaultsToOneMonthAndOldCertificateCleanupWithoutStartingWork()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var (accountId, targetId) = await factory.SeedConfigurationAsync();
        // 故意不传周期及吊销选项，验证真正的 HTTP 模型绑定默认值。
        var response = await admin.PostAsJsonAsync("/api/certificate-schedules", new
        {
            name = "每月续签", accountId, domain = "vpn.example.test", targetIds = new[] { targetId },
            firstRunAtUtc = DateTime.UtcNow.AddMonths(1), enabled = false
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var json = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(json.GetProperty("success").GetBoolean(), json.ToString());
        var data = json.GetProperty("data");
        Assert.Equal("month", data.GetProperty("intervalUnit").GetString());
        Assert.Equal(1, data.GetProperty("intervalValue").GetInt32());
        Assert.True(data.GetProperty("revokeOldCertificates").GetBoolean());
        Assert.False(data.GetProperty("enabled").GetBoolean());
        var id = data.GetProperty("id").GetString();
        var detail = await admin.GetStringAsync("/api/certificate-schedules/" + id);
        var history = await admin.GetStringAsync("/api/certificate-schedules/" + id + "/runs");
        foreach (var body in new[] { json.ToString(), detail, history })
        {
            Assert.DoesNotContain("test-cloud-secret", body);
            Assert.DoesNotContain("test-cloud-key", body);
            Assert.DoesNotContain("leaseToken", body, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("protectedCredentials", body, StringComparison.OrdinalIgnoreCase);
        }
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.Empty(await db.Set<CertificateScheduleRun>().ToListAsync());
        Assert.Empty(await db.CertificateJobs.ToListAsync());
        Assert.Empty(await db.DeploymentBatches.ToListAsync());
    }

    [Fact]
    public async Task EditsRequireCurrentRevisionAndPreserveExplicitCleanupOptOut()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var (accountId, targetId) = await factory.SeedConfigurationAsync();
        var input = Input(accountId, targetId);
        var created = await admin.PostAsJsonAsync("/api/certificate-schedules", input);
        Assert.Equal(HttpStatusCode.OK, created.StatusCode);
        var data = (await created.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("data");
        var id = data.GetProperty("id").GetString();
        var revision = data.GetProperty("configRevision").GetInt32();

        var missingRevision = await admin.PutAsJsonAsync("/api/certificate-schedules/" + id, input);
        Assert.Equal(HttpStatusCode.Conflict, missingRevision.StatusCode);
        input.ConfigRevision = revision;
        input.RevokeOldCertificates = false;
        var saved = await admin.PutAsJsonAsync("/api/certificate-schedules/" + id, input);
        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        var edited = (await saved.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("data");
        Assert.False(edited.GetProperty("revokeOldCertificates").GetBoolean());
        Assert.Equal(revision + 1, edited.GetProperty("configRevision").GetInt32());
        var stale = await admin.PutAsJsonAsync("/api/certificate-schedules/" + id, input);
        Assert.Equal(HttpStatusCode.Conflict, stale.StatusCode);
        var runDisabled = await admin.PostAsJsonAsync("/api/certificate-schedules/" + id + "/run", new { });
        Assert.False((await runDisabled.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("success").GetBoolean());
        using var scope = factory.Services.CreateScope();
        Assert.Empty(await scope.ServiceProvider.GetRequiredService<AppDbContext>().CertificateScheduleRuns.ToListAsync());
    }

    [Theory]
    [InlineData("ManualDns", "vpn.example.test")]
    [InlineData("File", "vpn.example.test")]
    [InlineData("ManagedDns", "other.example.test")]
    public async Task ScheduleRejectsManualValidationOrALinuxTargetBoundToAnotherDomain(string validationMode, string domain)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var (accountId, targetId) = await factory.SeedConfigurationAsync();
        var input = Input(accountId, targetId);
        input.ValidationMode = validationMode;
        input.Domain = domain;

        var response = await admin.PostAsJsonAsync("/api/certificate-schedules", input);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("VALIDATION", await response.Content.ReadAsStringAsync());
        using var scope = factory.Services.CreateScope();
        Assert.Empty(await scope.ServiceProvider.GetRequiredService<AppDbContext>().CertificateSchedules.ToListAsync());
    }

    [Fact]
    public async Task ScheduleSearchUsesDatabasePaginationWithoutLosingMatchingRows()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var (accountId, targetId) = await factory.SeedConfigurationAsync();
        foreach (var name in new[] { "续签一", "其他任务", "续签二" })
        {
            var input = Input(accountId, targetId);
            input.Name = name;
            Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync("/api/certificate-schedules", input)).StatusCode);
        }
        var search = Uri.EscapeDataString("续签");
        var first = (await admin.GetFromJsonAsync<JsonElement>("/api/certificate-schedules?search=" + search + "&page=1&pageSize=1")).GetProperty("data");
        var second = (await admin.GetFromJsonAsync<JsonElement>("/api/certificate-schedules?search=" + search + "&page=2&pageSize=1")).GetProperty("data");

        Assert.Equal(2, first.GetProperty("total").GetInt32());
        Assert.Equal(2, second.GetProperty("total").GetInt32());
        Assert.Single(first.GetProperty("items").EnumerateArray());
        Assert.Single(second.GetProperty("items").EnumerateArray());
        Assert.NotEqual(first.GetProperty("items")[0].GetProperty("id").GetString(), second.GetProperty("items")[0].GetProperty("id").GetString());
        Assert.Contains("续签", first.GetProperty("items")[0].GetProperty("name").GetString());
        Assert.Contains("续签", second.GetProperty("items")[0].GetProperty("name").GetString());
    }

    private static CertificateScheduleInput Input(string accountId, string targetId) => new()
    {
        Name = "周期任务", AccountId = accountId, Domain = "vpn.example.test", TargetIds = [targetId],
        FirstRunAtUtc = DateTime.UtcNow.AddMonths(1), Enabled = false
    };

    private static Task<HttpResponseMessage> SendAsync(HttpClient client, (string Method, string Path, object? Body) route)
    {
        var request = new HttpRequestMessage(new HttpMethod(route.Method), route.Path);
        if (route.Body is not null) request.Content = JsonContent.Create(route.Body);
        return client.SendAsync(request);
    }

    private static async Task SetupAsync(HttpClient admin)
    {
        await CsrfAsync(admin);
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync("/api/auth/setup", new
        {
            username = "schedule-admin", password = "admin-test"
        })).StatusCode);
        await CsrfAsync(admin);
    }

    private static async Task CsrfAsync(HttpClient client)
    {
        var result = await client.GetFromJsonAsync<JsonElement>("/api/auth/csrf");
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", result.GetProperty("data").GetProperty("token").GetString());
    }

    [Theory]
    [InlineData("vpn.example.test", true)]
    [InlineData("other.example.test", false)]
    public async Task HarborScheduleRequiresTheTargetsBoundDomain(string boundDomain, bool accepted)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var (accountId, targetId) = await factory.SeedConfigurationAsync();
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var target = await db.DeploymentTargets.SingleAsync(x => x.Id == targetId);
            target.ExecutorKey = "harbor.compose.ssh.v1";
            target.ConfigurationJson = JsonSerializer.Serialize(new DeploymentTargetConfiguration
            {
                SourceDomain = boundDomain
            }, new JsonSerializerOptions(JsonSerializerDefaults.Web));
            await db.SaveChangesAsync();
        }

        var response = await admin.PostAsJsonAsync("/api/certificate-schedules", new
        {
            name = "Harbor 续签", accountId, domain = "vpn.example.test", targetIds = new[] { targetId },
            firstRunAtUtc = DateTime.UtcNow.AddMonths(1), enabled = false
        });

        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(accepted, result.GetProperty("success").GetBoolean());
        using var verification = factory.Services.CreateScope();
        var database = verification.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.Equal(accepted ? 1 : 0, await database.CertificateSchedules.CountAsync());
        Assert.Empty(await database.DeploymentBatches.ToListAsync());
    }

    private sealed class IsolatedFactory : WebApplicationFactory<Program>
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "ssl-schedule-http-" + Guid.NewGuid().ToString("N"));

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            Directory.CreateDirectory(directory);
            builder.UseContentRoot(Path.GetFullPath("../../../../SslManager.Api", AppContext.BaseDirectory));
            builder.UseSetting("ConnectionStrings:Default", "Data Source=" + Path.Combine(directory, "test.db"));
            builder.UseSetting("Storage:KeyDirectory", Path.Combine(directory, "keys"));
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Default"] = "Data Source=" + Path.Combine(directory, "test.db"),
                ["Storage:KeyDirectory"] = Path.Combine(directory, "keys")
            }));
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<AppDbContext>();
                services.RemoveAll<DbContextOptions<AppDbContext>>();
                foreach (var descriptor in services.Where(service => service.ServiceType.IsGenericType &&
                    service.ServiceType.Name == "IDbContextOptionsConfiguration`1" &&
                    service.ServiceType.GenericTypeArguments.Contains(typeof(AppDbContext))).ToArray()) services.Remove(descriptor);
                services.AddDbContext<AppDbContext>(options => options.UseSqlite("Data Source=" + Path.Combine(directory, "test.db")));
                services.RemoveAll<IDataProtectionProvider>();
                services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
                // HTTP 测试仅验证配置与入口，不能让任何后台 Worker 提交云申请或连接部署目标。
                foreach (var descriptor in services.Where(service => service.ServiceType == typeof(IHostedService) &&
                    service.ImplementationType?.Namespace == "SslManager.Api.Workers").ToArray()) services.Remove(descriptor);
            });
        }

        public async Task<(string AccountId, string TargetId)> SeedConfigurationAsync()
        {
            using var scope = Services.CreateScope();
            var accounts = scope.ServiceProvider.GetRequiredService<ICloudAccountStore>();
            var created = await accounts.CreateAsync(new()
            {
                Name = "测试云账号", Provider = "TencentCloud", AccessKeyId = "test-cloud-key", AccessKeySecret = "test-cloud-secret"
            }, default);
            Assert.True(created.Success, created.Message);
            var accountId = created.Data!.Id;
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Domains.Add(new() { Id = "schedule-zone", AccountId = accountId, Provider = "TencentCloud", ZoneId = "zone", Name = "example.test" });
            db.DeploymentTargets.Add(new()
            {
                Id = "schedule-target", Name = "计划目标", ExecutorKey = "linux.files.ssh.v1", Enabled = true,
                Endpoint = "ssh.invalid", Username = "deployer", Port = 22,
                ConfigurationJson = JsonSerializer.Serialize(new DeploymentTargetConfiguration
                {
                    SourceDomain = "vpn.example.test", SourceFormat = "nginx", HostKeyFingerprint = "SHA256:test"
                }, new JsonSerializerOptions(JsonSerializerDefaults.Web))
            });
            await db.SaveChangesAsync();
            return (accountId, "schedule-target");
        }
    }
}
