using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mail;
using SslManager.Api.Service;

namespace SslManager.Tests;

/// <summary>通过真实登录、Cookie、CSRF、迁移和路由验证邮件入口，所有材料只写入新建隔离测试目录。</summary>
public sealed class MailHttpTests
{
    private static readonly (string Method, string Path, object? Body)[] Routes =
    [
        ("GET", "/api/mail/settings", null),
        ("GET", "/api/mail/messages", null),
        ("GET", "/api/mail/messages/missing", null),
        ("PUT", "/api/mail/settings", new { host = "smtp.example.test", fromAddress = "sender@example.test", password = "synthetic-password" }),
        ("POST", "/api/mail/probe", new { }),
        ("POST", "/api/mail/send", new { requestId = Guid.NewGuid().ToString(), to = new[] { "recipient@example.test" }, subject = "测试", body = "正文" })
    ];

    [Fact]
    public async Task ExistingDatabaseRequiresExplicitMailUpgradeAndKeepsOriginalData()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ssl-mail-upgrade-protection-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var connectionString = "Data Source=" + Path.Combine(directory, "test.db");
        var options = new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connectionString).Options;
        await using (var original = new AppDbContext(options))
        {
            // 只在本测试刚创建的数据库模拟旧版本；绝不使用或复制现有业务库。
            await original.GetService<IMigrator>().MigrateAsync("20261101093752_AddCertificateSchedules");
            original.Users.Add(new UserAccount
            {
                Id = "pre-mail-user", Username = "pre-mail-admin", NormalizedUsername = "PRE-MAIL-ADMIN",
                DisplayName = "升级前保留的管理员", PasswordHash = "synthetic-original-password-hash", Role = "admin", Enabled = true,
                CreatedAtUtc = DateTime.UtcNow
            });
            await original.SaveChangesAsync();
        }

        await using var factory = new IsolatedFactory(directory);
        var failure = Record.Exception(() => { using var client = factory.CreateClient(); });

        Assert.NotNull(failure);
        Assert.Contains("MAIL_DATABASE_UPGRADE_REQUIRED", failure.ToString());
        await using var after = new AppDbContext(options);
        Assert.DoesNotContain(await after.Database.GetAppliedMigrationsAsync(), x => x.EndsWith("_AddMailSending", StringComparison.Ordinal));
        Assert.Contains(await after.Database.GetPendingMigrationsAsync(), x => x.EndsWith("_AddMailSending", StringComparison.Ordinal));
        var retained = Assert.Single(await after.Users.AsNoTracking().ToListAsync());
        Assert.Equal("pre-mail-user", retained.Id);
        Assert.Equal("升级前保留的管理员", retained.DisplayName);
        Assert.Equal("synthetic-original-password-hash", retained.PasswordHash);
        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name IN ('MailSettings', 'MailMessages');";
        Assert.Equal(0L, await command.ExecuteScalarAsync());
        Assert.Equal(0, factory.Transport.SendCalls);
        Assert.Equal(0, factory.Transport.ProbeCalls);
    }

    [Fact]
    public async Task AnonymousAndViewerCannotReadOrSendMail()
    {
        await using var factory = new IsolatedFactory();
        using var anonymous = factory.CreateClient();
        foreach (var route in Routes)
            Assert.Equal(HttpStatusCode.Unauthorized, (await SendAsync(anonymous, route)).StatusCode);
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync("/api/users", new
        {
            username = "mail-viewer", password = "viewer-test", role = "viewer", enabled = true, displayName = "只读用户"
        })).StatusCode);
        using var viewer = factory.CreateClient();
        await CsrfAsync(viewer);
        Assert.Equal(HttpStatusCode.OK, (await viewer.PostAsJsonAsync("/api/auth/login", new
        {
            username = "mail-viewer", password = "viewer-test"
        })).StatusCode);
        await CsrfAsync(viewer);

        foreach (var route in Routes)
            Assert.Equal(HttpStatusCode.Forbidden, (await SendAsync(viewer, route)).StatusCode);

        Assert.Equal(0, factory.Transport.SendCalls);
        Assert.Equal(0, factory.Transport.ProbeCalls);
    }

    [Fact]
    public async Task ConfigurationProbeAndSendRequireCsrf()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        admin.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");

        foreach (var route in Routes.Where(x => x.Method != "GET"))
        {
            var response = await SendAsync(admin, route);
            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.Contains("CSRF_INVALID", await response.Content.ReadAsStringAsync());
        }

        Assert.Equal(0, factory.Transport.SendCalls);
        Assert.Equal(0, factory.Transport.ProbeCalls);
    }

    [Fact]
    public async Task SavedConfigurationAndConnectionProbeNeverSendOrExposePassword()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var saved = await admin.PutAsJsonAsync("/api/mail/settings", new
        {
            host = "smtp.example.test", fromAddress = "sender@example.test", password = "synthetic-password"
        });
        Assert.Equal(HttpStatusCode.OK, saved.StatusCode);
        var first = await saved.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(first.GetProperty("data").GetProperty("configured").GetBoolean());
        Assert.Equal(465, first.GetProperty("data").GetProperty("port").GetInt32());
        Assert.Equal("SslOnConnect", first.GetProperty("data").GetProperty("security").GetString());
        Assert.Equal("sender@example.test", first.GetProperty("data").GetProperty("username").GetString());
        AssertUtcTimestamp(first.GetProperty("data"), "updatedAtUtc");
        var updated = await admin.PutAsJsonAsync("/api/mail/settings", new
        {
            host = "smtp.example.test", fromAddress = "sender@example.test", password = "", fromName = "系统邮件"
        });
        Assert.Equal(HttpStatusCode.OK, updated.StatusCode);
        var edited = await updated.Content.ReadFromJsonAsync<JsonElement>();
        var editedAtUtc = AssertUtcTimestamp(edited.GetProperty("data"), "updatedAtUtc");
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync("/api/mail/probe", new { })).StatusCode);

        var read = await admin.GetAsync("/api/mail/settings");
        var reloaded = await read.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal(editedAtUtc, AssertUtcTimestamp(reloaded.GetProperty("data"), "updatedAtUtc"));
        foreach (var text in new[] { first.ToString(), await updated.Content.ReadAsStringAsync(), await read.Content.ReadAsStringAsync() })
        {
            Assert.DoesNotContain("synthetic-password", text);
            Assert.DoesNotContain("protectedPassword", text, StringComparison.OrdinalIgnoreCase);
        }
        Assert.Equal("no-store", read.Headers.CacheControl?.ToString());
        Assert.Equal(1, factory.Transport.ProbeCalls);
        Assert.Equal("synthetic-password", factory.Transport.LastEndpoint!.Password);
        Assert.Equal(0, factory.Transport.SendCalls);
        using var scope = factory.Services.CreateScope();
        Assert.Empty(await scope.ServiceProvider.GetRequiredService<AppDbContext>().Set<MailMessage>().ToListAsync());
    }

    [Fact]
    public async Task SendIsRecordedAndRepeatedRequestReturnsOriginalWithoutResending()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync("/api/mail/settings", new
        {
            host = "smtp.example.test", fromAddress = "sender@example.test", password = "synthetic-password"
        })).StatusCode);
        var input = new { requestId = Guid.NewGuid().ToString(), to = new[] { "recipient@example.test" }, subject = "证书通知", body = "正文仅在详情显示" };
        var firstResponse = await admin.PostAsJsonAsync("/api/mail/send", input);
        Assert.Equal(HttpStatusCode.OK, firstResponse.StatusCode);
        var first = (await firstResponse.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("data");
        Assert.Equal("Accepted", first.GetProperty("status").GetString());
        var createdAtUtc = AssertUtcTimestamp(first, "createdAtUtc");
        var completedAtUtc = AssertUtcTimestamp(first, "completedAtUtc");
        var id = first.GetProperty("id").GetString();
        var repeated = await admin.PostAsJsonAsync("/api/mail/send", input);
        Assert.Equal(HttpStatusCode.OK, repeated.StatusCode);
        Assert.Equal(id, (await repeated.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("data").GetProperty("id").GetString());
        var conflict = await admin.PostAsJsonAsync("/api/mail/send", new
        {
            input.requestId, input.to, input.subject, body = "更改后的正文"
        });
        Assert.Equal(HttpStatusCode.Conflict, conflict.StatusCode);

        var page = await admin.GetStringAsync("/api/mail/messages?page=1&pageSize=20&status=Accepted&search=" + Uri.EscapeDataString("证书"));
        var items = JsonDocument.Parse(page).RootElement.GetProperty("data");
        Assert.Equal(1, items.GetProperty("total").GetInt32());
        var listed = items.GetProperty("items")[0];
        Assert.Equal(createdAtUtc, AssertUtcTimestamp(listed, "createdAtUtc"));
        Assert.Equal(completedAtUtc, AssertUtcTimestamp(listed, "completedAtUtc"));
        Assert.DoesNotContain("正文仅在详情显示", page);
        var detail = await admin.GetStringAsync("/api/mail/messages/" + id);
        var detailed = JsonDocument.Parse(detail).RootElement.GetProperty("data");
        Assert.Equal(createdAtUtc, AssertUtcTimestamp(detailed, "createdAtUtc"));
        Assert.Equal(completedAtUtc, AssertUtcTimestamp(detailed, "completedAtUtc"));
        Assert.Contains("正文仅在详情显示", detailed.GetProperty("body").GetString());
        Assert.DoesNotContain("synthetic-password", detail);
        Assert.Equal(1, factory.Transport.SendCalls);
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.Single(await db.Set<MailMessage>().ToListAsync());
        Assert.DoesNotContain("synthetic-password", JsonSerializer.Serialize(await db.AuditLogs.ToListAsync()));
        Assert.DoesNotContain("正文仅在详情显示", JsonSerializer.Serialize(await db.AuditLogs.ToListAsync()));
    }

    [Fact]
    public async Task ConcurrentDuplicateDuringProtocolSubmissionReadsTheSameSendingRecord()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        Assert.Equal(HttpStatusCode.OK, (await admin.PutAsJsonAsync("/api/mail/settings", new
        {
            host = "smtp.example.test", fromAddress = "sender@example.test", password = "synthetic-password"
        })).StatusCode);
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        factory.Transport.OnSend = async () =>
        {
            entered.TrySetResult();
            await release.Task.WaitAsync(TimeSpan.FromSeconds(10));
        };
        var input = new { requestId = Guid.NewGuid().ToString(), to = new[] { "recipient@example.test" }, subject = "并发发送", body = "正文" };
        var firstTask = admin.PostAsJsonAsync("/api/mail/send", input);
        try
        {
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var repeated = await admin.PostAsJsonAsync("/api/mail/send", input);
            Assert.Equal(HttpStatusCode.OK, repeated.StatusCode);
            var repeatedData = (await repeated.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("data");
            Assert.Equal("Sending", repeatedData.GetProperty("status").GetString());
            Assert.Equal(1, factory.Transport.SendCalls);
            release.TrySetResult();
            var first = await firstTask;
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            var firstData = (await first.Content.ReadFromJsonAsync<JsonElement>()).GetProperty("data");
            Assert.Equal("Accepted", firstData.GetProperty("status").GetString());
            Assert.Equal(firstData.GetProperty("id").GetString(), repeatedData.GetProperty("id").GetString());
        }
        finally { release.TrySetResult(); }
    }

    private static Task<HttpResponseMessage> SendAsync(HttpClient client, (string Method, string Path, object? Body) route)
    {
        var request = new HttpRequestMessage(new HttpMethod(route.Method), route.Path);
        if (route.Body is not null) request.Content = JsonContent.Create(route.Body);
        return client.SendAsync(request);
    }

    /// <summary>SQLite 读回的 DateTime 不能丢失 UTC 标识，否则浏览器会按本地时区再次转换。</summary>
    private static string AssertUtcTimestamp(JsonElement data, string property)
    {
        var timestamp = data.GetProperty(property);
        var value = timestamp.GetString();
        Assert.NotNull(value);
        Assert.EndsWith("Z", value);
        Assert.Equal(DateTimeKind.Utc, timestamp.GetDateTime().Kind);
        return value;
    }

    private static async Task SetupAsync(HttpClient client)
    {
        await CsrfAsync(client);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/setup", new
        {
            username = "mail-admin", password = "admin-test", displayName = "邮件管理员"
        })).StatusCode);
        await CsrfAsync(client);
    }

    private static async Task CsrfAsync(HttpClient client)
    {
        var result = await client.GetFromJsonAsync<JsonElement>("/api/auth/csrf");
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", result.GetProperty("data").GetProperty("token").GetString());
    }

    private sealed class FakeTransport : IMailTransport
    {
        public int SendCalls { get; private set; }
        public int ProbeCalls { get; private set; }
        public MailTransportEndpoint? LastEndpoint { get; private set; }
        public Func<Task>? OnSend { get; set; }
        public Task<MailTransportProbeResult> ProbeAsync(MailTransportEndpoint endpoint, CancellationToken ct)
        {
            LastEndpoint = endpoint;
            ProbeCalls++;
            return Task.FromResult(new MailTransportProbeResult(true, "OK", "连接检测成功。"));
        }
        public async Task<MailTransportResult> SendAsync(MailTransportEndpoint endpoint, MailTransportMessage message, CancellationToken ct)
        {
            LastEndpoint = endpoint;
            SendCalls++;
            if (OnSend is not null) await OnSend();
            return new MailTransportResult("Accepted", "SMTP_ACCEPTED", "已提交邮件服务器。");
        }
    }

    private sealed class IsolatedFactory(string? existingDirectory = null) : WebApplicationFactory<Program>
    {
        private readonly string directory = existingDirectory ?? Path.Combine(Path.GetTempPath(), "ssl-mail-http-" + Guid.NewGuid().ToString("N"));
        public FakeTransport Transport { get; } = new();

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
                services.RemoveAll<IMailTransport>();
                services.AddSingleton<IMailTransport>(Transport);
                // 隔离测试不能启动证书、部署或调度后台任务，更不能连接任何真实云平台。
                foreach (var descriptor in services.Where(service => service.ServiceType == typeof(IHostedService) &&
                    service.ImplementationType?.Namespace == "SslManager.Api.Workers").ToArray()) services.Remove(descriptor);
            });
        }
    }
}
