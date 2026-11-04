using System.Data.Common;
using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mail;
using SslManager.Api.Service;

namespace SslManager.Tests;

/// <summary>仅在新建临时数据库中验证配置迁移，所有凭据为合成字符串，后台任务和网络传输均禁用。</summary>
public sealed partial class ConfigurationTransferHttpTests
{
    private const string Api = "/api/configuration-transfer";
    private const string CloudSecret = "synthetic-transfer-cloud-secret";
    private const string TargetPassword = "synthetic-transfer-target-password";
    private const string MailPassword = "synthetic-transfer-mail-password";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task AllEndpointsRequireAdministratorAndCsrf()
    {
        await using var factory = new IsolatedFactory();
        using var anonymous = factory.CreateClient();
        foreach (var path in new[] { "export", "preview", "import" })
            Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.PostAsJsonAsync($"{Api}/{path}", Request(Package()))).StatusCode);

        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync("/api/users", new
        { username = "transfer-viewer", password = "synthetic-viewer-password", displayName = "只读迁移测试", role = "viewer", enabled = true })).StatusCode);
        using var viewer = factory.CreateClient();
        await CsrfAsync(viewer);
        Assert.Equal(HttpStatusCode.OK, (await viewer.PostAsJsonAsync("/api/auth/login", new
        { username = "transfer-viewer", password = "synthetic-viewer-password" })).StatusCode);
        await CsrfAsync(viewer);
        foreach (var path in new[] { "export", "preview", "import" })
            Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PostAsJsonAsync($"{Api}/{path}", Request(Package()))).StatusCode);
        admin.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        foreach (var path in new[] { "export", "preview", "import" })
        {
            var denied = await admin.PostAsJsonAsync($"{Api}/{path}", Request(Package()));
            Assert.Equal(HttpStatusCode.BadRequest, denied.StatusCode);
            Assert.Contains("CSRF_INVALID", await denied.Content.ReadAsStringAsync());
        }
        Assert.Equal(0, factory.Transport.Calls);
    }

    [Fact]
    public async Task ExportIncludesDisabledConfigurationAndPlaintextCredentialsWithoutBusinessData()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        await SeedAsync(factory);

        var response = await admin.PostAsJsonAsync($"{Api}/export", new { });
        var exported = await ReadSuccessAsync<ConfigurationPackage>(response);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Equal("free-ssl-manager.configuration", exported.Format);
        Assert.Equal(1, exported.Version);
        Assert.Equal(CloudSecret, Assert.Single(exported.CloudAccounts).Settings.AccessKeySecret);
        var target = Assert.Single(exported.DeploymentTargets);
        Assert.Equal(TargetPassword, target.Settings.Password);
        Assert.Equal("synthetic-transfer-token", target.Settings.ApiToken);
        Assert.Equal("synthetic-transfer-ssh-key", target.Settings.PrivateKey);
        Assert.Equal("synthetic-transfer-passphrase", target.Settings.PrivateKeyPassphrase);
        Assert.Equal("synthetic-transfer-pfx-password", target.Settings.PfxPassword);
        Assert.Equal(MailPassword, exported.MailSettings!.Password);
        Assert.False(exported.CloudAccounts[0].Settings.Enabled);
        Assert.False(target.Settings.Enabled);
        Assert.False(exported.CertificateSchedules[0].Settings.Enabled);
        Assert.False(exported.MailSettings.Enabled);
        Assert.Equal(exported.CloudAccounts[0].SourceId, exported.CertificateSchedules[0].Settings.AccountId);
        Assert.Equal(target.SourceId, Assert.Single(exported.CertificateSchedules[0].Settings.TargetIds));
        var json = JsonSerializer.Serialize(exported, Json);
        foreach (var excluded in new[] { "protectedAccessKey", "protectedCredentials", "protectedPassword", "passwordHash", "users", "certificateJobs", "auditLogs", "mailMessages" })
            Assert.DoesNotContain(excluded, json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(CloudSecret, exported.ToString());
        await AssertAuditHasNoCredentialsAsync(factory);
        Assert.Equal(0, factory.Transport.Calls);
    }

    [Fact]
    public async Task FreshInstanceImportRemapsReferencesEncryptsCredentialsAndDisablesAutomation()
    {
        await using var source = new IsolatedFactory();
        using var sourceAdmin = source.CreateClient();
        await SetupAsync(sourceAdmin);
        await SeedAsync(source);
        var exported = await ReadSuccessAsync<ConfigurationPackage>(await sourceAdmin.PostAsJsonAsync($"{Api}/export", new { }));
        await using var destination = new IsolatedFactory();
        using var admin = destination.CreateClient();
        await SetupAsync(admin);
        var request = Request(exported);
        var previewResponse = await admin.PostAsJsonAsync($"{Api}/preview", request);
        var preview = await ReadSuccessAsync<ConfigurationImportPreview>(previewResponse);
        Assert.True(preview.CanImport);
        Assert.Equal(4, preview.Created);
        Assert.Equal("no-store", previewResponse.Headers.CacheControl?.ToString());
        Assert.DoesNotContain(CloudSecret, JsonSerializer.Serialize(preview, Json));
        await AssertCountsAsync(destination, 0);
        request.PreviewToken = preview.PreviewToken;
        var result = await ReadSuccessAsync<ConfigurationImportResult>(await admin.PostAsJsonAsync($"{Api}/import", request));
        Assert.Equal(4, result.Created);
        using (var scope = destination.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var protection = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>();
            var cloud = await db.CloudAccounts.SingleAsync();
            var target = await db.DeploymentTargets.SingleAsync();
            var schedule = await db.CertificateSchedules.SingleAsync();
            var mail = await db.MailSettings.SingleAsync();
            Assert.Equal("TencentCloud", cloud.Provider);
            Assert.NotEqual(exported.CloudAccounts[0].SourceId, cloud.Id);
            Assert.NotEqual(exported.DeploymentTargets[0].SourceId, target.Id);
            Assert.Equal(cloud.Id, schedule.AccountId);
            Assert.Equal(target.Id, Assert.Single(JsonSerializer.Deserialize<string[]>(schedule.TargetIdsJson)!));
            Assert.False(cloud.Enabled);
            Assert.False(cloud.AutoSyncEnabled);
            Assert.Null(cloud.AutoSyncNextRunAtUtc);
            Assert.False(target.Enabled);
            Assert.False(schedule.Enabled);
            Assert.False(mail.Enabled);
            Assert.Equal(CloudSecret, protection.CreateProtector("SslManager.CloudAccount.v1", cloud.Id).Unprotect(cloud.ProtectedAccessKeySecret));
            Assert.Equal(MailPassword, protection.CreateProtector("SslManager.Mail.Settings.v1").Unprotect(mail.ProtectedPassword));
            var credentials = protection.CreateProtector("SslManager.Deployment.Target.v1", target.Id).Unprotect(target.ProtectedCredentials);
            Assert.Equal(TargetPassword, JsonSerializer.Deserialize<DeploymentCredentials>(credentials, Json)!.Password);
            Assert.DoesNotContain(CloudSecret, cloud.ProtectedAccessKeySecret);
            Assert.Empty(await db.Domains.ToListAsync());
            Assert.Empty(await db.Certificates.ToListAsync());
            Assert.Empty(await db.CertificateJobs.ToListAsync());
            Assert.Empty(await db.DeploymentTasks.ToListAsync());
            Assert.Empty(await db.CertificateScheduleRuns.ToListAsync());
            Assert.Empty(await db.MailMessages.ToListAsync());
        }
        var roundTrip = await ReadSuccessAsync<ConfigurationPackage>(await admin.PostAsJsonAsync($"{Api}/export", new { }));
        Assert.Equal(CloudSecret, roundTrip.CloudAccounts[0].Settings.AccessKeySecret);
        Assert.Equal(TargetPassword, roundTrip.DeploymentTargets[0].Settings.Password);
        Assert.Equal(MailPassword, roundTrip.MailSettings!.Password);
        await AssertAuditHasNoCredentialsAsync(destination);
        Assert.Equal(0, destination.Transport.Calls);
    }

    [Fact]
    public async Task DuplicateImportIsRejectedAndUpdateModeKeepsLocalIds()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = Package();
        await ImportAsync(admin, Request(package));
        string cloudId;
        using (var scope = factory.Services.CreateScope())
            cloudId = (await scope.ServiceProvider.GetRequiredService<AppDbContext>().CloudAccounts.SingleAsync()).Id;
        var conflict = await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", Request(package)));
        Assert.False(conflict.CanImport);
        Assert.Equal(4, conflict.Conflicts);
        await AssertCountsAsync(factory, 1);
        package.CloudAccounts[0].Settings.AccessKeySecret = "synthetic-updated-cloud-secret";
        var update = Request(package, "UpdateByName");
        var result = await ImportAsync(admin, update);
        Assert.Equal(0, result.Created);
        Assert.Equal(4, result.Updated);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            Assert.Equal(cloudId, (await db.CloudAccounts.SingleAsync()).Id);
            Assert.Equal(cloudId, (await db.CertificateSchedules.SingleAsync()).AccountId);
        }
        var exported = await ReadSuccessAsync<ConfigurationPackage>(await admin.PostAsJsonAsync($"{Api}/export", new { }));
        Assert.Equal("synthetic-updated-cloud-secret", exported.CloudAccounts[0].Settings.AccessKeySecret);
        await AssertCountsAsync(factory, 1);
    }

    [Theory]
    [InlineData("package")]
    [InlineData("mode")]
    [InlineData("database")]
    [InlineData("token")]
    [InlineData("expired")]
    [InlineData("missing-token")]
    public async Task PreviewCannotBeReusedAfterContentModeDatabaseOrTokenChanges(string change)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = Package();
        var request = Request(package);
        request.PreviewToken = (await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", request))).PreviewToken;
        if (change == "package")
        {
            package.CloudAccounts[0].Settings.Name = "篡改后的配置";
            request.Package = JsonSerializer.SerializeToElement(package, Json);
        }
        else if (change == "mode") request.Mode = "UpdateByName";
        else if (change == "token") request.PreviewToken = request.PreviewToken[..^1] + "!";
        else if (change == "missing-token") request.PreviewToken = "";
        else if (change == "expired")
        {
            using var scope = factory.Services.CreateScope();
            var protector = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>().CreateProtector("SslManager.ConfigurationTransfer.Preview.v1");
            var payload = JsonNode.Parse(protector.Unprotect(request.PreviewToken))!.AsObject();
            payload["expiresAtUtc"] = JsonValue.Create(DateTime.UtcNow.AddMinutes(-1));
            request.PreviewToken = protector.Protect(payload.ToJsonString());
        }
        else
        {
            using var scope = factory.Services.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.CloudAccounts.Add(new CloudAccount { Id = "concurrent-cloud", Name = "并发新增", Provider = "Aliyun" });
            await db.SaveChangesAsync();
        }
        var response = await admin.PostAsJsonAsync($"{Api}/import", request);
        Assert.False(response.IsSuccessStatusCode);
        Assert.DoesNotContain(CloudSecret, await response.Content.ReadAsStringAsync());
        using var check = factory.Services.CreateScope();
        Assert.Empty(await check.ServiceProvider.GetRequiredService<AppDbContext>().DeploymentTargets.ToListAsync());
    }

    [Fact]
    public async Task PreviewRejectsUnknownFieldsDuplicateKeysAndDanglingReferences()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        foreach (var kind in new[] { "unknown", "duplicate", "dangling", "version" })
        {
            var package = Package();
            if (kind == "duplicate") package.CloudAccounts.Add(package.CloudAccounts[0]);
            if (kind == "dangling") package.CertificateSchedules[0].Settings.AccountId = "missing-cloud";
            if (kind == "version") package.Version = 999;
            var request = Request(package);
            if (kind == "unknown")
            {
                var json = JsonSerializer.Serialize(package, Json);
                request.Package = JsonDocument.Parse(json[..^1] + ",\"unexpected\":\"synthetic-private-value\"}").RootElement.Clone();
            }
            var response = await admin.PostAsJsonAsync($"{Api}/preview", request);
            var result = await response.Content.ReadFromJsonAsync<ApiResult<ConfigurationImportPreview>>(Json);
            Assert.NotNull(result);
            Assert.True(!result.Success || result.Data?.CanImport == false);
            Assert.DoesNotContain("synthetic-private-value", await response.Content.ReadAsStringAsync());
            await AssertCountsAsync(factory, 0);
        }
    }

    [Fact]
    public async Task PreviewTokenIsBoundToTheAdministratorWhoRequestedIt()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var request = Request(Package());
        request.PreviewToken = (await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", request))).PreviewToken;
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync("/api/users", new
        { username = "another-admin", password = "synthetic-second-admin-password", displayName = "另一位管理员", role = "admin", enabled = true })).StatusCode);
        using var another = factory.CreateClient();
        await CsrfAsync(another);
        Assert.Equal(HttpStatusCode.OK, (await another.PostAsJsonAsync("/api/auth/login", new
        { username = "another-admin", password = "synthetic-second-admin-password" })).StatusCode);
        await CsrfAsync(another);
        Assert.False((await another.PostAsJsonAsync($"{Api}/import", request)).IsSuccessStatusCode);
        await AssertCountsAsync(factory, 0);
    }

    [Theory]
    [InlineData("bytes")]
    [InlineData("records")]
    public async Task PreviewLimitsPackageSizeAndConfigurationCount(string limit)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = Package();
        if (limit == "bytes") package.MailSettings!.Password = new string('x', 5 * 1024 * 1024);
        else for (var index = 0; index < 1000; index++) package.CloudAccounts.Add(package.CloudAccounts[0]);
        var response = await admin.PostAsJsonAsync($"{Api}/preview", Request(package));
        var result = await response.Content.ReadFromJsonAsync<ApiResult<ConfigurationImportPreview>>(Json);
        Assert.NotNull(result);
        Assert.True(!result.Success || result.Data?.CanImport == false);
        await AssertCountsAsync(factory, 0);
    }

    [Fact]
    public async Task UnreadableCredentialFailsTheWholeExportWithoutReturningPartialSecrets()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        await SeedAsync(factory);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            (await db.MailSettings.SingleAsync()).ProtectedPassword = "synthetic-invalid-protected-value";
            await db.SaveChangesAsync();
        }
        var response = await admin.PostAsJsonAsync($"{Api}/export", new { });
        Assert.False(response.IsSuccessStatusCode);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(CloudSecret, body);
        Assert.DoesNotContain(TargetPassword, body);
        Assert.DoesNotContain(MailPassword, body);
    }

    [Fact]
    public async Task FailedDatabaseWriteRollsBackPreviouslyExecutedInserts()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var request = Request(Package());
        request.PreviewToken = (await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", request))).PreviewToken;
        factory.Failure.Enabled = true;
        var response = await admin.PostAsJsonAsync($"{Api}/import", request);
        Assert.False(response.IsSuccessStatusCode);
        Assert.True(factory.Failure.SuccessfulWrites >= 2, "必须在已有配置 SQL 写入后模拟失败，才能验证事务回滚。");
        await AssertCountsAsync(factory, 0);
    }

    [Theory]
    [InlineData("certificate")]
    [InlineData("deployment")]
    [InlineData("schedule")]
    [InlineData("mail")]
    public async Task UpdateRechecksActiveWorkThatStartsAfterPreview(string kind)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        await ImportAsync(admin, Request(Package()));
        var request = Request(Package(), "UpdateByName");
        request.PreviewToken = (await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", request))).PreviewToken;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var cloud = await db.CloudAccounts.SingleAsync();
            if (kind == "certificate")
            {
                db.Certificates.Add(new ManagedCertificate { Id = "active-certificate", AccountId = cloud.Id, Domain = "example.com" });
                db.CertificateJobs.Add(new CertificateJob { Id = "active-job", CertificateId = "active-certificate", Status = "Waiting" });
            }
            else if (kind == "deployment") db.DeploymentTasks.Add(new DeploymentTask
            { Id = "active-deployment", TargetId = (await db.DeploymentTargets.SingleAsync()).Id, Status = "Queued" });
            else if (kind == "schedule") db.CertificateScheduleRuns.Add(new CertificateScheduleRun
            { Id = "active-schedule-run", ScheduleId = (await db.CertificateSchedules.SingleAsync()).Id, Active = true });
            else db.MailMessages.Add(new MailMessage { Id = "active-mail", RequestId = "active-mail-request", Status = "Sending" });
            await db.SaveChangesAsync();
        }
        var response = await admin.PostAsJsonAsync($"{Api}/import", request);
        Assert.False(response.IsSuccessStatusCode);
        await AssertCountsAsync(factory, 1);
        Assert.Equal(0, factory.Transport.Calls);
    }

    [Fact]
    public async Task ImportedDisabledConfigurationCannotBypassEnableDependencies()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        await ImportAsync(admin, Request(Package()));
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var target = await db.DeploymentTargets.SingleAsync();
        var schedule = await db.CertificateSchedules.SingleAsync();
        var targets = scope.ServiceProvider.GetRequiredService<IDeploymentTargetService>();
        Assert.False((await targets.SetStatusAsync(target.Id, true, CancellationToken.None)).Success);
        var schedules = scope.ServiceProvider.GetRequiredService<ICertificateScheduleService>();
        Assert.False((await schedules.SetEnabledAsync(schedule.Id, true, CancellationToken.None)).Success);
    }

    [Fact]
    public async Task TargetOnlyUpdateIsBlockedByActiveScheduleWithoutLegacyTargetSnapshot()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        await ImportAsync(admin, Request(Package()));
        var targetOnly = Package();
        targetOnly.CloudAccounts.Clear();
        targetOnly.CertificateSchedules.Clear();
        targetOnly.MailSettings = null;
        var request = Request(targetOnly, "UpdateByName");
        request.PreviewToken = (await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", request))).PreviewToken;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.CertificateScheduleRuns.Add(new CertificateScheduleRun
            {
                Id = "legacy-active-run", ScheduleId = (await db.CertificateSchedules.SingleAsync()).Id,
                Active = true, ConfigSnapshotJson = "{}", TargetsJson = "[]"
            });
            await db.SaveChangesAsync();
        }
        Assert.False((await admin.PostAsJsonAsync($"{Api}/import", request)).IsSuccessStatusCode);
        await AssertCountsAsync(factory, 1);
    }

    [Theory]
    [InlineData("example.com", true)]
    [InlineData("other.example.com", false)]
    public async Task HarborImportValidatesScheduleDomainWithoutConnectingToServer(string boundDomain, bool accepted)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = Package();
        var target = Assert.Single(package.DeploymentTargets).Settings;
        target.ExecutorKey = "harbor.compose.ssh.v1";
        target.Configuration = new()
        {
            SourceDomain = boundDomain, HarborInstallDirectory = "/opt/harbor", HarborComposeCommand = "docker compose",
            HarborProxyService = "proxy", OutputDirectory = "/data/secret/cert",
            Files = [new("FullChain", "server.crt"), new("PrivateKey", "server.key")],
            VerificationHost = "192.0.2.10", VerificationPort = 8443, VerificationServerName = boundDomain
        };

        var preview = await ReadSuccessAsync<ConfigurationImportPreview>(
            await admin.PostAsJsonAsync($"{Api}/preview", Request(package)));

        Assert.Equal(accepted, preview.CanImport);
        if (accepted) Assert.Empty(preview.Errors);
        else Assert.Contains(preview.Errors, error => error.Message.Contains("域名", StringComparison.Ordinal));
        Assert.Equal(0, factory.Transport.Calls);
        await AssertCountsAsync(factory, 0);
    }

    private static ConfigurationPackage Package() => new()
    {
        ExportedAtUtc = DateTime.UtcNow,
        CloudAccounts = [new() { SourceId = "source-cloud", Settings = new()
        { Name = "迁移测试云账号", Provider = "TencentCloud", AccessKeyId = "synthetic-access-key", AccessKeySecret = CloudSecret,
            Enabled = true, AutoSyncEnabled = true, AutoSyncIntervalUnit = "hour", AutoSyncIntervalValue = 6 } }],
        DeploymentTargets = [new() { SourceId = "source-target", Settings = new()
        {
            Name = "迁移测试目标", ExecutorKey = "linux.files.ssh.v1", Endpoint = "192.0.2.10", Port = 22, Username = "root",
            AuthenticationMode = "Password", Password = TargetPassword, ApiToken = "synthetic-transfer-token",
            PrivateKey = "synthetic-transfer-ssh-key", PrivateKeyPassphrase = "synthetic-transfer-passphrase", PfxPassword = "synthetic-transfer-pfx-password",
            Enabled = true, Configuration = new()
            {
                SourceDomain = "example.com", SourceFormat = "nginx", OutputDirectory = "/etc/nginx/ssl",
                Files = [new("certificate", "tls.crt", "", "Nginx/example.com.crt")]
            }
        } }],
        CertificateSchedules = [new() { SourceId = "source-schedule", Settings = new()
        { Name = "迁移测试计划", AccountId = "source-cloud", Domain = "example.com", TargetIds = ["source-target"], Enabled = true,
            FirstRunAtUtc = DateTime.UtcNow.AddDays(1), IntervalUnit = "month", IntervalValue = 1 } }],
        MailSettings = new() { Enabled = true, Host = "smtp.example.test", Port = 465, Security = "SslOnConnect",
            Username = "sender@example.test", Password = MailPassword, FromAddress = "sender@example.test", FromName = "迁移测试发信" }
    };

    private static ConfigurationImportRequest Request(ConfigurationPackage package, string mode = "CreateOnly") =>
        new() { Package = JsonSerializer.SerializeToElement(package, Json), Mode = mode };

    private static async Task<ConfigurationImportResult> ImportAsync(HttpClient client, ConfigurationImportRequest request)
    {
        var preview = await ReadSuccessAsync<ConfigurationImportPreview>(await client.PostAsJsonAsync($"{Api}/preview", request));
        Assert.True(preview.CanImport, JsonSerializer.Serialize(preview.Errors, Json));
        request.PreviewToken = preview.PreviewToken;
        return await ReadSuccessAsync<ConfigurationImportResult>(await client.PostAsJsonAsync($"{Api}/import", request));
    }

    private static async Task<T> ReadSuccessAsync<T>(HttpResponseMessage response)
    {
        var text = await response.Content.ReadAsStringAsync();
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var result = JsonSerializer.Deserialize<ApiResult<T>>(text, Json);
        Assert.NotNull(result);
        Assert.True(result.Success, result.Message);
        Assert.NotNull(result.Data);
        return result.Data;
    }

    private static async Task SetupAsync(HttpClient client)
    {
        await CsrfAsync(client);
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsJsonAsync("/api/auth/setup", new
        { username = "admin", password = "synthetic-admin-password", displayName = "迁移测试管理员" })).StatusCode);
        await CsrfAsync(client);
    }

    private static async Task CsrfAsync(HttpClient client)
    {
        var result = await client.GetFromJsonAsync<JsonElement>("/api/auth/csrf");
        client.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        client.DefaultRequestHeaders.Add("X-CSRF-TOKEN", result.GetProperty("data").GetProperty("token").GetString());
    }

    private static async Task AssertCountsAsync(IsolatedFactory factory, int count)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.Equal(count, await db.CloudAccounts.CountAsync());
        Assert.Equal(count, await db.DeploymentTargets.CountAsync());
        Assert.Equal(count, await db.CertificateSchedules.CountAsync());
        Assert.Equal(count, await db.MailSettings.CountAsync());
    }

    private static async Task AssertAuditHasNoCredentialsAsync(IsolatedFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var logs = JsonSerializer.Serialize(await scope.ServiceProvider.GetRequiredService<AppDbContext>().AuditLogs.ToListAsync(), Json);
        foreach (var secret in new[] { CloudSecret, TargetPassword, MailPassword, "synthetic-transfer-ssh-key", "synthetic-transfer-token" })
            Assert.DoesNotContain(secret, logs);
    }

    private static async Task SeedAsync(IsolatedFactory factory)
    {
        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var protection = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>();
        var package = Package();
        var now = DateTime.UtcNow;
        db.CloudAccounts.Add(new CloudAccount
        {
            Id = "source-cloud", Name = package.CloudAccounts[0].Settings.Name, Provider = "TencentCloud", Enabled = false,
            ProtectedAccessKeyId = protection.CreateProtector("SslManager.CloudAccount.v1", "source-cloud").Protect("synthetic-access-key"),
            ProtectedAccessKeySecret = protection.CreateProtector("SslManager.CloudAccount.v1", "source-cloud").Protect(CloudSecret),
            AutoSyncEnabled = true, CreatedAtUtc = now, UpdatedAtUtc = now
        });
        var input = package.DeploymentTargets[0].Settings;
        db.DeploymentTargets.Add(new DeploymentTarget
        {
            Id = "source-target", Name = input.Name, ExecutorKey = input.ExecutorKey, ExecutorRevision = "1", Endpoint = input.Endpoint,
            Port = input.Port, Username = input.Username, AuthenticationMode = input.AuthenticationMode, Enabled = false,
            ConfigurationJson = JsonSerializer.Serialize(input.Configuration, Json), CreatedAtUtc = now, UpdatedAtUtc = now,
            ProtectedCredentials = protection.CreateProtector("SslManager.Deployment.Target.v1", "source-target").Protect(JsonSerializer.Serialize(new DeploymentCredentials
            { Password = input.Password, ApiToken = input.ApiToken, PrivateKey = input.PrivateKey, PrivateKeyPassphrase = input.PrivateKeyPassphrase, PfxPassword = input.PfxPassword }, Json))
        });
        db.CertificateSchedules.Add(new CertificateSchedule
        { Id = "source-schedule", Name = package.CertificateSchedules[0].Settings.Name, AccountId = "source-cloud", Domain = "example.com",
            TargetIdsJson = "[\"source-target\"]", FirstRunAtUtc = DateTime.UtcNow.AddDays(1), NextRunAtUtc = DateTime.UtcNow.AddDays(1), Enabled = false,
            CreatedAtUtc = now, UpdatedAtUtc = now });
        db.MailSettings.Add(new MailSettings
        { Enabled = false, Host = "smtp.example.test", Port = 465, Security = "SslOnConnect", Username = "sender@example.test", FromAddress = "sender@example.test",
            FromName = "迁移测试发信", ProtectedPassword = protection.CreateProtector("SslManager.Mail.Settings.v1").Protect(MailPassword), UpdatedAtUtc = now });
        // 这些业务快照仅用于证明导出范围不会混入证书或 DNS 资产。
        db.Domains.Add(new ManagedDomain { Id = "not-exported-domain", AccountId = "source-cloud", Name = "example.com", ZoneId = "synthetic-zone" });
        db.Certificates.Add(new ManagedCertificate { Id = "not-exported-certificate", AccountId = "source-cloud", Domain = "example.com", Status = "Issued" });
        await db.SaveChangesAsync();
    }

    private sealed class ForbiddenMailTransport : IMailTransport
    {
        public int Calls { get; private set; }
        public Task<MailTransportProbeResult> ProbeAsync(MailTransportEndpoint endpoint, CancellationToken ct)
        { Calls++; throw new InvalidOperationException("配置迁移不能连接 SMTP。"); }
        public Task<MailTransportResult> SendAsync(MailTransportEndpoint endpoint, MailTransportMessage message, CancellationToken ct)
        { Calls++; throw new InvalidOperationException("配置迁移不能发送邮件。"); }
    }

    /// <summary>在实际执行两个配置 INSERT 后模拟第三次失败，不依赖修改测试数据库结构。</summary>
    private sealed class ImportWriteFailure : DbCommandInterceptor
    {
        public bool Enabled { get; set; }
        public int SuccessfulWrites { get; private set; }
        private static bool IsConfigurationInsert(DbCommand command) => command.CommandText.TrimStart().StartsWith("INSERT", StringComparison.Ordinal) &&
            new[] { "\"CloudAccounts\"", "\"DeploymentTargets\"", "\"CertificateSchedules\"", "\"MailSettings\"" }.Any(command.CommandText.Contains);
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command, CommandEventData eventData,
            InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            if (Enabled && IsConfigurationInsert(command) && SuccessfulWrites >= 2)
                throw new InvalidOperationException("SYNTHETIC_IMPORT_WRITE_FAILURE");
            return ValueTask.FromResult(result);
        }
        public override ValueTask<DbDataReader> ReaderExecutedAsync(DbCommand command, CommandExecutedEventData eventData,
            DbDataReader result, CancellationToken cancellationToken = default)
        {
            if (Enabled && IsConfigurationInsert(command)) SuccessfulWrites++;
            return ValueTask.FromResult(result);
        }
    }

    private sealed class IsolatedFactory : WebApplicationFactory<Program>
    {
        private readonly string directory = Path.Combine(Path.GetTempPath(), "ssl-configuration-transfer-" + Guid.NewGuid().ToString("N"));
        public ForbiddenMailTransport Transport { get; } = new();
        public ImportWriteFailure Failure { get; } = new();
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            Directory.CreateDirectory(directory);
            var connection = "Data Source=" + Path.Combine(directory, "test.db");
            builder.UseContentRoot(Path.GetFullPath("../../../../SslManager.Api", AppContext.BaseDirectory));
            builder.UseSetting("ConnectionStrings:Default", connection);
            builder.UseSetting("Storage:KeyDirectory", Path.Combine(directory, "keys"));
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            { ["ConnectionStrings:Default"] = connection, ["Storage:KeyDirectory"] = Path.Combine(directory, "keys") }));
            builder.ConfigureTestServices(services =>
            {
                services.RemoveAll<AppDbContext>();
                services.RemoveAll<DbContextOptions<AppDbContext>>();
                foreach (var descriptor in services.Where(x => x.ServiceType.IsGenericType && x.ServiceType.Name == "IDbContextOptionsConfiguration`1" &&
                    x.ServiceType.GenericTypeArguments.Contains(typeof(AppDbContext))).ToArray()) services.Remove(descriptor);
                services.AddDbContext<AppDbContext>(options => options.UseSqlite(connection).AddInterceptors(Failure));
                services.RemoveAll<IDataProtectionProvider>();
                services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
                services.RemoveAll<IMailTransport>();
                services.AddSingleton<IMailTransport>(Transport);
                foreach (var descriptor in services.Where(x => x.ServiceType == typeof(IHostedService) &&
                    x.ImplementationType?.Namespace == "SslManager.Api.Workers").ToArray()) services.Remove(descriptor);
            });
        }
    }
}
