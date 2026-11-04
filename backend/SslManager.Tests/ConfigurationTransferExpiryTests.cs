using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mail;

namespace SslManager.Tests;

public sealed partial class ConfigurationTransferHttpTests
{
    [Fact]
    public async Task ExpirySettingsRoundTripIsOptionalAndImportDisablesWithoutCopyingAlertHistory()
    {
        await using var source = new IsolatedFactory();
        using var sourceAdmin = source.CreateClient();
        await SetupAsync(sourceAdmin);
        using (var scope = source.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.ExpiryReminderSettings.Add(new() { Enabled = true, DaysBeforeExpiry = 14, RepeatIntervalDays = 3,
                RecipientsJson = "[\"ops@example.test\"]", UpdatedAtUtc = DateTime.UtcNow });
            db.CertificateExpiryAlerts.Add(new() { Id = "synthetic-alert", CertificateId = "synthetic-certificate", Domain = "example.test",
                NotAfterUtc = DateTime.UtcNow.AddDays(3), FirstDetectedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow });
            await db.SaveChangesAsync();
        }
        var package = await ReadSuccessAsync<ConfigurationPackage>(await sourceAdmin.PostAsJsonAsync($"{Api}/export", new { }));
        Assert.True(package.ExpiryReminderSettings!.Enabled);
        Assert.Equal(14, package.ExpiryReminderSettings.DaysBeforeExpiry);
        Assert.Equal(3, package.ExpiryReminderSettings.RepeatIntervalDays);
        Assert.DoesNotContain("synthetic-alert", JsonSerializer.Serialize(package, Json));
        await using var destination = new IsolatedFactory();
        using var admin = destination.CreateClient();
        await SetupAsync(admin);
        Assert.Equal(1, (await ImportAsync(admin, Request(package))).Created);
        using (var scope = destination.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var row = await db.ExpiryReminderSettings.SingleAsync();
            Assert.False(row.Enabled);
            Assert.Equal(14, row.DaysBeforeExpiry);
            Assert.Equal(3, row.RepeatIntervalDays);
            Assert.Equal("ops@example.test", Assert.Single(JsonSerializer.Deserialize<string[]>(row.RecipientsJson)!));
            Assert.Empty(await db.CertificateExpiryAlerts.ToListAsync());
        }
        var duplicate = await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", Request(package)));
        Assert.False(duplicate.CanImport);
        Assert.Equal(1, duplicate.Conflicts);
        package.ExpiryReminderSettings.RepeatIntervalDays = 0;
        Assert.Equal(1, (await ImportAsync(admin, Request(package, "UpdateByName"))).Updated);
        Assert.Equal(0, destination.Transport.Calls);
    }

    [Fact]
    public async Task LegacyPackageWithoutExpiryFieldStillImports()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var node = System.Text.Json.Nodes.JsonNode.Parse(JsonSerializer.Serialize(Package(), Json))!.AsObject();
        node.Remove("expiryReminderSettings");
        var request = new ConfigurationImportRequest { Package = JsonSerializer.SerializeToElement(node, Json) };
        Assert.Equal(4, (await ImportAsync(admin, request)).Created);
        using var scope = factory.Services.CreateScope();
        Assert.Empty(await scope.ServiceProvider.GetRequiredService<AppDbContext>().ExpiryReminderSettings.ToListAsync());
    }

    [Theory]
    [InlineData("changed")]
    [InlineData("pending")]
    public async Task ReminderImportRechecksChangedSettingsAndPendingMail(string reason)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = new ConfigurationPackage { ExpiryReminderSettings = new() { DaysBeforeExpiry = 10, Recipients = ["ops@example.test"] } };
        await ImportAsync(admin, Request(package));
        var request = Request(package, "UpdateByName");
        request.PreviewToken = (await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", request))).PreviewToken;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            if (reason == "changed") (await db.ExpiryReminderSettings.SingleAsync()).DaysBeforeExpiry = 20;
            else db.CertificateExpiryAlerts.Add(new() { Id = "pending-alert", CertificateId = "synthetic-cert", PendingRequestId = Guid.NewGuid().ToString(),
                NotAfterUtc = DateTime.UtcNow.AddDays(2), FirstDetectedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow });
            await db.SaveChangesAsync();
        }
        Assert.False((await admin.PostAsJsonAsync($"{Api}/import", request)).IsSuccessStatusCode);
        Assert.Equal(0, factory.Transport.Calls);
    }

    [Fact]
    public async Task ReminderEndpointsEnforceAuthorizationCsrfAndSavingDoesNotSend()
    {
        const string endpoint = "/api/mail/expiry-reminders";
        await using var factory = new IsolatedFactory();
        using var anonymous = factory.CreateClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(endpoint + "/settings")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await anonymous.GetAsync(endpoint + "/alerts")).StatusCode);
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var input = new ExpiryReminderSettingsInput { Enabled = true, DaysBeforeExpiry = 7, RepeatIntervalDays = 0, Recipients = ["ops@example.test"] };
        var response = await admin.PutAsJsonAsync(endpoint + "/settings", input);
        var saved = await ReadSuccessAsync<ExpiryReminderSettingsSummary>(response);
        Assert.True(saved.Enabled);
        Assert.False(saved.SmtpConfigured);
        Assert.Equal("no-store", response.Headers.CacheControl?.ToString());
        Assert.Empty((await ReadSuccessAsync<PageResult<ExpiryAlertView>>(await admin.GetAsync(endpoint + "/alerts?status=Active"))).Items);
        Assert.False((await admin.GetAsync(endpoint + "/alerts?status=arbitrary")).IsSuccessStatusCode);
        admin.DefaultRequestHeaders.Remove("X-CSRF-TOKEN");
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PutAsJsonAsync(endpoint + "/settings", input)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await admin.PostAsJsonAsync(endpoint + "/alerts/synthetic/ignore", new { })).StatusCode);
        await CsrfAsync(admin);
        Assert.Equal(HttpStatusCode.OK, (await admin.PostAsJsonAsync("/api/users", new { username = "reminder-viewer", password = "synthetic-viewer-password",
            displayName = "提醒只读测试", role = "viewer", enabled = true })).StatusCode);
        using var viewer = factory.CreateClient();
        await CsrfAsync(viewer);
        await viewer.PostAsJsonAsync("/api/auth/login", new { username = "reminder-viewer", password = "synthetic-viewer-password" });
        await CsrfAsync(viewer);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync(endpoint + "/settings")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync(endpoint + "/alerts")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PutAsJsonAsync(endpoint + "/settings", input)).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PostAsJsonAsync(endpoint + "/alerts/synthetic/ignore", new { })).StatusCode);
        Assert.Equal(0, factory.Transport.Calls);
    }
}
