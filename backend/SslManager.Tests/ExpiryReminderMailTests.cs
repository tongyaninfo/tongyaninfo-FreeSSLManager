using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using MimeKit;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mail;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Mail;

namespace SslManager.Tests;

/// <summary>系统提醒只通过合成传输器发送；数据库使用内存，模板验证不修改发布资源。</summary>
public sealed class ExpiryReminderMailTests
{
    [Fact]
    public void HtmlMime_HasUtf8PlainAndHtmlAlternatives()
    {
        using var mime = MailKitTransport.CreateMime(new("reminder@example.test", "from@example.test", "证书提醒",
            ["to@example.test"], "到期提醒", "纯文本摘要", DateTime.UtcNow, "<p>HTML 正文</p>"));
        var alternatives = Assert.IsType<MultipartAlternative>(mime.Body);
        Assert.Equal("alternative", alternatives.ContentType.MediaSubtype);
        Assert.Equal(2, alternatives.Count);
        var plain = Assert.IsType<TextPart>(alternatives[0]);
        var html = Assert.IsType<TextPart>(alternatives[1]);
        Assert.Equal("plain", plain.ContentType.MediaSubtype);
        Assert.Equal("html", html.ContentType.MediaSubtype);
        Assert.Equal("utf-8", plain.ContentType.Charset);
        Assert.Equal("utf-8", html.ContentType.Charset);
        Assert.Equal("纯文本摘要", mime.TextBody);
        Assert.Equal("<p>HTML 正文</p>", mime.HtmlBody);
    }

    [Fact]
    public void HtmlMime_RejectsOversizeAndInjectedIdentifiers()
    {
        var message = new MailTransportMessage("reminder@example.test", "from@example.test", "",
            ["to@example.test"], "提醒", "正文", DateTime.UtcNow, "<p>正文</p>");
        Assert.Throws<ArgumentException>(() => MailKitTransport.CreateMime(message with { HtmlBody = new string('x', 100001) }));
        Assert.Throws<ArgumentException>(() => MailKitTransport.CreateMime(message with { MessageId = "id\r\nBcc: injected@example.test" }));
    }

    [Fact]
    public async Task Template_UsesPublishedLocalResourceAndEscapesEveryBusinessField()
    {
        var now = new DateTime(2026, 11, 2, 12, 0, 0, DateTimeKind.Utc);
        var alert = AlertView(now) with { Domain = "<script>alert(1)</script>", AccountName = "A&B <account>", Alias = "\"<img src=x onerror=alert(1)> {{Title}}" };
        var result = await new ExpiryReminderTemplateRenderer().RenderAsync([alert], 30, now, default);
        Assert.Contains(HtmlEncoder.Default.Encode(alert.Domain), result.HtmlBody);
        Assert.Contains(HtmlEncoder.Default.Encode(alert.AccountName), result.HtmlBody);
        Assert.Contains(HtmlEncoder.Default.Encode(alert.Alias), result.HtmlBody);
        Assert.DoesNotContain("<script>", result.HtmlBody);
        Assert.DoesNotContain("<img ", result.HtmlBody);
        Assert.Contains("2026-11-07 12:00:00", result.HtmlBody);
        Assert.Contains("最近检查说明", result.TextBody);
        Assert.Contains("剩余 5 天", result.TextBody);
        Assert.Contains("5", result.HtmlBody);
        Assert.Contains("<table", result.HtmlBody);
    }

    [Fact]
    public async Task Template_OverdueCertificateStillGetsAnExplicitWarning()
    {
        var now = new DateTime(2026, 11, 2, 12, 0, 0, DateTimeKind.Utc);
        var result = await new ExpiryReminderTemplateRenderer().RenderAsync([AlertView(now) with { NotAfterUtc = now.AddDays(-2) }], 30, now, default);
        Assert.Contains("已过期 2 天", result.TextBody);
        Assert.DoesNotContain("{{AlertRows}}", result.HtmlBody);
    }

    [Fact]
    public async Task SystemReminder_UsesSameLedgerAndKeepsHtmlOnlyInMemory()
    {
        await using var fixture = await Fixture.CreateAsync();
        var result = await fixture.Mail.SendExpiryReminderAsync(fixture.Input, default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("Accepted", result.Data!.Status);
        Assert.Equal("system:certificate-expiry", result.Data.CreatedByUserId);
        Assert.Equal("提醒正文摘要", result.Data.Body);
        Assert.Equal(1, fixture.Transport.Calls);
        Assert.Equal("<p>本轮 HTML</p>", fixture.Transport.Message!.HtmlBody);
        var stored = await fixture.Db.MailMessages.SingleAsync();
        Assert.Equal("提醒正文摘要", stored.Body);
        Assert.DoesNotContain("本轮 HTML", JsonSerializer.Serialize(stored));
        Assert.DoesNotContain("本轮 HTML", JsonSerializer.Serialize(fixture.Input));
        Assert.DoesNotContain("本轮 HTML", fixture.Input.ToString());
        Assert.DoesNotContain("本轮 HTML", fixture.Transport.Message.ToString());
    }

    [Theory]
    [InlineData("Accepted")]
    [InlineData("Unknown")]
    [InlineData("Failed")]
    public async Task SameRequest_AlwaysReturnsOriginalSystemResultEvenWhenContentAndRulesChange(string status)
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Transport.Result = new(status, status == "Accepted" ? "MAIL_ACCEPTED" : status == "Unknown" ? "MAIL_RESULT_UNKNOWN" : "MAIL_AUTH_FAILED", "");
        var first = await fixture.Mail.SendExpiryReminderAsync(fixture.Input, default);
        fixture.Input.Subject = ""; fixture.Input.Body = ""; fixture.Input.HtmlBody = ""; fixture.Input.To = [];
        await fixture.Db.ExpiryReminderSettings.ExecuteUpdateAsync(setters => setters.SetProperty(x => x.Enabled, false));
        var replay = await fixture.Mail.SendExpiryReminderAsync(fixture.Input, default);
        Assert.True(replay.Success, replay.Message);
        Assert.Equal(first.Data!.Id, replay.Data!.Id);
        Assert.Equal(status, replay.Data.Status);
        Assert.Equal(1, fixture.Transport.Calls);
        Assert.Equal(1, await fixture.Db.MailMessages.CountAsync());
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("settings-changed")]
    [InlineData("ignored")]
    [InlineData("resolved")]
    [InlineData("request-changed")]
    [InlineData("certificate-renewed")]
    [InlineData("certificate-revoked")]
    [InlineData("certificate-refunded")]
    [InlineData("certificate-removed")]
    [InlineData("smtp-disabled")]
    public async Task ChangedAuthorizationOrCertificate_BlocksBeforeCreatingAnIntent(string scenario)
    {
        await using var fixture = await Fixture.CreateAsync();
        switch (scenario)
        {
            case "disabled": await fixture.Db.ExpiryReminderSettings.ExecuteUpdateAsync(setters => setters.SetProperty(x => x.Enabled, false)); break;
            case "settings-changed": fixture.Input.SettingsUpdatedAtUtc = fixture.Input.SettingsUpdatedAtUtc.AddSeconds(-1); break;
            case "ignored": await fixture.Db.CertificateExpiryAlerts.ExecuteUpdateAsync(setters => setters.SetProperty(x => x.Status, "Ignored")); break;
            case "resolved": await fixture.Db.CertificateExpiryAlerts.ExecuteUpdateAsync(setters => setters.SetProperty(x => x.Status, "Resolved")); break;
            case "request-changed": await fixture.Db.CertificateExpiryAlerts.ExecuteUpdateAsync(setters => setters.SetProperty(x => x.PendingRequestId, Guid.NewGuid().ToString("D"))); break;
            case "certificate-renewed": await fixture.Db.Certificates.ExecuteUpdateAsync(setters => setters.SetProperty(x => x.NotAfterUtc, DateTime.UtcNow.AddDays(90))); break;
            case "certificate-revoked": await fixture.Db.Certificates.ExecuteUpdateAsync(setters => setters.SetProperty(x => x.Status, "Revoked")); break;
            case "certificate-refunded": await fixture.Db.Certificates.ExecuteUpdateAsync(setters => setters.SetProperty(x => x.Status, "Refunded")); break;
            case "certificate-removed": await fixture.Db.Certificates.ExecuteUpdateAsync(setters => setters.SetProperty(x => x.Status, "Removed")); break;
            case "smtp-disabled": await fixture.Db.MailSettings.ExecuteUpdateAsync(setters => setters.SetProperty(x => x.Enabled, false)); break;
        }
        var result = await fixture.Mail.SendExpiryReminderAsync(fixture.Input, default);
        Assert.False(result.Success);
        Assert.Equal(0, fixture.Transport.Calls);
        Assert.Empty(await fixture.Db.MailMessages.ToListAsync());
    }

    [Theory]
    [InlineData("alert", "EXPIRY_ALERT_CHANGED")]
    [InlineData("rule", "EXPIRY_REMINDER_CONFIGURATION_CHANGED")]
    [InlineData("smtp", "MAIL_CONFIGURATION_CHANGED")]
    [InlineData("removed", "EXPIRY_ALERT_CHANGED")]
    public async Task AuthorizationChangedAfterIntent_IsRecheckedBeforeTransportAndNeverReplayed(string scenario, string expectedCode)
    {
        await using var fixture = await Fixture.CreateAsync();
        // ID 在意图入库时生成，此时模拟另一个请求忽略提醒，不依赖真实 SMTP 或线程时序。
        fixture.Ids.OnGenerate = () => fixture.Db.Database.ExecuteSqlRaw(scenario switch
        {
            "rule" => "UPDATE ExpiryReminderSettings SET Enabled = 0",
            "smtp" => "UPDATE MailSettings SET Enabled = 0",
            "removed" => "UPDATE Certificates SET Status = 'Removed'",
            _ => "UPDATE CertificateExpiryAlerts SET Status = 'Ignored'"
        });
        var result = await fixture.Mail.SendExpiryReminderAsync(fixture.Input, default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("Failed", result.Data!.Status);
        Assert.Equal(expectedCode, result.Data.Code);
        Assert.Equal(0, fixture.Transport.Calls);
        Assert.Equal("Failed", (await fixture.Mail.SendExpiryReminderAsync(fixture.Input, default)).Data!.Status);
        Assert.Equal(0, fixture.Transport.Calls);
    }

    [Fact]
    public async Task InterruptedSystemIntent_RecoversToUnknownWithoutSendingAgain()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Db.MailMessages.Add(new() { Id = "interrupted", RequestId = fixture.Input.RequestId, CreatedByUserId = "system:certificate-expiry",
            Subject = "原提醒", Body = "原摘要", ToJson = "[\"to@example.test\"]", Status = "Sending", CreatedAtUtc = DateTime.UtcNow.AddMinutes(-10) });
        await fixture.Db.SaveChangesAsync();
        var result = await fixture.Mail.SendExpiryReminderAsync(fixture.Input, default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("Unknown", result.Data!.Status);
        Assert.Equal("原摘要", result.Data.Body);
        Assert.Equal(0, fixture.Transport.Calls);
    }

    [Fact]
    public async Task SystemEntry_CannotReadAnAdministratorsRequest()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Db.MailMessages.Add(new() { Id = "admin-mail", RequestId = fixture.Input.RequestId, CreatedByUserId = "admin",
            Subject = "人工邮件", Body = "管理员正文", Status = "Accepted", CreatedAtUtc = DateTime.UtcNow });
        await fixture.Db.SaveChangesAsync();
        var result = await fixture.Mail.SendExpiryReminderAsync(fixture.Input, default);
        Assert.False(result.Success);
        Assert.Equal("CONFLICT", result.Code);
        Assert.Null(result.Data);
        Assert.Equal(0, fixture.Transport.Calls);
    }

    private static ExpiryAlertView AlertView(DateTime now) => new("alert", "certificate", "测试账号", "vpn.example.test", "测试别名",
        now.AddDays(5), "Active", now, null, now, "", "");

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, MailService mail,
        FakeTransport transport, TestIds ids, ExpiryReminderMailInput input) : IAsyncDisposable
    {
        public AppDbContext Db => db;
        public MailService Mail => mail;
        public FakeTransport Transport => transport;
        public TestIds Ids => ids;
        public ExpiryReminderMailInput Input => input;

        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            var now = DateTime.UtcNow;
            var input = new ExpiryReminderMailInput { RequestId = Guid.NewGuid().ToString("D"), To = ["to@example.test"],
                Subject = "到期提醒", Body = "提醒正文摘要", HtmlBody = "<p>本轮 HTML</p>", SettingsUpdatedAtUtc = now, AlertIds = ["alert"] };
            var protection = new EphemeralDataProtectionProvider();
            db.MailSettings.Add(new() { Host = "smtp.example.test", FromAddress = "from@example.test", Username = "from@example.test",
                ProtectedPassword = protection.CreateProtector("SslManager.Mail.Settings.v1").Protect("synthetic-password"), UpdatedAtUtc = now });
            db.ExpiryReminderSettings.Add(new() { Enabled = true, RecipientsJson = "[\"to@example.test\"]", UpdatedAtUtc = now });
            db.Certificates.Add(new() { Id = "certificate", AccountId = "account", Domain = "vpn.example.test", Status = "Issued", NotAfterUtc = now.AddDays(5) });
            db.CertificateExpiryAlerts.Add(new() { Id = "alert", CertificateId = "certificate", Domain = "vpn.example.test", NotAfterUtc = now.AddDays(5),
                Status = "Active", PendingRequestId = input.RequestId, UpdatedAtUtc = now, FirstDetectedAtUtc = now });
            await db.SaveChangesAsync();
            var transport = new FakeTransport(); var ids = new TestIds();
            return new(connection, db, new(db, protection, ids, transport, new Lifetime()), transport, ids, input);
        }

        public async ValueTask DisposeAsync() { await db.DisposeAsync(); await connection.DisposeAsync(); }
    }

    private sealed class TestIds : IIdGenerator
    {
        public Action? OnGenerate { get; set; }
        public string NewId() { OnGenerate?.Invoke(); return Guid.NewGuid().ToString("N"); }
    }
    private sealed class FakeTransport : IMailTransport
    {
        public int Calls { get; private set; }
        public MailTransportMessage? Message { get; private set; }
        public MailTransportResult Result { get; set; } = new("Accepted", "MAIL_ACCEPTED", "");
        public Task<MailTransportProbeResult> ProbeAsync(MailTransportEndpoint endpoint, CancellationToken ct) => throw new NotSupportedException();
        public Task<MailTransportResult> SendAsync(MailTransportEndpoint endpoint, MailTransportMessage message, CancellationToken ct)
        { Calls++; Message = message; return Task.FromResult(Result); }
    }
    private sealed class Lifetime : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        public void StopApplication() { }
    }
}
