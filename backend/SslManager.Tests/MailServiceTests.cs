using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Hosting;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mail;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Mail;

namespace SslManager.Tests;

/// <summary>仅使用新建 SQLite 内存库和协议替身，验证极简发件配置、落账及防重，不连接真实邮箱。</summary>
public sealed class MailServiceTests
{
    [Fact]
    public async Task MigrationAddsOnlyTwoMailTablesAndPreservesExistingUserData()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
        // 在全新的隔离内存库先应用旧版迁移，模拟升级前数据；没有任何现存业务数据库参与。
        await db.GetService<IMigrator>().MigrateAsync("20261101093752_AddCertificateSchedules");
        db.Users.Add(new UserAccount { Id = "existing-user", Username = "existing", NormalizedUsername = "EXISTING", Role = "admin", Enabled = true,
            DisplayName = "升级前用户", PasswordHash = "synthetic-existing-hash", CreatedAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync();
        var before = await TablesAsync(connection);

        // 此用例只检验邮件两表迁移，后续功能迁移由各自的隔离测试覆盖。
        await db.GetService<IMigrator>().MigrateAsync("20261102061651_AddMailSending");

        var added = (await TablesAsync(connection)).Except(before).OrderBy(x => x).ToArray();
        Assert.Equal(new[] { "MailMessages", "MailSettings" }, added);
        Assert.Equal("升级前用户", (await db.Users.AsNoTracking().SingleAsync()).DisplayName);
        Assert.Equal("20261102061651_AddMailSending", (await db.Database.GetAppliedMigrationsAsync()).Last());
        Assert.False(db.Database.HasPendingModelChanges());
        db.Set<MailSettings>().Add(new() { Id = "another-configuration" });
        // 数据库本身约束单套配置，不能依赖页面隐藏多邮箱入口来保证。
        await Assert.ThrowsAsync<DbUpdateException>(() => db.SaveChangesAsync());
    }

    [Fact]
    public async Task FirstSaveUsesSafeDefaultsAndNeverReturnsThePassword()
    {
        await using var fixture = await Fixture.CreateAsync();
        var initial = await fixture.Service.GetSettingsAsync(default);
        Assert.True(initial.Success);
        Assert.False(initial.Data!.Configured);
        Assert.Equal(465, initial.Data.Port);
        Assert.Equal("SslOnConnect", initial.Data.Security);

        var saved = await fixture.Service.SaveSettingsAsync(Settings(), default);

        Assert.True(saved.Success, saved.Message);
        Assert.True(saved.Data!.Configured);
        Assert.True(saved.Data.HasPassword);
        Assert.Equal("sender@example.test", saved.Data.Username);
        var stored = await fixture.Db.Set<MailSettings>().SingleAsync();
        Assert.Equal("default", stored.Id);
        Assert.DoesNotContain("synthetic-smtp-password", stored.ProtectedPassword);
        Assert.DoesNotContain("synthetic-smtp-password", JsonSerializer.Serialize(saved));
        Assert.DoesNotContain("ProtectedPassword", JsonSerializer.Serialize(saved));
        Assert.Equal(0, fixture.Transport.ProbeCalls);
        Assert.Equal(0, fixture.Transport.SendCalls);
    }

    [Fact]
    public async Task EmptyPasswordOnEditPreservesEncryptedValueAndExistingPassword()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.Service.SaveSettingsAsync(Settings(), default)).Success);
        var cipher = (await fixture.Db.Set<MailSettings>().AsNoTracking().SingleAsync()).ProtectedPassword;
        var edit = Settings();
        edit.Password = "";
        edit.FromName = "新的发件名称";

        Assert.True((await fixture.Service.SaveSettingsAsync(edit, default)).Success);
        Assert.Equal(cipher, (await fixture.Db.Set<MailSettings>().AsNoTracking().SingleAsync()).ProtectedPassword);
        Assert.True((await fixture.Service.ProbeAsync(default)).Success);
        Assert.Equal("synthetic-smtp-password", fixture.Transport.LastEndpoint!.Password);
        Assert.Equal(1, fixture.Transport.ProbeCalls);
        Assert.Equal(0, fixture.Transport.SendCalls);
        Assert.DoesNotContain("synthetic-smtp-password", JsonSerializer.Serialize(fixture.Transport.LastEndpoint));
        Assert.DoesNotContain("synthetic-smtp-password", fixture.Transport.LastEndpoint.ToString());
    }

    [Theory]
    [InlineData("host")]
    [InlineData("port")]
    [InlineData("security")]
    [InlineData("from")]
    [InlineData("username")]
    public async Task InvalidConfigurationCannotOverwriteSavedSettings(string invalidField)
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.Service.SaveSettingsAsync(Settings(), default)).Success);
        var input = Settings();
        switch (invalidField)
        {
            case "host": input.Host = "https://smtp.example.test/path"; break;
            case "port": input.Port = 0; break;
            case "security": input.Security = "None"; break;
            case "from": input.FromAddress = "not-an-address"; break;
            case "username": input.Username = "sender\r\nInjected: value"; break;
        }

        var rejected = await fixture.Service.SaveSettingsAsync(input, default);

        Assert.False(rejected.Success);
        Assert.Equal("VALIDATION", rejected.Code);
        var stored = await fixture.Db.Set<MailSettings>().AsNoTracking().SingleAsync();
        Assert.Equal("smtp.example.test", stored.Host);
        Assert.Equal(465, stored.Port);
        Assert.Equal("SslOnConnect", stored.Security);
        Assert.Equal(0, fixture.Transport.SendCalls);
    }

    [Fact]
    public async Task MissingInitialPasswordAndUnconfiguredSendCreateNoRecords()
    {
        await using var fixture = await Fixture.CreateAsync();
        var settings = Settings();
        settings.Password = "";
        Assert.False((await fixture.Service.SaveSettingsAsync(settings, default)).Success);

        var sent = await fixture.Service.SendAsync(Input(), "admin-id", default);

        Assert.False(sent.Success);
        Assert.Empty(await fixture.Db.Set<MailSettings>().ToListAsync());
        Assert.Empty(await fixture.Db.Set<MailMessage>().ToListAsync());
        Assert.Equal(0, fixture.Transport.SendCalls);
    }

    [Fact]
    public async Task SendPersistsIntentBeforeProtocolCallAndFreezesSenderIdentity()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.Service.SaveSettingsAsync(Settings(), default)).Success);
        fixture.Transport.OnSend = async () =>
        {
            var intent = await fixture.Db.Set<MailMessage>().AsNoTracking().SingleAsync();
            Assert.Equal("Sending", intent.Status);
            Assert.Equal("admin-id", intent.CreatedByUserId);
            Assert.Equal("真实管理员", intent.CreatedByName);
            Assert.Equal("sender@example.test", intent.FromAddress);
        };

        var sent = await fixture.Service.SendAsync(Input(), "admin-id", default);

        Assert.True(sent.Success, sent.Message);
        Assert.Equal("Accepted", sent.Data!.Status);
        Assert.Equal("sender@example.test", sent.Data.FromAddress);
        Assert.NotNull(sent.Data.CompletedAtUtc);
        Assert.Equal("正文内容", sent.Data.Body);
        Assert.False(string.IsNullOrWhiteSpace(sent.Data.MessageId));
        Assert.Equal(sent.Data.MessageId, fixture.Transport.LastMessage!.MessageId);
        Assert.Equal(1, fixture.Transport.SendCalls);
        Assert.DoesNotContain("synthetic-smtp-password", JsonSerializer.Serialize(sent));
    }

    [Theory]
    [InlineData("Failed", "SMTP_REJECTED")]
    [InlineData("Unknown", "SMTP_RESULT_UNKNOWN")]
    public async Task NegativeAndUnknownResultsRemainVisibleWithoutAutomaticReplay(string status, string code)
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.Service.SaveSettingsAsync(Settings(), default)).Success);
        fixture.Transport.Result = new(status, code, "固定的安全结果说明");
        var input = Input();

        var first = await fixture.Service.SendAsync(input, "admin-id", default);
        var repeated = await fixture.Service.SendAsync(input, "admin-id", default);

        Assert.True(first.Success);
        Assert.Equal(status, first.Data!.Status);
        Assert.Equal(first.Data.Id, repeated.Data!.Id);
        Assert.Equal(status, repeated.Data.Status);
        Assert.Single(await fixture.Db.Set<MailMessage>().ToListAsync());
        Assert.Equal(1, fixture.Transport.SendCalls);
    }

    [Fact]
    public async Task TransportFreeTextAndUnexpectedExceptionCannotExposeCredentials()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.Service.SaveSettingsAsync(Settings(), default)).Success);
        fixture.Transport.Result = new("Failed", "synthetic-smtp-password", "SMTP returned synthetic-smtp-password");

        var failed = await fixture.Service.SendAsync(Input(), "admin-id", default);

        Assert.True(failed.Success);
        Assert.Equal("Failed", failed.Data!.Status);
        Assert.Equal("MAIL_SEND_FAILED", failed.Data.Code);
        Assert.DoesNotContain("synthetic-smtp-password", JsonSerializer.Serialize(failed));
        fixture.Transport.OnSend = () => throw new IOException("SMTP connection included synthetic-smtp-password");
        var interrupted = await fixture.Service.SendAsync(Input(), "admin-id", default);
        Assert.True(interrupted.Success);
        Assert.Equal("Unknown", interrupted.Data!.Status);
        Assert.DoesNotContain("synthetic-smtp-password", JsonSerializer.Serialize(interrupted));
        Assert.DoesNotContain("synthetic-smtp-password", JsonSerializer.Serialize(await fixture.Db.Set<MailMessage>().ToListAsync()));
    }

    [Fact]
    public async Task DisabledConfigurationBlocksBothProbeAndSend()
    {
        await using var fixture = await Fixture.CreateAsync();
        var input = Settings();
        input.Enabled = false;
        Assert.True((await fixture.Service.SaveSettingsAsync(input, default)).Success);

        Assert.False((await fixture.Service.ProbeAsync(default)).Success);
        Assert.False((await fixture.Service.SendAsync(Input(), "admin-id", default)).Success);

        Assert.Equal(0, fixture.Transport.ProbeCalls);
        Assert.Equal(0, fixture.Transport.SendCalls);
        Assert.Empty(await fixture.Db.Set<MailMessage>().ToListAsync());
    }

    [Fact]
    public async Task RequestIdReturnsOriginalRecordAndRejectsDifferentContent()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.Service.SaveSettingsAsync(Settings(), default)).Success);
        var input = Input();
        var first = await fixture.Service.SendAsync(input, "admin-id", default);
        var repeated = await fixture.Service.SendAsync(input, "admin-id", default);
        input.Body = "不同的内容";

        var conflict = await fixture.Service.SendAsync(input, "admin-id", default);

        Assert.True(repeated.Success);
        Assert.Equal(first.Data!.Id, repeated.Data!.Id);
        Assert.False(conflict.Success);
        Assert.Equal("CONFLICT", conflict.Code);
        Assert.Equal(1, fixture.Transport.SendCalls);
        Assert.Single(await fixture.Db.Set<MailMessage>().ToListAsync());
    }

    [Fact]
    public async Task AnotherAdministratorCannotReuseAnExistingRequestId()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.Service.SaveSettingsAsync(Settings(), default)).Success);
        fixture.Db.Users.Add(new UserAccount { Id = "another-admin", Username = "another", NormalizedUsername = "ANOTHER", Role = "admin", Enabled = true });
        await fixture.Db.SaveChangesAsync();
        var input = Input();
        Assert.True((await fixture.Service.SendAsync(input, "admin-id", default)).Success);

        var denied = await fixture.Service.SendAsync(input, "another-admin", default);

        Assert.False(denied.Success);
        Assert.Equal("CONFLICT", denied.Code);
        Assert.Equal(1, fixture.Transport.SendCalls);
    }

    [Theory]
    [InlineData("missing-user")]
    [InlineData("viewer-id")]
    [InlineData("disabled-admin-id")]
    public async Task SendRevalidatesTheActualEnabledAdministrator(string userId)
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.Service.SaveSettingsAsync(Settings(), default)).Success);
        fixture.Db.Users.AddRange(
            new UserAccount { Id = "viewer-id", Username = "viewer", NormalizedUsername = "VIEWER", Role = "viewer", Enabled = true },
            new UserAccount { Id = "disabled-admin-id", Username = "disabled", NormalizedUsername = "DISABLED", Role = "admin", Enabled = false });
        await fixture.Db.SaveChangesAsync();

        var denied = await fixture.Service.SendAsync(Input(), userId, default);

        Assert.False(denied.Success);
        Assert.Equal(0, fixture.Transport.SendCalls);
        Assert.Empty(await fixture.Db.Set<MailMessage>().ToListAsync());
    }

    [Theory]
    [InlineData("requestId")]
    [InlineData("recipient")]
    [InlineData("subject")]
    [InlineData("body")]
    public async Task InvalidMailNeverReachesTransportOrCreatesAnIntent(string invalidField)
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.True((await fixture.Service.SaveSettingsAsync(Settings(), default)).Success);
        var input = Input();
        switch (invalidField)
        {
            case "requestId": input.RequestId = ""; break;
            case "recipient": input.To = ["not-a-recipient"]; break;
            case "subject": input.Subject = "主题\r\nBcc: other@example.test"; break;
            case "body": input.Body = ""; break;
        }

        var rejected = await fixture.Service.SendAsync(input, "admin-id", default);

        Assert.False(rejected.Success);
        Assert.Equal("VALIDATION", rejected.Code);
        Assert.Equal(0, fixture.Transport.SendCalls);
        Assert.Empty(await fixture.Db.Set<MailMessage>().ToListAsync());
    }

    [Fact]
    public async Task ListFiltersBeforePaginationAndKeepsBodyOutOfTheList()
    {
        await using var fixture = await Fixture.CreateAsync();
        var now = DateTime.UtcNow;
        fixture.Db.Set<MailMessage>().AddRange(
            Message("first", "证书通知一", "Accepted", now),
            Message("other", "其他邮件", "Accepted", now.AddSeconds(1)),
            Message("failed", "证书通知失败", "Failed", now.AddSeconds(2)),
            Message("second", "证书通知二", "Accepted", now.AddSeconds(3)));
        await fixture.Db.SaveChangesAsync();

        var first = await fixture.Service.ListAsync(1, 1, "证书通知", "Accepted", default);
        var second = await fixture.Service.ListAsync(2, 1, "证书通知", "Accepted", default);

        Assert.Equal(2, first.Data!.Total);
        Assert.Equal(2, second.Data!.Total);
        Assert.Single(first.Data.Items);
        Assert.Single(second.Data.Items);
        Assert.NotEqual(first.Data.Items[0].Id, second.Data.Items[0].Id);
        Assert.DoesNotContain("仅限详情的正文", JsonSerializer.Serialize(first));
        Assert.Equal("VALIDATION", (await fixture.Service.ListAsync(0, 20, null, null, default)).Code);
        Assert.Equal("VALIDATION", (await fixture.Service.ListAsync(1, 101, null, null, default)).Code);
        Assert.Empty((await fixture.Service.ListAsync(int.MaxValue, 100, null, null, default)).Data!.Items);
    }

    [Fact]
    public async Task RecoveryOnlyMarksStaleSendingUnknownAndNeverResends()
    {
        await using var fixture = await Fixture.CreateAsync();
        var now = DateTime.UtcNow;
        fixture.Db.Set<MailMessage>().AddRange(
            Message("stale", "中断的发送", "Sending", now.AddMinutes(-10)),
            Message("active", "正在发送", "Sending", now),
            Message("done", "已提交", "Accepted", now.AddMinutes(-20)));
        await fixture.Db.SaveChangesAsync();

        Assert.Equal(1, await fixture.Service.RecoverInterruptedAsync(default));
        fixture.Db.ChangeTracker.Clear();
        Assert.Equal("Unknown", (await fixture.Db.Set<MailMessage>().SingleAsync(x => x.Id == "stale")).Status);
        Assert.Equal("Sending", (await fixture.Db.Set<MailMessage>().SingleAsync(x => x.Id == "active")).Status);
        Assert.Equal("Accepted", (await fixture.Db.Set<MailMessage>().SingleAsync(x => x.Id == "done")).Status);
        Assert.Equal(0, await fixture.Service.RecoverInterruptedAsync(default));
        Assert.Equal(0, fixture.Transport.SendCalls);
    }

    private static MailSettingsInput Settings() => new()
    {
        Host = "smtp.example.test", FromAddress = "sender@example.test", Password = "synthetic-smtp-password"
    };

    private static MailSendInput Input() => new()
    {
        RequestId = Guid.NewGuid().ToString(), To = ["recipient@example.test"], Subject = "测试主题", Body = "正文内容"
    };

    private static MailMessage Message(string id, string subject, string status, DateTime createdAtUtc) => new()
    {
        Id = id, RequestId = Guid.NewGuid().ToString(), ToJson = "[\"recipient@example.test\"]", FromAddress = "sender@example.test",
        Subject = subject, Body = "仅限详情的正文", Status = status, CreatedByUserId = "admin-id", CreatedByName = "真实管理员",
        CreatedAtUtc = createdAtUtc, MessageId = "<" + id + "@example.test>"
    };

    private static async Task<HashSet<string>> TablesAsync(SqliteConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table';";
        await using var reader = await command.ExecuteReaderAsync();
        var names = new HashSet<string>(StringComparer.Ordinal);
        while (await reader.ReadAsync()) names.Add(reader.GetString(0));
        return names;
    }

    private sealed class FakeTransport : IMailTransport
    {
        public int SendCalls { get; private set; }
        public int ProbeCalls { get; private set; }
        public MailTransportEndpoint? LastEndpoint { get; private set; }
        public MailTransportMessage? LastMessage { get; private set; }
        public MailTransportResult Result { get; set; } = new("Accepted", "SMTP_ACCEPTED", "已提交邮件服务器。");
        public Func<Task>? OnSend { get; set; }

        public Task<MailTransportProbeResult> ProbeAsync(MailTransportEndpoint endpoint, CancellationToken ct)
        {
            ProbeCalls++;
            LastEndpoint = endpoint;
            return Task.FromResult(new MailTransportProbeResult(true, "OK", "连接检测成功。"));
        }

        public async Task<MailTransportResult> SendAsync(MailTransportEndpoint endpoint, MailTransportMessage message, CancellationToken ct)
        {
            SendCalls++;
            LastEndpoint = endpoint;
            LastMessage = message;
            if (OnSend is not null) await OnSend();
            return Result;
        }
    }

    private sealed class Lifetime : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;
        public CancellationToken ApplicationStopping => CancellationToken.None;
        public CancellationToken ApplicationStopped => CancellationToken.None;
        public void StopApplication() { }
    }

    private sealed class Fixture(SqliteConnection connection, AppDbContext db) : IAsyncDisposable
    {
        public AppDbContext Db { get; } = db;
        public FakeTransport Transport { get; } = new();
        public MailService Service { get; private set; } = null!;

        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            db.Users.Add(new UserAccount { Id = "admin-id", Username = "actual-admin", NormalizedUsername = "ACTUAL-ADMIN",
                DisplayName = "真实管理员", Role = "admin", Enabled = true });
            await db.SaveChangesAsync();
            var fixture = new Fixture(connection, db);
            fixture.Service = new(db, new EphemeralDataProtectionProvider(), new GuidIdGenerator(), fixture.Transport, new Lifetime());
            return fixture;
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }
}
