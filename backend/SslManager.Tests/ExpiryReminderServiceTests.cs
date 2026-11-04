using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mail;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Mail;

namespace SslManager.Tests;

/// <summary>所有证书、邮箱及数据库均为隔离合成数据，不执行真实云端或 SMTP 操作。</summary>
public sealed class ExpiryReminderServiceTests
{
    [Fact]
    public async Task SavingRulesAllowsMissingSmtpAndDoesNotSend()
    {
        await using var fixture = await Fixture.CreateAsync(smtp: false);
        await fixture.SettingsAsync(recipients: ["alerts@example.test", "ALERTS@example.test"]);
        await fixture.WithDb(async db =>
        {
            var settings = await db.ExpiryReminderSettings.SingleAsync();
            Assert.Equal("[\"alerts@example.test\"]", settings.RecipientsJson);
            Assert.Empty(await db.MailMessages.ToListAsync());
            Assert.Empty(await db.CertificateExpiryAlerts.ToListAsync());
        });
        using var scope = fixture.Services.CreateScope();
        var summary = await scope.ServiceProvider.GetRequiredService<IExpiryReminderService>().GetSettingsAsync(default);
        Assert.True(summary.Data!.Enabled); Assert.False(summary.Data.SmtpConfigured);
        Assert.Equal(0, fixture.Transport.Calls);
    }

    [Fact]
    public async Task FirstDetectionOnlyIncludesIssuedFutureCertificatesInsideThreshold()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.SettingsAsync();
        await fixture.AddCertificateAsync("inside", 29);
        await fixture.AddCertificateAsync("outside", 31);
        await fixture.AddCertificateAsync("historical-issued", -1);
        await fixture.AddCertificateAsync("historical-expired", -1, "Expired");
        await fixture.AddCertificateAsync("revoked", 5, "Revoked");
        Assert.Equal(1, await fixture.ProcessAsync());
        await fixture.WithDb(async db => Assert.Equal("inside", (await db.CertificateExpiryAlerts.SingleAsync()).CertificateId));
        Assert.Equal(1, fixture.Transport.Calls);
        Assert.Equal(0, await fixture.ProcessAsync());
    }

    [Theory]
    [InlineData(0, 1)]
    [InlineData(1, 2)]
    public async Task RepeatRulesContinueExistingAlertsAfterExpiry(int repeatDays, int expectedCalls)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.SettingsAsync(repeatDays);
        await fixture.AddCertificateAsync("cert", 0.5);
        await fixture.ProcessAsync();
        fixture.Clock.Advance(TimeSpan.FromDays(1.1));
        await fixture.WithDb(async db => { (await db.Certificates.SingleAsync()).Status = "Expired"; await db.SaveChangesAsync(); });
        await fixture.ProcessAsync();
        await fixture.ProcessAsync();
        Assert.Equal(expectedCalls, fixture.Transport.Calls);
        await fixture.WithDb(async db =>
        {
            var alert = await db.CertificateExpiryAlerts.SingleAsync();
            Assert.Equal("Active", alert.Status); Assert.Equal(expectedCalls, alert.AttemptSequence);
            if (repeatDays == 0) Assert.Null(alert.NextReminderAtUtc);
            else Assert.True(alert.NextReminderAtUtc > fixture.Clock.GetUtcNow().UtcDateTime);
        });
    }

    [Fact]
    public async Task AnotherCertificateForSameDomainDoesNotResolveOldCertificate()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.SettingsAsync();
        await fixture.AddCertificateAsync("old", 5);
        await fixture.ProcessAsync();
        await fixture.AddCertificateAsync("new-same-domain", 90);
        fixture.Clock.Advance(TimeSpan.FromDays(1.1));
        await fixture.ProcessAsync();
        await fixture.WithDb(async db => Assert.Equal("Active", (await db.CertificateExpiryAlerts.SingleAsync()).Status));
        Assert.Equal(2, fixture.Transport.Calls);
        await fixture.WithDb(async db => { (await db.Certificates.SingleAsync(item => item.Id == "old")).NotAfterUtc = fixture.Clock.GetUtcNow().UtcDateTime.AddDays(90); await db.SaveChangesAsync(); });
        await fixture.ProcessAsync();
        await fixture.WithDb(async db => Assert.Equal("Resolved", (await db.CertificateExpiryAlerts.SingleAsync()).Status));
        Assert.Equal(2, fixture.Transport.Calls);
    }

    [Fact]
    public async Task IgnorePersistsForSameExpiryButChangedExpiryCanCreateAnotherAlert()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.SettingsAsync();
        await fixture.AddCertificateAsync("cert", 10);
        await fixture.ProcessAsync();
        string id = "";
        await fixture.WithDb(async db => id = (await db.CertificateExpiryAlerts.SingleAsync()).Id);
        using (var scope = fixture.Services.CreateScope())
            Assert.True((await scope.ServiceProvider.GetRequiredService<IExpiryReminderService>().IgnoreAsync(id, default)).Success);
        fixture.Clock.Advance(TimeSpan.FromDays(1.1));
        await fixture.ProcessAsync();
        Assert.Equal(1, fixture.Transport.Calls);
        await fixture.WithDb(async db => { (await db.Certificates.SingleAsync()).NotAfterUtc = fixture.Clock.GetUtcNow().UtcDateTime.AddDays(15); await db.SaveChangesAsync(); });
        await fixture.ProcessAsync();
        await fixture.WithDb(async db =>
        {
            Assert.Equal(2, await db.CertificateExpiryAlerts.CountAsync());
            Assert.Equal(1, await db.CertificateExpiryAlerts.CountAsync(item => item.Status == "Ignored"));
            Assert.Equal(1, await db.CertificateExpiryAlerts.CountAsync(item => item.Status == "Active"));
        });
        Assert.Equal(2, fixture.Transport.Calls);
    }

    [Fact]
    public async Task ChangedExpiryStillInsideRangeContinuesAnExistingExpiredAlert()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.SettingsAsync(repeatDays: 0); await fixture.AddCertificateAsync("cert", 1); await fixture.ProcessAsync();
        fixture.Clock.Advance(TimeSpan.FromDays(3));
        await fixture.WithDb(async db =>
        {
            var certificate = await db.Certificates.SingleAsync();
            certificate.Status = "Expired"; certificate.NotAfterUtc = fixture.Clock.GetUtcNow().UtcDateTime.AddDays(-1);
            await db.SaveChangesAsync();
        });
        await fixture.ProcessAsync();
        await fixture.WithDb(async db =>
        {
            Assert.Equal(2, await db.CertificateExpiryAlerts.CountAsync());
            Assert.Equal(1, await db.CertificateExpiryAlerts.CountAsync(item => item.Status == "Active"));
            Assert.Equal(1, await db.CertificateExpiryAlerts.CountAsync(item => item.Status == "Resolved"));
        });
        Assert.Equal(2, fixture.Transport.Calls);
    }

    [Theory]
    [InlineData("Revoked")]
    [InlineData("Deleted")]
    [InlineData("Removed")]
    [InlineData("Refunded")]
    public async Task RemovedOrWithdrawnCertificateResolvesExistingAlert(string status)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.SettingsAsync(); await fixture.AddCertificateAsync("cert", 10); await fixture.ProcessAsync();
        await fixture.WithDb(async db => { (await db.Certificates.SingleAsync()).Status = status; await db.SaveChangesAsync(); });
        fixture.Clock.Advance(TimeSpan.FromDays(2)); await fixture.ProcessAsync();
        await fixture.WithDb(async db => Assert.Equal("Resolved", (await db.CertificateExpiryAlerts.SingleAsync()).Status));
        Assert.Equal(1, fixture.Transport.Calls);
    }

    [Fact]
    public async Task UnknownDoesNotRetryThisCycleAndNextCycleUsesAnotherRequest()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Transport.NextResult = new("Unknown", "MAIL_RESULT_UNKNOWN", "");
        await fixture.SettingsAsync(); await fixture.AddCertificateAsync("cert", 10);
        await fixture.ProcessAsync(); await fixture.ProcessAsync();
        Assert.Equal(1, fixture.Transport.Calls);
        await fixture.WithDb(async db => Assert.Equal("Unknown", (await db.CertificateExpiryAlerts.SingleAsync()).LastMailStatus));
        fixture.Clock.Advance(TimeSpan.FromDays(1.1)); await fixture.ProcessAsync();
        Assert.Equal(2, fixture.Transport.Calls);
        await fixture.WithDb(async db => Assert.Equal(2, await db.MailMessages.Select(item => item.RequestId).Distinct().CountAsync()));
    }

    [Fact]
    public async Task MissingSmtpPreservesFirstAttemptUntilSmtpBecomesReady()
    {
        await using var fixture = await Fixture.CreateAsync(smtp: false);
        await fixture.SettingsAsync(repeatDays: 0); await fixture.AddCertificateAsync("cert", 10);
        await fixture.ProcessAsync();
        await fixture.WithDb(async db =>
        {
            Assert.Empty(await db.MailMessages.ToListAsync());
            var alert = await db.CertificateExpiryAlerts.SingleAsync();
            Assert.Null(alert.LastAttemptAtUtc); Assert.NotNull(alert.NextReminderAtUtc); Assert.Equal("", alert.PendingRequestId);
        });
        await fixture.AddSmtpAsync(); await fixture.ProcessAsync();
        Assert.Equal(1, fixture.Transport.Calls);
    }

    [Fact]
    public async Task ConcurrentLeaseRecoveryUsesOriginalRequestAndNeverSendsTwice()
    {
        await using var fixture = await Fixture.CreateAsync();
        var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.Transport.OnSend = async () => { entered.TrySetResult(); await release.Task; };
        await fixture.SettingsAsync(); await fixture.AddCertificateAsync("cert", 10);
        var first = fixture.ProcessAsync();
        await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        string request = "";
        await fixture.WithDb(async db => request = (await db.CertificateExpiryAlerts.SingleAsync()).PendingRequestId);
        fixture.Clock.Advance(TimeSpan.FromMinutes(4));
        Assert.Equal(0, await fixture.ProcessAsync());
        await fixture.WithDb(async db => Assert.Equal(request, (await db.CertificateExpiryAlerts.SingleAsync()).PendingRequestId));
        Assert.Equal(1, fixture.Transport.Calls);
        release.TrySetResult(); await first;
        fixture.Clock.Advance(TimeSpan.FromMinutes(2)); await fixture.ProcessAsync();
        Assert.Equal(1, fixture.Transport.Calls);
        await fixture.WithDb(async db =>
        {
            Assert.Equal("", (await db.CertificateExpiryAlerts.SingleAsync()).PendingRequestId);
            Assert.Single(await db.MailMessages.ToListAsync());
        });
    }

    [Fact]
    public async Task CrashAfterSmtpBeforeCompletionIsReconciledFromOriginalLedger()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.SettingsAsync(); await fixture.AddCertificateAsync("cert", 10);
        fixture.Interceptor.FailCompletion = true;
        Assert.Equal(0, await fixture.ProcessAsync());
        Assert.Equal(1, fixture.Transport.Calls);
        await fixture.WithDb(async db =>
        {
            var recorded = await db.MailMessages.SingleAsync(); Assert.Equal("Sending", recorded.Status);
            recorded.CreatedAtUtc = DateTime.UtcNow.AddMinutes(-5);
            (await db.CertificateExpiryAlerts.SingleAsync()).LeaseUntilUtc = fixture.Clock.GetUtcNow().UtcDateTime.AddMinutes(-1);
            await db.SaveChangesAsync();
        });
        await fixture.ProcessAsync();
        Assert.Equal(1, fixture.Transport.Calls);
        await fixture.WithDb(async db =>
        {
            var alert = await db.CertificateExpiryAlerts.SingleAsync();
            Assert.Equal("Unknown", alert.LastMailStatus); Assert.Equal("", alert.PendingRequestId);
            Assert.Single(await db.MailMessages.ToListAsync());
        });
    }

    [Theory]
    [InlineData("ignore")]
    [InlineData("smtp")]
    [InlineData("rules")]
    public async Task CancellationAfterRecordingDoesNotConsumeFirstAttemptForRemainingAlerts(string change)
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.SettingsAsync(repeatDays: 0);
        await fixture.AddCertificateAsync("first", 10); await fixture.AddCertificateAsync("second", 11);
        fixture.Interceptor.AfterRecorded = async () => await fixture.WithDb(async db =>
        {
            if (change == "ignore") (await db.CertificateExpiryAlerts.SingleAsync(item => item.CertificateId == "first")).Status = "Ignored";
            else if (change == "smtp") (await db.MailSettings.SingleAsync()).UpdatedAtUtc = DateTime.UtcNow.AddTicks(1);
            else (await db.ExpiryReminderSettings.SingleAsync()).UpdatedAtUtc = fixture.Clock.GetUtcNow().UtcDateTime.AddTicks(1);
            await db.SaveChangesAsync();
        });
        Assert.Equal(0, await fixture.ProcessAsync());
        Assert.Equal(0, fixture.Transport.Calls);
        await fixture.WithDb(async db =>
        {
            var active = await db.CertificateExpiryAlerts.Where(item => item.Status == "Active").ToListAsync();
            Assert.NotEmpty(active);
            Assert.All(active, item => { Assert.Null(item.LastAttemptAtUtc); Assert.Equal(0, item.AttemptSequence);
                Assert.NotNull(item.NextReminderAtUtc); Assert.Equal("", item.PendingRequestId); });
        });
        await fixture.ProcessAsync();
        Assert.Equal(1, fixture.Transport.Calls);
        await fixture.WithDb(async db => Assert.All(await db.CertificateExpiryAlerts.Where(item => item.Status == "Active").ToListAsync(),
            item => { Assert.NotNull(item.LastAttemptAtUtc); Assert.Equal(1, item.AttemptSequence); Assert.Null(item.NextReminderAtUtc); }));
    }

    private sealed class Fixture(ServiceProvider services, ManualClock clock, FakeTransport transport, MailInterceptor interceptor) : IAsyncDisposable
    {
        public ServiceProvider Services { get; } = services;
        public ManualClock Clock { get; } = clock;
        public FakeTransport Transport { get; } = transport;
        public MailInterceptor Interceptor { get; } = interceptor;
        public static async Task<Fixture> CreateAsync(bool smtp = true)
        {
            var directory = Directory.CreateTempSubdirectory("ssl-expiry-reminder-tests-").FullName;
            var services = new ServiceCollection();
            var clock = new ManualClock(DateTimeOffset.UtcNow);
            var transport = new FakeTransport(); var interceptor = new MailInterceptor();
            services.AddDbContext<AppDbContext>(options => options.UseSqlite("Data Source=" + Path.Combine(directory, "test.db"))
                .AddInterceptors(interceptor));
            services.AddSingleton<IDataProtectionProvider>(new EphemeralDataProtectionProvider());
            services.AddSingleton<IIdGenerator, GuidIdGenerator>(); services.AddSingleton<TimeProvider>(clock);
            services.AddSingleton<IHostApplicationLifetime>(new Lifetime()); services.AddSingleton<IMailTransport>(transport);
            services.AddScoped<IMailService, MailService>(); services.AddScoped<IExpiryReminderService, ExpiryReminderService>();
            services.AddSingleton<IExpiryReminderTemplateRenderer, FakeRenderer>();
            var fixture = new Fixture(services.BuildServiceProvider(), clock, transport, interceptor);
            await fixture.WithDb(async db =>
            {
                await db.Database.EnsureCreatedAsync();
                db.CloudAccounts.Add(new CloudAccount { Id = "account", Name = "合成测试账号", Provider = "TencentCloud" });
                await db.SaveChangesAsync();
            });
            if (smtp) await fixture.AddSmtpAsync();
            return fixture;
        }
        public async Task SettingsAsync(int repeatDays = 1, string[]? recipients = null)
        {
            using var scope = Services.CreateScope();
            var result = await scope.ServiceProvider.GetRequiredService<IExpiryReminderService>().SaveSettingsAsync(new()
            { Enabled = true, DaysBeforeExpiry = 30, RepeatIntervalDays = repeatDays, Recipients = recipients ?? ["alerts@example.test"] }, default);
            Assert.True(result.Success, result.Message);
        }
        public async Task AddSmtpAsync()
        {
            using var scope = Services.CreateScope();
            var result = await scope.ServiceProvider.GetRequiredService<IMailService>().SaveSettingsAsync(new()
            { Enabled = true, Host = "smtp.example.test", Username = "sender@example.test", FromAddress = "sender@example.test",
                Password = "synthetic-expiry-smtp-password" }, default);
            Assert.True(result.Success, result.Message);
        }
        public Task AddCertificateAsync(string id, double expiryDays, string status = "Issued") => WithDb(async db =>
        {
            db.Certificates.Add(new ManagedCertificate { Id = id, AccountId = "account", Provider = "TencentCloud", Domain = "example.com",
                Alias = "合成证书", Status = status, NotAfterUtc = Clock.GetUtcNow().UtcDateTime.AddDays(expiryDays), SyncedAtUtc = Clock.GetUtcNow().UtcDateTime });
            await db.SaveChangesAsync();
        });
        public async Task<int> ProcessAsync()
        {
            using var scope = Services.CreateScope();
            return await scope.ServiceProvider.GetRequiredService<IExpiryReminderService>().ProcessAsync(default);
        }
        public async Task WithDb(Func<AppDbContext, Task> action)
        {
            using var scope = Services.CreateScope(); await action(scope.ServiceProvider.GetRequiredService<AppDbContext>());
        }
        public ValueTask DisposeAsync() => Services.DisposeAsync();
    }

    private sealed class ManualClock(DateTimeOffset now) : TimeProvider
    {
        private long ticks = now.UtcTicks;
        public override DateTimeOffset GetUtcNow() => new(Interlocked.Read(ref ticks), TimeSpan.Zero);
        public void Advance(TimeSpan duration) => Interlocked.Add(ref ticks, duration.Ticks);
    }
    private sealed class FakeRenderer : IExpiryReminderTemplateRenderer
    {
        public Task<ExpiryReminderContent> RenderAsync(IReadOnlyList<ExpiryAlertView> alerts, int daysBeforeExpiry, DateTime generatedAtUtc, CancellationToken ct)
            => Task.FromResult(new ExpiryReminderContent("合成到期预警", string.Join(";", alerts.Select(item => item.CertificateId)), "<html><body>synthetic reminder</body></html>"));
    }
    private sealed class FakeTransport : IMailTransport
    {
        private int calls;
        public int Calls => Volatile.Read(ref calls);
        public MailTransportResult? NextResult { get; set; }
        public Func<Task>? OnSend { get; set; }
        public Task<MailTransportProbeResult> ProbeAsync(MailTransportEndpoint endpoint, CancellationToken ct) => Task.FromResult(new MailTransportProbeResult(true, "OK", ""));
        public async Task<MailTransportResult> SendAsync(MailTransportEndpoint endpoint, MailTransportMessage message, CancellationToken ct)
        {
            Interlocked.Increment(ref calls); if (OnSend is { } hook) await hook();
            var result = NextResult ?? new("Accepted", "MAIL_ACCEPTED", ""); NextResult = null; return result;
        }
    }
    private sealed class MailInterceptor : SaveChangesInterceptor
    {
        public bool FailCompletion { get; set; }
        public Func<Task>? AfterRecorded { get; set; }
        public override ValueTask<InterceptionResult<int>> SavingChangesAsync(DbContextEventData eventData, InterceptionResult<int> result, CancellationToken ct = default)
        {
            if (FailCompletion && eventData.Context!.ChangeTracker.Entries<MailMessage>().Any(item => item.Entity.Status == "Accepted"))
            { FailCompletion = false; throw new InvalidOperationException("synthetic-completion-crash"); }
            return ValueTask.FromResult(result);
        }
        public override async ValueTask<int> SavedChangesAsync(SaveChangesCompletedEventData eventData, int result, CancellationToken ct = default)
        {
            if (AfterRecorded is { } hook && eventData.Context!.ChangeTracker.Entries<MailMessage>().Any(item => item.Entity.Status == "Sending"))
            { AfterRecorded = null; await hook(); }
            return result;
        }
    }
    private sealed class Lifetime : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => default;
        public CancellationToken ApplicationStopping => default;
        public CancellationToken ApplicationStopped => default;
        public void StopApplication() { }
    }
}
