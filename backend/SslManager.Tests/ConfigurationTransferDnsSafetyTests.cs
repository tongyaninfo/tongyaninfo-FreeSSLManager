using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Tests;

/// <summary>复用隔离 HTTP 工厂，验证导入不能改变签发环境或覆盖独立 DNS 的活跃恢复凭据。</summary>
public sealed partial class ConfigurationTransferHttpTests
{
    private const string ProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory";
    private const string StagingDirectory = "https://acme-staging-v02.api.letsencrypt.org/directory";
    private const string DnsToken = "synthetic-original-dns-token";

    [Theory]
    [InlineData(ProductionDirectory, StagingDirectory)]
    [InlineData(StagingDirectory, ProductionDirectory)]
    public async Task ImportCannotSwitchAnExistingAcmeAccountBetweenProductionAndStaging(string original, string replacement)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        using var accountKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var package = new ConfigurationPackage
        {
            CloudAccounts = [new() { SourceId = "acme", Settings = new()
            { Name = "合成ACME账号", Provider = "Acme", UseForDns = false, AcmeDirectoryUrl = original,
                AccessKeyId = original.Replace("/directory", "/acme/acct/123456", StringComparison.Ordinal), AccessKeySecret = accountKey.ExportPkcs8PrivateKeyPem() } }]
        };
        await ImportAsync(admin, Request(package));
        package.CloudAccounts[0].Settings.AcmeDirectoryUrl = replacement;
        package.CloudAccounts[0].Settings.AccessKeyId = replacement.Replace("/directory", "/acme/acct/123456", StringComparison.Ordinal);

        var preview = await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", Request(package, "UpdateByName")));

        Assert.False(preview.CanImport);
        Assert.Empty(preview.PreviewToken);
        Assert.Contains(preview.Errors, item => item.Path.EndsWith("acmeDirectoryUrl", StringComparison.Ordinal));
        using var scope = factory.Services.CreateScope();
        Assert.Equal(original, (await scope.ServiceProvider.GetRequiredService<AppDbContext>().CloudAccounts.SingleAsync()).AcmeDirectoryUrl);
        Assert.Equal(0, factory.Transport.Calls);
    }

    [Theory]
    [InlineData("current-plan")]
    [InlineData("run-snapshot")]
    [InlineData("busy-certificate")]
    [InlineData("cleanup-job")]
    [InlineData("validation-row")]
    [InlineData("application-cleanup")]
    [InlineData("old-application-cleanup")]
    [InlineData("old-revocation-cleanup")]
    [InlineData("missing-zone")]
    public async Task DnsAccountOnlyImportRechecksIndependentDnsReferencesThatBecomeActiveAfterPreview(string source)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = DnsAccountPackage();
        await ImportAsync(admin, Request(package));
        string dnsAccountId;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var dns = await db.CloudAccounts.SingleAsync();
            dnsAccountId = dns.Id; dns.Enabled = true;
            db.CloudAccounts.Add(new CloudAccount { Id = "certificate-owner", Name = "合成签发账号", Provider = "TencentCloud" });
            db.Domains.Add(new ManagedDomain { Id = "independent-zone", AccountId = dns.Id, Provider = "Cloudflare", Name = "example.com", ZoneId = "synthetic-zone" });
            db.CertificateSchedules.Add(new CertificateSchedule
            {
                Id = "independent-plan", Name = "合成跨账号计划", AccountId = "certificate-owner", Domain = "example.com",
                DnsZoneId = source == "current-plan" ? "independent-zone" : null, TargetIdsJson = "[]", Enabled = false
            });
            await db.SaveChangesAsync();
        }
        package.CloudAccounts[0].Settings.AccessKeySecret = "synthetic-replacement-dns-token";
        var request = Request(package, "UpdateByName");
        var preview = await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", request));
        Assert.True(preview.CanImport, JsonSerializer.Serialize(preview.Errors, Json));
        request.PreviewToken = preview.PreviewToken;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            if (source is "busy-certificate" or "cleanup-job" or "validation-row")
            {
                db.Certificates.Add(new ManagedCertificate
                {
                    Id = "busy-dns-certificate", AccountId = "certificate-owner", Domain = "example.com",
                    Status = source == "cleanup-job" ? "Issued" : "PendingValidation",
                    DnsZoneId = source == "validation-row" ? null : "independent-zone"
                });
                if (source == "cleanup-job") db.CertificateJobs.Add(new CertificateJob
                { Id = "dns-cleanup-job", CertificateId = "busy-dns-certificate", Status = "Waiting" });
                if (source == "validation-row") db.ValidationRecords.Add(new ValidationRecord
                { Id = "dns-validation", CertificateId = "busy-dns-certificate", DnsZoneId = "independent-zone", Name = "_validation.example.com", Value = "synthetic-value" });
            }
            else
            {
                var snapshot = new Dictionary<string, object?> { ["accountId"] = "certificate-owner" };
                if (source == "run-snapshot") snapshot["dnsZoneId"] = "independent-zone";
                if (source == "missing-zone") snapshot["dnsZoneId"] = "missing-original-zone";
                if (source == "application-cleanup") snapshot["applicationCleanup"] = ApplicationCleanup(dnsAccountId);
                var old = new List<ScheduleCertificateCleanup>();
                if (source == "old-application-cleanup") old.Add(new()
                { CertificateId = "archived-certificate", ApplicationCleanup = ApplicationCleanup(dnsAccountId) });
                if (source == "old-revocation-cleanup") old.Add(new()
                { CertificateId = "archived-certificate", RevocationValidation = [new() { AccountId = dnsAccountId, Name = "_revoke.example.com" }] });
                db.CertificateScheduleRuns.Add(new CertificateScheduleRun
                {
                    Id = "independent-active-run", ScheduleId = "independent-plan", Active = true,
                    ConfigSnapshotJson = JsonSerializer.Serialize(snapshot, Json), OldCertificatesJson = JsonSerializer.Serialize(old, Json)
                });
            }
            await db.SaveChangesAsync();
        }

        var imported = await admin.PostAsJsonAsync($"{Api}/import", request);

        Assert.False(imported.IsSuccessStatusCode);
        var blockedPreview = await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", Request(package, "UpdateByName")));
        Assert.False(blockedPreview.CanImport);
        Assert.Contains(blockedPreview.Items, item => item.Kind == "CloudAccount" && item.Action == "Conflict");
        using var finalScope = factory.Services.CreateScope();
        var dnsAccount = await finalScope.ServiceProvider.GetRequiredService<AppDbContext>().CloudAccounts.SingleAsync(item => item.Id == dnsAccountId);
        Assert.True(dnsAccount.Enabled);
        var protector = finalScope.ServiceProvider.GetRequiredService<IDataProtectionProvider>().CreateProtector("SslManager.CloudAccount.v1", dnsAccount.Id);
        Assert.Equal(DnsToken, protector.Unprotect(dnsAccount.ProtectedAccessKeySecret));
        Assert.Equal(0, factory.Transport.Calls);
    }

    [Fact]
    public async Task AnInactivePlanDoesNotBlockDnsAccountImport()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = DnsAccountPackage();
        await ImportAsync(admin, Request(package));
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.CertificateSchedules.Add(new CertificateSchedule
            { Id = "inactive-plan", AccountId = "other-account", Name = "未运行计划", Domain = "example.com", DnsZoneId = "inactive-zone", Enabled = false });
            await db.SaveChangesAsync();
        }
        Assert.Equal(1, (await ImportAsync(admin, Request(package, "UpdateByName"))).Updated);
    }

    [Theory]
    [InlineData("")]
    [InlineData("missing-zone")]
    [InlineData("not-present-zone")]
    public async Task ExportRejectsUnresolvedDnsInsteadOfLosingTheIndependentAccountBinding(string zoneId)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        await SeedAsync(factory);
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            (await db.CertificateSchedules.SingleAsync()).DnsZoneId = zoneId;
            if (zoneId == "not-present-zone") db.Domains.Add(new ManagedDomain
            { Id = zoneId, AccountId = "source-cloud", Name = "example.com", ZoneId = "synthetic-not-present-zone", Status = "NotPresent" });
            await db.SaveChangesAsync();
        }

        var response = await admin.PostAsJsonAsync($"{Api}/export", new { });
        var json = await response.Content.ReadAsStringAsync();
        var result = JsonSerializer.Deserialize<ApiResult<ConfigurationPackage>>(json, Json);

        Assert.NotNull(result);
        Assert.False(result.Success);
        Assert.Equal("DNS_ZONE_UNRESOLVED", result.Code);
        Assert.Null(result.Data);
        Assert.DoesNotContain(CloudSecret, json);
        Assert.DoesNotContain(TargetPassword, json);
        Assert.Equal(0, factory.Transport.Calls);
    }

    [Fact]
    public async Task APortableDnsBindingImportsAsUnresolvedAndCannotBeReexportedAsLegacyAutomaticDns()
    {
        await using var source = new IsolatedFactory();
        using var sourceAdmin = source.CreateClient();
        await SetupAsync(sourceAdmin);
        await SeedAsync(source);
        using (var scope = source.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            (await db.CertificateSchedules.SingleAsync()).DnsZoneId = "not-exported-domain";
            await db.SaveChangesAsync();
        }
        var exported = await ReadSuccessAsync<ConfigurationPackage>(await sourceAdmin.PostAsJsonAsync($"{Api}/export", new { }));
        var plan = Assert.Single(exported.CertificateSchedules);
        Assert.Null(plan.Settings.DnsZoneId);
        Assert.Equal("source-cloud", plan.DnsAccountSourceId);
        Assert.Equal("example.com", plan.DnsZoneName);
        Assert.Equal("synthetic-zone", plan.DnsProviderZoneId);
        await using var destination = new IsolatedFactory();
        using var admin = destination.CreateClient();
        await SetupAsync(admin);
        await ImportAsync(admin, Request(exported));
        using (var scope = destination.Services.CreateScope())
            Assert.Equal("", (await scope.ServiceProvider.GetRequiredService<AppDbContext>().CertificateSchedules.SingleAsync()).DnsZoneId);

        var response = await admin.PostAsJsonAsync($"{Api}/export", new { });
        Assert.Contains("DNS_ZONE_UNRESOLVED", await response.Content.ReadAsStringAsync());
    }

    private static ConfigurationPackage DnsAccountPackage() => new()
    {
        CloudAccounts = [new() { SourceId = "dns-source", Settings = new()
        { Name = "合成独立DNS账号", Provider = "Cloudflare", AccessKeySecret = DnsToken, UseForCertificates = false, UseForDns = true } }]
    };

    private static ScheduleApplicationDnsCleanup ApplicationCleanup(string accountId) => new()
    { CertificateId = "archived-certificate", AccountId = "certificate-owner", Records = [new() { AccountId = accountId, Name = "_validation.example.com" }] };

    [Theory]
    [InlineData("Existing", "Automatic")]
    [InlineData("Automatic", "Existing")]
    public async Task ImportCannotChangeTheModeOfAnExistingAcmeAccount(string originalMode, string replacementMode)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = ConfiguredAcmePackage(originalMode);
        await ImportAsync(admin, Request(package));
        package.CloudAccounts[0].Settings.AcmeAccountMode = replacementMode;

        var preview = await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", Request(package, "UpdateByName")));

        Assert.False(preview.CanImport);
        Assert.Contains(preview.Errors, error => error.Path.EndsWith("acmeAccountMode", StringComparison.Ordinal));
        using var scope = factory.Services.CreateScope();
        Assert.Equal(originalMode, (await scope.ServiceProvider.GetRequiredService<AppDbContext>().CloudAccounts.SingleAsync()).AcmeAccountMode);
    }

    [Theory]
    [InlineData("Existing")]
    [InlineData("Automatic")]
    public async Task ImportCannotReplaceTheExternalAcmeAccountUrl(string mode)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = ConfiguredAcmePackage(mode);
        await ImportAsync(admin, Request(package));
        package.CloudAccounts[0].Settings.AccessKeyId = "https://acme-v02.api.letsencrypt.org/acme/acct/654321";

        var preview = await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", Request(package, "UpdateByName")));

        Assert.False(preview.CanImport);
        Assert.Contains(preview.Errors, error => error.Path.EndsWith("accessKeyId", StringComparison.Ordinal));
    }

    [Fact]
    public async Task AnUnregisteredAutomaticAccountImportsWithoutCreatingAnExternalAccountOrLocalPrivateKey()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = new ConfigurationPackage
        {
            CloudAccounts = [new() { SourceId = "automatic-acme", Settings = new()
            { Name = "待显式注册账户", Provider = "Acme", AcmeAccountMode = "Automatic", UseForDns = false, ContactEmail = "operator@example.test" } }]
        };
        await ImportAsync(admin, Request(package));

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var account = await db.CloudAccounts.SingleAsync();
        Assert.False(account.Enabled);
        Assert.Equal("Automatic", account.AcmeAccountMode);
        Assert.Equal("New", account.AcmeRegistrationStatus);
        Assert.Null(account.AcmeRegisteredAtUtc);
        Assert.Empty(account.ProtectedAccessKeyId);
        Assert.Empty(account.ProtectedAccessKeySecret);
        Assert.Empty(await db.CertificateIssuanceStates.ToListAsync());
    }

    [Theory]
    [InlineData("Existing")]
    [InlineData("Automatic")]
    public async Task ExportedAcmeCredentialsPreserveTheModeAndImportAsConfiguredWithoutRegistration(string mode)
    {
        await using var source = new IsolatedFactory();
        using var sourceAdmin = source.CreateClient();
        await SetupAsync(sourceAdmin);
        var package = ConfiguredAcmePackage(mode);
        await ImportAsync(sourceAdmin, Request(package));
        using (var scope = source.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var account = await db.CloudAccounts.SingleAsync();
            account.AcmeRegistrationStatus = "Registered"; account.AcmeRegisteredAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }
        var exported = await ReadSuccessAsync<ConfigurationPackage>(await sourceAdmin.PostAsJsonAsync($"{Api}/export", new { }));
        Assert.Equal(mode, Assert.Single(exported.CloudAccounts).Settings.AcmeAccountMode);
        Assert.Equal(package.CloudAccounts[0].Settings.AccessKeyId, exported.CloudAccounts[0].Settings.AccessKeyId);
        Assert.Equal(package.CloudAccounts[0].Settings.AccessKeySecret, exported.CloudAccounts[0].Settings.AccessKeySecret);
        await using var destination = new IsolatedFactory();
        using var admin = destination.CreateClient();
        await SetupAsync(admin);
        await ImportAsync(admin, Request(exported));

        using var finalScope = destination.Services.CreateScope();
        var finalDb = finalScope.ServiceProvider.GetRequiredService<AppDbContext>();
        var imported = await finalDb.CloudAccounts.SingleAsync();
        Assert.False(imported.Enabled);
        Assert.Equal(mode, imported.AcmeAccountMode);
        Assert.Equal("Configured", imported.AcmeRegistrationStatus);
        Assert.Null(imported.AcmeRegisteredAtUtc);
        Assert.NotEmpty(imported.ProtectedAccessKeyId);
        Assert.NotEmpty(imported.ProtectedAccessKeySecret);
        Assert.Empty(await finalDb.CertificateIssuanceStates.ToListAsync());
    }

    [Theory]
    [InlineData("mode")]
    [InlineData("status")]
    [InlineData("registration-time")]
    public async Task AccountModeAndRegistrationProgressInvalidateAnEarlierImportPreview(string changedField)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = ConfiguredAcmePackage("Automatic");
        await ImportAsync(admin, Request(package));
        var request = Request(package, "UpdateByName");
        request.PreviewToken = (await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", request))).PreviewToken;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var account = await db.CloudAccounts.SingleAsync();
            if (changedField == "mode") account.AcmeAccountMode = "Existing";
            if (changedField == "status") account.AcmeRegistrationStatus = "Registered";
            if (changedField == "registration-time") account.AcmeRegisteredAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();
        }

        var response = await admin.PostAsJsonAsync($"{Api}/import", request);
        var result = JsonSerializer.Deserialize<ApiResult<ConfigurationImportResult>>(await response.Content.ReadAsStringAsync(), Json);
        Assert.NotNull(result);
        Assert.False(result.Success);
        Assert.Contains("配置已发生变化", result.Message);
    }

    private static ConfigurationPackage ConfiguredAcmePackage(string mode)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return new()
        {
            CloudAccounts = [new() { SourceId = "configured-acme", Settings = new()
            { Name = "可复用ACME账户", Provider = "Acme", AcmeAccountMode = mode, UseForDns = false, ContactEmail = "operator@example.test",
                AccessKeyId = "https://acme-v02.api.letsencrypt.org/acme/acct/123456", AccessKeySecret = key.ExportPkcs8PrivateKeyPem() } }]
        };
    }

    [Theory]
    [InlineData("Prepared")]
    [InlineData("Submitting")]
    [InlineData("Unknown")]
    public async Task ImportCannotOverwriteAnAccountWhoseExplicitRegistrationIsInProgressOrUnknown(string status)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = ConfiguredAcmePackage("Automatic");
        await ImportAsync(admin, Request(package));
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            (await db.CloudAccounts.SingleAsync()).AcmeRegistrationStatus = status;
            await db.SaveChangesAsync();
        }

        var preview = await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", Request(package, "UpdateByName")));

        Assert.False(preview.CanImport);
        Assert.Contains(preview.Items, item => item.Kind == "CloudAccount" && item.Action == "Conflict");
        using var finalScope = factory.Services.CreateScope();
        Assert.Equal(status, (await finalScope.ServiceProvider.GetRequiredService<AppDbContext>().CloudAccounts.SingleAsync()).AcmeRegistrationStatus);
    }

    [Theory]
    [InlineData("Existing")]
    [InlineData("Automatic")]
    public async Task ImportCannotReplaceAnExistingAcmeAccountPublicKey(string mode)
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = ConfiguredAcmePackage(mode);
        await ImportAsync(admin, Request(package));
        using var replacement = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        package.CloudAccounts[0].Settings.AccessKeySecret = replacement.ExportPkcs8PrivateKeyPem();

        var preview = await ReadSuccessAsync<ConfigurationImportPreview>(await admin.PostAsJsonAsync($"{Api}/preview", Request(package, "UpdateByName")));

        Assert.False(preview.CanImport);
        Assert.Contains(preview.Errors, error => error.Path.EndsWith("accessKeySecret", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ImportingTheSameAcmePublicKeyInAnotherPemFormatPreservesTheOriginalCiphertext()
    {
        await using var factory = new IsolatedFactory();
        using var admin = factory.CreateClient();
        await SetupAsync(admin);
        var package = ConfiguredAcmePackage("Existing");
        await ImportAsync(admin, Request(package));
        string originalCiphertext;
        using (var scope = factory.Services.CreateScope())
            originalCiphertext = (await scope.ServiceProvider.GetRequiredService<AppDbContext>().CloudAccounts.SingleAsync()).ProtectedAccessKeySecret;
        using var key = ECDsa.Create();
        key.ImportFromPem(package.CloudAccounts[0].Settings.AccessKeySecret);
        var alternatePem = key.ExportECPrivateKeyPem();
        Assert.NotEqual(package.CloudAccounts[0].Settings.AccessKeySecret, alternatePem);
        package.CloudAccounts[0].Settings.AccessKeySecret = alternatePem;

        Assert.Equal(1, (await ImportAsync(admin, Request(package, "UpdateByName"))).Updated);

        using var finalScope = factory.Services.CreateScope();
        Assert.Equal(originalCiphertext, (await finalScope.ServiceProvider.GetRequiredService<AppDbContext>().CloudAccounts.SingleAsync()).ProtectedAccessKeySecret);
    }
}
