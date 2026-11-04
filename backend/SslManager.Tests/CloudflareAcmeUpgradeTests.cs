using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service.impl;

namespace SslManager.Tests;

/// <summary>新增签发结构只在内存 SQLite 验证；保留历史凭据、重复升级及原密钥恢复能力。</summary>
public sealed class CloudflareAcmeUpgradeTests
{
    private const string Baseline = "20261102133402_AddMcpServices";
    private const string Target = "20261103161458_AddCloudflareAcmeIssuance";

    [Fact]
    public async Task BaselineUpgradePreservesDataAndOldDnsSemanticsAndIsRepeatable()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
        await using var db = Database(connection);
        var migrator = db.GetService<IMigrator>();
        await migrator.MigrateAsync(Baseline);
        await HistoricalDatabaseRows.InsertAsync(db, "CloudAccounts", new CloudAccount
        { Id = "old-account", Name = "合成旧账号", Provider = "TencentCloud", ProtectedAccessKeyId = "synthetic-id", ProtectedAccessKeySecret = "synthetic-secret" });
        await HistoricalDatabaseRows.InsertAsync(db, "Certificates", new ManagedCertificate
        { Id = "old-certificate", AccountId = "old-account", Provider = "TencentCloud", CertificateId = "synthetic-cloud-id", Domain = "test.example.com", Status = "Issued" });
        await HistoricalDatabaseRows.InsertAsync(db, "CertificateSchedules", new CertificateSchedule
        { Id = "old-plan", AccountId = "old-account", Domain = "test.example.com", Enabled = false });
        var before = await TablesAsync(db);

        await migrator.MigrateAsync(Target);

        Assert.Equal(new[] { "CertificateIssuanceStates" }, (await TablesAsync(db)).Except(before).Order().ToArray());
        var account = await db.CloudAccounts.SingleAsync();
        Assert.Equal("synthetic-secret", account.ProtectedAccessKeySecret);
        Assert.Equal(AcmeProtocolClient.ProductionDirectory, account.AcmeDirectoryUrl);
        var certificate = await db.Certificates.SingleAsync();
        Assert.True(certificate.HasPrivateKey); Assert.False(certificate.IsStaging);
        Assert.Equal("synthetic-cloud-id", certificate.CertificateId);
        Assert.Null((await db.CertificateSchedules.SingleAsync()).DnsZoneId);
        Assert.False(db.Database.HasPendingModelChanges());
        await migrator.MigrateAsync(Target);
        Assert.Equal(11, (await db.Database.GetAppliedMigrationsAsync()).Count());
        // 固定验证 rc.1 终点；后续 MCP 增量保持待执行，不能把历史测试改成自动升级最新结构。
        Assert.DoesNotContain(Target, await db.Database.GetPendingMigrationsAsync());
        Assert.Single(await db.Certificates.ToListAsync());
        Assert.Equal("ok", await HistoricalDatabaseRows.ScalarAsync(db, "PRAGMA integrity_check"));
    }

    [Fact]
    public async Task FreshDatabaseBackupRestoresSameEncryptedPrivateKeyWithOriginalProtection()
    {
        await using var source = new SqliteConnection("Data Source=:memory:"); await source.OpenAsync();
        await using var db = Database(source); await db.GetService<IMigrator>().MigrateAsync(Target);
        var protection = new EphemeralDataProtectionProvider();
        var store = new CertificateIssuanceStore(db, protection);
        var created = await store.GetOrCreateAsync("local", "Acme", "test.example.com", "account");
        Assert.True(created.Success);
        var ciphertext = (await db.CertificateIssuanceStates.SingleAsync()).ProtectedPayload;
        Assert.DoesNotContain("BEGIN PRIVATE KEY", ciphertext);

        await using var restored = new SqliteConnection("Data Source=:memory:"); await restored.OpenAsync();
        source.BackupDatabase(restored);
        await using var restoredDb = Database(restored);
        var read = await new CertificateIssuanceStore(restoredDb, protection).GetAsync("local");
        Assert.True(read.Success); Assert.Equal(created.Data!.PrivateKeyPem, read.Data!.PrivateKeyPem);
        var missingOriginalKeys = new CertificateIssuanceStore(restoredDb, new EphemeralDataProtectionProvider());
        var rejected = await missingOriginalKeys.GetOrCreateAsync("local", "Acme", "test.example.com", "account");
        Assert.False(rejected.Success); Assert.Equal("CERTIFICATE_MATERIAL_UNREADABLE", rejected.Code);
        Assert.Equal(ciphertext, (await restoredDb.CertificateIssuanceStates.SingleAsync()).ProtectedPayload);
        Assert.Equal("ok", await HistoricalDatabaseRows.ScalarAsync(restoredDb, "PRAGMA integrity_check"));
    }

    [Fact]
    public async Task ProviderSpecificCredentialsAreProtectedAndCloudflareCannotBecomeCertificateIssuer()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
        await using var db = Database(connection); await db.Database.MigrateAsync();
        var store = new CloudAccountStore(db, new EphemeralDataProtectionProvider(), new GuidIdGenerator());
        var dns = await store.CreateAsync(new() { Name = "合成 DNS", Provider = "Cloudflare", AccessKeySecret = "synthetic-token", UseForCertificates = false }, default);
        Assert.True(dns.Success);
        Assert.NotEqual("synthetic-token", (await db.CloudAccounts.SingleAsync()).ProtectedAccessKeySecret);
        var credentials = await store.GetCredentialsAsync(dns.Data!.Id, default);
        Assert.Equal("", credentials.Data!.AccessKeyId); Assert.Equal("synthetic-token", credentials.Data.AccessKeySecret);
        var unsupported = await store.CreateAsync(new() { Name = "错误用途", Provider = "Cloudflare", AccessKeySecret = "synthetic-token" }, default);
        Assert.False(unsupported.Success);
        using var accountKey = System.Security.Cryptography.ECDsa.Create(System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var acme = await store.CreateAsync(new() { Name = "合成 ACME", Provider = "Acme", UseForDns = false,
            AccessKeyId = "https://acme-v02.api.letsencrypt.org/acme/acct/1234", AccessKeySecret = accountKey.ExportPkcs8PrivateKeyPem() }, default);
        Assert.True(acme.Success);
        Assert.True((await store.GetCredentialsAsync(acme.Data!.Id, default)).Success);
    }

    private static AppDbContext Database(SqliteConnection connection) => new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
    private static async Task<string[]> TablesAsync(AppDbContext db)
    {
        await using var command = db.Database.GetDbConnection().CreateCommand(); command.CommandText = "SELECT name FROM sqlite_master WHERE type='table'";
        await using var reader = await command.ExecuteReaderAsync(); var names = new List<string>();
        while (await reader.ReadAsync()) names.Add(reader.GetString(0)); return names.ToArray();
    }
}
