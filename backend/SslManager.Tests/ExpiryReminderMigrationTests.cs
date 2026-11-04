using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Tests;

/// <summary>只在隔离 SQLite 验证已发布旧结构到新结构的升级，不打开业务数据库。</summary>
public sealed class ExpiryReminderMigrationTests
{
    [Fact]
    public async Task PreviousSchemaUpgradeOnlyAddsTwoReminderTablesAndPreservesConfiguration()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ssl-expiry-migration-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        await using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite("Data Source=" + Path.Combine(directory, "test.db")).Options);
        await db.GetService<IMigrator>().MigrateAsync("20261102061651_AddMailSending");
        await HistoricalDatabaseRows.InsertAsync(db, "CloudAccounts", new CloudAccount { Id = "synthetic-retained-cloud", Name = "迁移保留的账号", Provider = "TencentCloud",
            ProtectedAccessKeyId = "synthetic-protected-id", ProtectedAccessKeySecret = "synthetic-protected-secret", Enabled = false });
        var before = await TablesAsync(db);
        Assert.DoesNotContain("ExpiryReminderSettings", before);
        Assert.DoesNotContain("CertificateExpiryAlerts", before);
        Assert.Contains("20261102103053_AddCertificateExpiryAlerts", await db.Database.GetPendingMigrationsAsync());
        await db.GetService<IMigrator>().MigrateAsync("20261102103053_AddCertificateExpiryAlerts");
        var added = (await TablesAsync(db)).Except(before).Order().ToArray();
        Assert.Equal(new[] { "CertificateExpiryAlerts", "ExpiryReminderSettings" }, added);
        Assert.Equal("synthetic-protected-secret", await HistoricalDatabaseRows.ScalarAsync(db, "SELECT ProtectedAccessKeySecret FROM CloudAccounts"));
        Assert.Empty(await db.ExpiryReminderSettings.ToListAsync());
        Assert.Empty(await db.CertificateExpiryAlerts.ToListAsync());
        Assert.DoesNotContain("20261102103053_AddCertificateExpiryAlerts", await db.Database.GetPendingMigrationsAsync());
        Assert.False(db.Database.HasPendingModelChanges());
    }

    private static async Task<string[]> TablesAsync(AppDbContext db)
    {
        await db.Database.OpenConnectionAsync();
        await using var command = db.Database.GetDbConnection().CreateCommand();
        command.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name";
        await using var reader = await command.ExecuteReaderAsync();
        var names = new List<string>();
        while (await reader.ReadAsync()) names.Add(reader.GetString(0));
        return names.ToArray();
    }
}
