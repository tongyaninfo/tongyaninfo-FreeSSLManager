using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SslManager.Api.Data;

namespace SslManager.Tests;

/// <summary>固定验证 1.0.0 历史基线，只使用内存 SQLite，不打开业务数据库或生成密钥。</summary>
public sealed class ReleaseBaselineUpgradeTests
{
    private const string BaselineTarget = "20261102133402_AddMcpServices";

    // 历史基线保持不变；未来版本另增测试，不能将这里的目标替换成最新迁移。
    private static readonly string[] BaselineMigrations =
    [
        "20261015094736_InitialCreate",
        "20261015113232_AddCloudAccountSyncAndTestState",
        "20261015123945_RemoveAutoSyncScope",
        "20261015152909_AddAliyunContactId",
        "20261028061409_AddDeploymentTargets",
        "20261028061614_AddDeploymentRecoveryTasks",
        "20261101093752_AddCertificateSchedules",
        "20261102061651_AddMailSending",
        "20261102103053_AddCertificateExpiryAlerts",
        BaselineTarget
    ];

    public static IEnumerable<object[]> HistoricalMigrationEndpoints =>
        BaselineMigrations.Take(BaselineMigrations.Length - 1).Select(value => new object[] { value });

    [Theory]
    [MemberData(nameof(HistoricalMigrationEndpoints))]
    public async Task EveryHistoricalPrefixUpgradesToBaselineAndPreservesExistingData(string sourceMigration)
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = CreateDatabase(connection);
        var migrator = db.GetService<IMigrator>();
        await migrator.MigrateAsync(sourceMigration);
        Assert.Equal(BaselineMigrations.TakeWhile(value => value != sourceMigration).Append(sourceMigration),
            await db.Database.GetAppliedMigrationsAsync());

        // 按历史表实际列插入，不使用可能要求未来列的当前实体映射。
        await InsertHistoricalDataAsync(connection);
        var original = await ReadHistoricalDataAsync(connection);
        Assert.Equal("synthetic-baseline-cloud", original.CloudAccount[0]);
        Assert.Equal("synthetic-protected-access-id", original.CloudAccount[3]);
        Assert.Equal("synthetic-protected-access-secret", original.CloudAccount[4]);
        Assert.Equal("synthetic-baseline-audit", original.AuditLog[0]);
        Assert.Equal("SyntheticBaselineUpgrade", original.AuditLog[3]);

        await migrator.MigrateAsync(BaselineTarget);
        await AssertBaselineAsync(db, connection);
        AssertHistoricalDataEqual(original, await ReadHistoricalDataAsync(connection));
        var originalSchema = await ReadRowsAsync(connection,
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name");

        // 重复执行同一明确终点应保持已应用迁移、表结构和已有业务数据不变。
        await migrator.MigrateAsync(BaselineTarget);
        await AssertBaselineAsync(db, connection);
        AssertHistoricalDataEqual(original, await ReadHistoricalDataAsync(connection));
        var repeatedSchema = await ReadRowsAsync(connection,
            "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name");
        Assert.Equal(originalSchema.Count, repeatedSchema.Count);
        for (var index = 0; index < originalSchema.Count; index++)
            Assert.Equal(originalSchema[index], repeatedSchema[index]);
    }

    [Fact]
    public async Task FreshDatabaseInitializesExactlyTheOnePointZeroBaseline()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:");
        await connection.OpenAsync();
        await using var db = CreateDatabase(connection);
        Assert.Empty(await ReadRowsAsync(connection, "SELECT name FROM sqlite_master WHERE type = 'table'"));

        await db.GetService<IMigrator>().MigrateAsync(BaselineTarget);

        await AssertBaselineAsync(db, connection);
        Assert.Empty(await ReadRowsAsync(connection, "SELECT Id FROM CloudAccounts"));
        Assert.Empty(await ReadRowsAsync(connection, "SELECT Id FROM AuditLogs"));

        // 当前模型继续演进后，此固定历史终点不要求应用未来迁移或匹配未来模型。
        if (db.Database.GetMigrations().Last() == BaselineTarget)
            Assert.False(db.Database.HasPendingModelChanges());
    }

    private static AppDbContext CreateDatabase(SqliteConnection connection) =>
        new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);

    private static async Task AssertBaselineAsync(AppDbContext db, SqliteConnection connection)
    {
        Assert.Equal(BaselineMigrations, await db.Database.GetAppliedMigrationsAsync());
        var businessTables = (await ReadRowsAsync(connection,
            "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"))
            .Select(row => row[0])
            .Where(name => !name.StartsWith("__EF", StringComparison.Ordinal) &&
                !name.StartsWith("sqlite_", StringComparison.Ordinal))
            .ToArray();
        Assert.Equal(28, businessTables.Length);
        Assert.Contains("CloudAccounts", businessTables);
        Assert.Contains("McpSettings", businessTables);

        var integrity = Assert.Single(await ReadRowsAsync(connection, "PRAGMA integrity_check"));
        Assert.Equal("ok", Assert.Single(integrity));
        Assert.Empty(await ReadRowsAsync(connection, "PRAGMA foreign_key_check"));
    }

    private static async Task InsertHistoricalDataAsync(SqliteConnection connection)
    {
        // SQLite 历史表重建后可能不再保留列默认值，夹具须显式填齐该时点的全部非空列。
        var values = new Dictionary<string, object?>
        {
            ["Id"] = "synthetic-baseline-cloud",
            ["Name"] = "升级保留账号",
            ["Provider"] = "TencentCloud",
            ["ProtectedAccessKeyId"] = "synthetic-protected-access-id",
            ["ProtectedAccessKeySecret"] = "synthetic-protected-access-secret",
            ["Enabled"] = 0,
            ["UseForCertificates"] = 1,
            ["UseForDns"] = 0,
            ["ContactName"] = "合成联系人",
            ["ContactEmail"] = "synthetic@example.invalid",
            ["ContactPhone"] = "synthetic-phone",
            ["CreatedAtUtc"] = "2026-11-03 00:00:00",
            ["UpdatedAtUtc"] = "2026-11-03 01:00:00",
            ["AutoSyncAtLocalTime"] = "02:30",
            ["AutoSyncEnabled"] = 0,
            ["AutoSyncIntervalUnit"] = "hour",
            ["AutoSyncIntervalValue"] = 8,
            ["AutoSyncNextRunAtUtc"] = null,
            ["AutoSyncScope"] = "synthetic-historical-scope",
            ["LastAutoSyncAtUtc"] = null,
            ["LastTestAtUtc"] = null,
            ["LastTestCode"] = "SYNTHETIC",
            ["LastTestMessage"] = "合成测试状态",
            ["LastTestSuccess"] = 1,
            ["AliyunContactId"] = "synthetic-contact"
        };
        var columns = (await ReadRowsAsync(connection, "PRAGMA table_info(CloudAccounts)"))
            .Select(row => row[1]).ToArray();
        await using var command = connection.CreateCommand();
        var parameters = columns.Select((_, index) => "$value" + index).ToArray();
        command.CommandText = $"INSERT INTO CloudAccounts ({string.Join(", ", columns.Select(name => "\"" + name + "\""))}) " +
            $"VALUES ({string.Join(", ", parameters)});" + """
            INSERT INTO AuditLogs
                (Id, UserId, Username, Action, ResourceId, Success, Code, Message, CreatedAtUtc)
            VALUES
                ('synthetic-baseline-audit', 'synthetic-baseline-user', 'synthetic-user', 'SyntheticBaselineUpgrade',
                 'synthetic-baseline-cloud', 1, 'SYNTHETIC', '升级前审计记录', '2026-11-03 02:00:00');
            """;
        for (var index = 0; index < columns.Length; index++)
            command.Parameters.AddWithValue(parameters[index], values[columns[index]] ?? DBNull.Value);
        await command.ExecuteNonQueryAsync();
    }

    private static async Task<HistoricalData> ReadHistoricalDataAsync(SqliteConnection connection)
    {
        var cloud = Assert.Single(await ReadRowsAsync(connection, """
            SELECT Id, Name, Provider, ProtectedAccessKeyId, ProtectedAccessKeySecret, Enabled,
                UseForCertificates, UseForDns, ContactName, ContactEmail, ContactPhone, CreatedAtUtc, UpdatedAtUtc
            FROM CloudAccounts ORDER BY Id
            """));
        var audit = Assert.Single(await ReadRowsAsync(connection, """
            SELECT Id, UserId, Username, Action, ResourceId, Success, Code, Message, CreatedAtUtc
            FROM AuditLogs ORDER BY Id
            """));
        return new(cloud, audit);
    }

    private static void AssertHistoricalDataEqual(HistoricalData expected, HistoricalData actual)
    {
        Assert.Equal(expected.CloudAccount, actual.CloudAccount);
        Assert.Equal(expected.AuditLog, actual.AuditLog);
    }

    private static async Task<List<string[]>> ReadRowsAsync(SqliteConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        await using var reader = await command.ExecuteReaderAsync();
        var rows = new List<string[]>();
        while (await reader.ReadAsync())
        {
            var row = new string[reader.FieldCount];
            for (var index = 0; index < reader.FieldCount; index++)
                row[index] = reader.IsDBNull(index) ? "<null>" : reader.GetValue(index).ToString()!;
            rows.Add(row);
        }
        return rows;
    }

    private sealed record HistoricalData(string[] CloudAccount, string[] AuditLog);
}
