using System.Data.Common;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;

namespace SslManager.Tests;

/// <summary>只在隔离内存库核对增量范围、旧 OAuth 数据语义、失败原子性与成套恢复前的数据库快照。</summary>
public sealed class McpApiKeyUpgradeTests
{
    private const string Previous = "20261103161458_AddCloudflareAcmeIssuance";
    private const string Target = "20261104065304_AddMcpApiKeysAndAudit";

    [Fact]
    public async Task ExistingWebDatabaseRefusesAutomaticKeyUpgradeBeforeChangingSchema()
    {
        var directory = Path.Combine(Path.GetTempPath(), "ssl-mcp-key-upgrade-refusal-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var connectionString = "Data Source=" + Path.Combine(directory, "isolated.db");
        await using var connection = new SqliteConnection(connectionString); await connection.OpenAsync();
        await using (var previous = Database(connection)) await previous.GetService<IMigrator>().MigrateAsync(Previous);
        var before = await SchemaAsync(connection);
        await using var factory = new UpgradeRefusalFactory(directory, connectionString);
        var failure = Record.Exception(() => { using var client = factory.CreateClient(); });
        Assert.NotNull(failure); Assert.Contains("MCP_APIKEY_DATABASE_UPGRADE_REQUIRED", failure.ToString());
        Assert.Equal(before, await SchemaAsync(connection));
        Assert.Empty(Directory.GetFiles(Path.Combine(directory, "keys"), "*.xml"));
    }

    [Theory]
    [InlineData("20261102133402_AddMcpServices")]
    [InlineData(Previous)]
    public async Task SupportedUpgradePreservesOldOAuthAndBusinessRowsAndIsRepeatable(string source)
    {
        await using var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
        await using var db = Database(connection);
        var migrator = db.GetService<IMigrator>(); await migrator.MigrateAsync(source);
        await HistoricalDatabaseRows.InsertAsync(db, "CloudAccounts", new CloudAccount
        { Id = "retained", Name = "原账号", ProtectedAccessKeyId = "synthetic-cipher-id", ProtectedAccessKeySecret = "synthetic-cipher-secret" });
        await HistoricalDatabaseRows.InsertAsync(db, "McpSettings", new McpSettings { Enabled = false, PublicBaseUrl = "https://old.example.test" });
        await HistoricalDatabaseRows.InsertAsync(db, "McpInvocationLogs", new McpInvocationLog
        { Id = "old-log", ClientId = "old-client", AuthorizationId = "old-grant", Status = "Succeeded", Code = "OK" });
        await HistoricalDatabaseRows.InsertAsync(db, "McpOperations", new McpOperation
        { Id = "old-operation", ClientId = "old-client", AuthorizationId = "old-grant", EffectiveUserId = "old-user", IdempotencyKey = "old-idempotency" });
        var before = await SchemaAsync(connection);

        await migrator.MigrateAsync(Target);

        var after = await SchemaAsync(connection);
        var newTables = after.Keys.Except(before.Keys).ToArray();
        Assert.Contains("table:McpApiKeys", newTables);
        foreach (var (name, schema) in before.Where(entry => !entry.Key.Contains("McpSettings") && !entry.Key.Contains("McpInvocationLogs")
            && !entry.Key.Contains("McpOperations") && !(source != Previous && (entry.Key.Contains("CloudAccounts") || entry.Key.Contains("Certificates") || entry.Key.Contains("CertificateSchedules")))))
            Assert.Equal(schema, after[name]);
        var log = await db.McpInvocationLogs.SingleAsync();
        Assert.Equal("OAuth", log.AuthenticationType); Assert.Equal("old-grant", log.AuthorizationId);
        Assert.Equal("{}", log.ContextJson); Assert.Equal("", log.ApiKeyId);
        var operation = await db.McpOperations.SingleAsync();
        Assert.Equal("OAuth", operation.AuthenticationType); Assert.Equal("old-grant", operation.AuthorizationId);
        Assert.Equal("old-idempotency", operation.IdempotencyKey);
        var settings = await db.McpSettings.SingleAsync();
        Assert.Equal("Free SSL Manager", settings.SystemName); Assert.Equal("", settings.InstanceId);
        Assert.Equal("synthetic-cipher-secret", (await db.CloudAccounts.SingleAsync()).ProtectedAccessKeySecret);
        Assert.Empty(await db.McpApiKeys.ToListAsync());
        await migrator.MigrateAsync(Target);
        Assert.Equal(12, (await db.Database.GetAppliedMigrationsAsync()).Count());
        Assert.Empty(await db.Database.GetPendingMigrationsAsync());
        Assert.False(db.Database.HasPendingModelChanges());
        Assert.Equal("ok", await HistoricalDatabaseRows.ScalarAsync(db, "PRAGMA integrity_check"));
        Assert.Equal(after, await SchemaAsync(connection));
    }

    [Fact]
    public async Task FreshInstallAndBackupRestoreKeepKeyHashesWithoutExposingPlaintext()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
        await using var db = Database(connection); await db.Database.MigrateAsync();
        db.McpApiKeys.Add(new() { Id = "key", ClientId = "client", Name = "测试 Key", Prefix = "sslm_public-prefix", SecretHash = "synthetic-one-way-hash" });
        await db.SaveChangesAsync();
        await using var restored = new SqliteConnection("Data Source=:memory:"); await restored.OpenAsync();
        connection.BackupDatabase(restored);
        await using var restoredDb = Database(restored);
        Assert.Equal("synthetic-one-way-hash", (await restoredDb.McpApiKeys.SingleAsync()).SecretHash);
        Assert.Equal(12, (await restoredDb.Database.GetAppliedMigrationsAsync()).Count());
        Assert.DoesNotContain("SecretHash", System.Text.Json.JsonSerializer.Serialize(await restoredDb.McpApiKeys.SingleAsync()));
        Assert.Equal("ok", await HistoricalDatabaseRows.ScalarAsync(restoredDb, "PRAGMA integrity_check"));
    }

    [Fact]
    public async Task FailedIncrementRollsBackAndOriginalBackupRemainsRecoverable()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
        await using (var previous = Database(connection))
        {
            await previous.GetService<IMigrator>().MigrateAsync(Previous);
            await HistoricalDatabaseRows.InsertAsync(previous, "McpInvocationLogs", new McpInvocationLog { Id = "original", Code = "ORIGINAL" });
        }
        await using var backup = new SqliteConnection("Data Source=:memory:"); await backup.OpenAsync(); connection.BackupDatabase(backup);
        var before = await SchemaAsync(connection);
        await using (var failing = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection)
            .AddInterceptors(new FailKeyTableCreation()).Options))
            await Assert.ThrowsAsync<InvalidOperationException>(() => failing.GetService<IMigrator>().MigrateAsync(Target));
        Assert.Equal(before, await SchemaAsync(connection));
        await using var restored = new SqliteConnection("Data Source=:memory:"); await restored.OpenAsync(); backup.BackupDatabase(restored);
        await using var restoredDb = Database(restored);
        Assert.Equal(Previous, (await restoredDb.Database.GetAppliedMigrationsAsync()).Last());
        Assert.Equal("ORIGINAL", await HistoricalDatabaseRows.ScalarAsync(restoredDb, "SELECT Code FROM McpInvocationLogs"));
        Assert.Equal(before, await SchemaAsync(restored));
    }

    private sealed class FailKeyTableCreation : DbCommandInterceptor
    {
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command, CommandEventData eventData,
            InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            if (command.CommandText.Contains("CREATE TABLE \"McpApiKeys\"", StringComparison.Ordinal))
                throw new InvalidOperationException("隔离测试注入建表失败。");
            return ValueTask.FromResult(result);
        }
    }
    private sealed class UpgradeRefusalFactory(string directory, string connectionString) : WebApplicationFactory<Program>
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseContentRoot(Path.GetFullPath("../../../../SslManager.Api", AppContext.BaseDirectory));
            builder.UseSetting("ConnectionStrings:Default", connectionString);
            builder.UseSetting("Storage:KeyDirectory", Path.Combine(directory, "keys"));
            builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Default"] = connectionString,
                ["Storage:KeyDirectory"] = Path.Combine(directory, "keys")
            }));
        }
    }
    private static AppDbContext Database(SqliteConnection connection) => new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
    private static async Task<Dictionary<string, string>> SchemaAsync(SqliteConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT type || ':' || name, coalesce(sql,'') FROM sqlite_master ORDER BY type,name";
        await using var reader = await command.ExecuteReaderAsync(); var result = new Dictionary<string, string>();
        while (await reader.ReadAsync()) result[reader.GetString(0)] = reader.GetString(1);
        return result;
    }
}
