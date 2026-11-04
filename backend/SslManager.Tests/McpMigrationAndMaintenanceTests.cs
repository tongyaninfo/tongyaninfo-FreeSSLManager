using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Tests;

/// <summary>只在内存库核对批准的九表范围、既有数据保留以及日志保留边界。</summary>
public sealed class McpMigrationAndMaintenanceTests
{
    [Fact]
    public async Task UpgradeAddsExactlyNineTablesAndPreservesExistingConfiguration()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
        await using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
        await db.GetService<IMigrator>().MigrateAsync("20261102103053_AddCertificateExpiryAlerts");
        await HistoricalDatabaseRows.InsertAsync(db, "CloudAccounts", new CloudAccount { Id = "retained", Name = "保留账号", ProtectedAccessKeyId = "synthetic-cipher-id",
            ProtectedAccessKeySecret = "synthetic-cipher-secret" });
        var before = await SchemasAsync(connection);
        await db.GetService<IMigrator>().MigrateAsync("20261102133402_AddMcpServices");
        var after = await SchemasAsync(connection);
        Assert.Equal(new[] { "McpAllowRules", "McpClients", "McpInvocationLogs", "McpOAuthApplications", "McpOAuthAuthorizations",
            "McpOAuthScopes", "McpOAuthTokens", "McpOperations", "McpSettings" }, after.Keys.Except(before.Keys).Order().ToArray());
        foreach (var (table, schema) in before) Assert.Equal(schema, after[table]);
        Assert.Equal("synthetic-cipher-secret", await HistoricalDatabaseRows.ScalarAsync(db, "SELECT ProtectedAccessKeySecret FROM CloudAccounts"));
        // 固定历史结构只投影当时已有的 ID，不能读取后来增加的实例身份列。
        Assert.Empty(await db.McpSettings.Select(x => x.Id).ToArrayAsync());
        Assert.DoesNotContain("20261102133402_AddMcpServices", await db.Database.GetPendingMigrationsAsync());
    }

    [Fact]
    public async Task InterruptedCallIsUnknownAndRetentionDoesNotDeleteOperationsOrTokens()
    {
        await using var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
        await using var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
        await db.Database.EnsureCreatedAsync();
        var now = DateTime.UtcNow;
        db.McpInvocationLogs.AddRange(new() { Id = "interrupted", StartedAtUtc = now.AddHours(-1) },
            new() { Id = "active", StartedAtUtc = now },
            new() { Id = "old", StartedAtUtc = now.AddDays(-100), Status = "Success" });
        db.McpOperations.Add(new() { Id = "unknown-operation", Status = "Unknown", ClientId = "client", IdempotencyKey = "retained-key" });
        db.Set<McpOAuthToken>().Add(new());
        await db.SaveChangesAsync();
        var maintenance = new McpMaintenanceService(db, TimeProvider.System);
        Assert.Equal(1, await maintenance.SweepAsync(default));
        db.ChangeTracker.Clear();
        Assert.Equal("Unknown", (await db.McpInvocationLogs.SingleAsync(x => x.Id == "interrupted")).Status);
        Assert.Equal(3, await db.McpInvocationLogs.CountAsync());
        db.McpSettings.Add(new() { LogRetentionDays = 90 }); await db.SaveChangesAsync();
        Assert.Equal(1, await maintenance.SweepAsync(default));
        Assert.Equal(2, await db.McpInvocationLogs.CountAsync());
        Assert.Single(await db.McpOperations.ToArrayAsync());
        Assert.Single(await db.Set<McpOAuthToken>().ToArrayAsync());
    }

    private static async Task<Dictionary<string, string>> SchemasAsync(SqliteConnection connection)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name";
        await using var reader = await command.ExecuteReaderAsync();
        var result = new Dictionary<string, string>();
        while (await reader.ReadAsync()) result[reader.GetString(0)] = reader.GetString(1);
        return result;
    }
}
