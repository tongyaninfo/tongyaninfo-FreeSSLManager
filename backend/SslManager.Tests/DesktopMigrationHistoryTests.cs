using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SslManager.Api.Common;
using SslManager.Api.Data;

namespace SslManager.Tests;

/// <summary>仅在新建隔离目录模拟迁移历史损坏，测试现场保留；不读取业务库或原密钥。</summary>
public sealed class DesktopMigrationHistoryTests
{
    [Theory]
    [InlineData("20261015094736_InitialCreate")]
    [InlineData("20261102103053_AddCertificateExpiryAlerts")]
    public async Task ReadyKnownHistoryWithMissingMiddleMigrationIsRejectedBeforeAnyRepair(string missing)
    {
        await using var fixture = await Fixture.CreateAsync();
        // 在隔离测试库故意构造历史缺口；结构已经完整，不能借历史特许重新执行旧迁移。
        await fixture.Db.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM __EFMigrationsHistory WHERE MigrationId = {missing}");
        var before = await fixture.SnapshotAsync();

        var error = await Assert.ThrowsAsync<DesktopStartupException>(() => DesktopDatabase.InitializeAsync(fixture.Runtime, fixture.Db, default));

        Assert.Equal("DESKTOP_DATABASE_HISTORY_INVALID", error.Code);
        Assert.Equal(before, await fixture.SnapshotAsync());
        Assert.Empty(Directory.GetFiles(fixture.Runtime.KeysDirectory, "*.xml"));
    }

    [Fact]
    public async Task UnknownFutureMigrationKeepsExistingNewerVersionCodeAndPreservesDatabase()
    {
        await using var fixture = await Fixture.CreateAsync();
        await fixture.Db.Database.ExecuteSqlRawAsync("INSERT INTO __EFMigrationsHistory (MigrationId,ProductVersion) VALUES ('20990101000000_SyntheticFuture','99.0.0')");
        var before = await fixture.SnapshotAsync();

        var error = await Assert.ThrowsAsync<DesktopStartupException>(() => DesktopDatabase.InitializeAsync(fixture.Runtime, fixture.Db, default));

        Assert.Equal("DESKTOP_DATABASE_NEWER_VERSION", error.Code);
        Assert.Equal(before, await fixture.SnapshotAsync());
    }

    [Theory]
    [InlineData("20261102133402_AddMcpServices")]
    [InlineData("20261103161458_AddCloudflareAcmeIssuance")]
    public async Task SupportedContinuousBaselineStillRequiresExplicitUpgrade(string target)
    {
        await using var fixture = await Fixture.CreateAsync(target);
        var before = await fixture.SnapshotAsync();

        var error = await Assert.ThrowsAsync<DesktopStartupException>(() => DesktopDatabase.InitializeAsync(fixture.Runtime, fixture.Db, default));

        Assert.Equal("DESKTOP_DATABASE_UPGRADE_REQUIRED", error.Code);
        Assert.Equal(before, await fixture.SnapshotAsync());
        Assert.Empty(Directory.GetFiles(fixture.Runtime.KeysDirectory, "*.xml"));
    }

    private sealed class Fixture(DesktopRuntime runtime, SqliteConnection connection, AppDbContext db) : IAsyncDisposable
    {
        public DesktopRuntime Runtime { get; } = runtime;
        public AppDbContext Db { get; } = db;

        public static async Task<Fixture> CreateAsync(string? target = null)
        {
            var root = Path.Combine(Path.GetTempPath(), "ssl-manager-desktop-history-tests", Guid.NewGuid().ToString("N"));
            var web = Path.Combine(root, "web"); Directory.CreateDirectory(web);
            await File.WriteAllTextAsync(Path.Combine(web, "index.html"), "<!doctype html><title>isolated migration test</title>");
            var runtime = DesktopRuntime.Create(new() { Type = "initialize", Protocol = 1, InstanceId = "history-test",
                Token = new string('A', 64), DataDirectory = Path.Combine(root, "business"), WebRoot = web });
            var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = runtime.DatabasePath }.ConnectionString);
            await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.GetService<IMigrator>().MigrateAsync(target);
            await File.WriteAllTextAsync(runtime.ManifestPath, JsonSerializer.Serialize(new { application = "SslManager.Desktop", protocol = 1, state = "Ready" }));
            return new(runtime, connection, db);
        }

        public async Task<string> SnapshotAsync()
        {
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name";
            await using var reader = await command.ExecuteReaderAsync();
            var schema = new List<string[]>();
            while (await reader.ReadAsync())
                schema.Add(Enumerable.Range(0, reader.FieldCount).Select(index => reader.IsDBNull(index) ? "" : reader.GetString(index)).ToArray());
            return JsonSerializer.Serialize(new { schema, migrations = await Db.Database.GetAppliedMigrationsAsync() });
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync(); await connection.DisposeAsync(); Runtime.Dispose();
            // 不清理目录、数据库或日志，方便复核拒绝后的原始现场。
        }
    }
}
