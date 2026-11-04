using System.Diagnostics;
using System.Net;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Tests;

/// <summary>启动独立测试后端进程与全新 SQLite 数据目录，不接触现有数据库、云账号或真实设备；测试现场保留。</summary>
public sealed class DesktopBackendTests
{
    [Fact]
    public async Task FreshDesktopStartsOnOneLoopbackPortWithSameOriginUiAndApi()
    {
        await using var app = await Fixture.StartAsync();
        Assert.Equal("ready", app.Ready.GetProperty("type").GetString());
        Assert.Equal(app.InstanceId, app.Ready.GetProperty("instanceId").GetString());
        Assert.Equal("127.0.0.1", new Uri(app.Origin).Host);
        Assert.NotEqual(0, new Uri(app.Origin).Port);
        var health = await app.Client.GetStringAsync("/api/health");
        Assert.Contains(app.InstanceId, health);
        Assert.Contains("desktop-test-ui", await app.Client.GetStringAsync("/"));
        Assert.Contains("desktop-test-ui", await app.Client.GetStringAsync("/certificates/example"));
        var unknown = await app.Client.GetAsync("/api/not-a-real-route");
        Assert.Equal(HttpStatusCode.NotFound, unknown.StatusCode);
        Assert.Equal("NOT_FOUND", JsonDocument.Parse(await unknown.Content.ReadAsStringAsync()).RootElement.GetProperty("code").GetString());
        Assert.Equal(HttpStatusCode.NotFound, (await app.Client.GetAsync("/missing-asset.js")).StatusCode);
        Assert.True(File.Exists(app.Database));
        await using var database = Database(app.Database);
        Assert.False(database.Database.HasPendingModelChanges());
    }

    [Theory]
    [InlineData("missing-token")]
    [InlineData("wrong-token")]
    [InlineData("cross-origin")]
    [InlineData("cross-referer")]
    [InlineData("wrong-host")]
    public async Task LocalApiRejectsOtherClientsAndCrossOriginRequests(string scenario)
    {
        await using var app = await Fixture.StartAsync();
        using var client = new HttpClient { BaseAddress = new(app.Origin) };
        if (scenario != "missing-token") client.DefaultRequestHeaders.Add(DesktopRuntime.TokenHeader, scenario == "wrong-token" ? new string('B', 64) : app.Token);
        if (scenario == "cross-origin") client.DefaultRequestHeaders.Add("Origin", "https://untrusted.invalid");
        if (scenario == "cross-referer") client.DefaultRequestHeaders.Referrer = new("https://untrusted.invalid/");
        if (scenario == "wrong-host") client.DefaultRequestHeaders.Host = "localhost:" + new Uri(app.Origin).Port;
        var response = await client.GetAsync("/api/health");
        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("DESKTOP_ACCESS_DENIED", await response.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task BackupIncludesWalCommitsAndPersistentKeysAndPreservesTheSource()
    {
        await using var app = await Fixture.StartAsync();
        // 未登录也能备份，首个正常密钥必须在 ready 前生成；原数据库继续由后端保持打开。
        Assert.NotEmpty(Directory.GetFiles(Path.Combine(app.Business, "keys"), "*.xml"));
        await using var db = Database(app.Database);
        db.AuditLogs.Add(new() { Id = "wal-record", UserId = "test", Username = "test", Action = "DesktopBackupTest", CreatedAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync();
        var destination = Path.Combine(app.Root, "backups", "snapshot");
        var result = await app.CommandAsync(new { type = "backup", requestId = "backup-1", destination });
        Assert.True(result.GetProperty("success").GetBoolean(), result.ToString());
        var data = result.GetProperty("data");
        Assert.Equal(destination, data.GetProperty("snapshotDirectory").GetString());
        Assert.Equal(Path.Combine(destination, "data", "ssl-manager.db"), data.GetProperty("databasePath").GetString());
        Assert.True(File.Exists(Path.Combine(destination, "desktop-storage.json")));
        Assert.NotEmpty(Directory.GetFiles(Path.Combine(destination, "keys"), "*.xml"));
        await using var snapshot = Database(data.GetProperty("databasePath").GetString()!);
        Assert.True(await snapshot.AuditLogs.AnyAsync(row => row.Id == "wal-record"));
        Assert.True(await db.AuditLogs.AnyAsync(row => row.Id == "wal-record"));
        Assert.False(snapshot.Database.HasPendingModelChanges());
    }

    [Fact]
    public async Task BackupNeverOverwritesExistingFilesOrWritesInsideBusinessData()
    {
        await using var app = await Fixture.StartAsync();
        var destination = Path.Combine(app.Root, "retained"); Directory.CreateDirectory(destination);
        var retained = Path.Combine(destination, "original.txt"); await File.WriteAllTextAsync(retained, "retained");
        var result = await app.CommandAsync(new { type = "backup", requestId = "nonempty", destination });
        Assert.Equal("BACKUP_PATH_NOT_EMPTY", result.GetProperty("code").GetString());
        Assert.Equal("retained", await File.ReadAllTextAsync(retained));
        result = await app.CommandAsync(new { type = "backup", requestId = "inside", destination = Path.Combine(app.Business, "snapshot") });
        Assert.Equal("BACKUP_PATH_INVALID", result.GetProperty("code").GetString());
    }

    [Fact]
    public async Task ClosingTheParentPipeStopsTheBackendAndReleasesItsDirectoryLock()
    {
        await using var app = await Fixture.StartAsync();
        app.Process.StandardInput.Close();
        await app.WaitForExitAsync();
        Assert.Equal(0, app.Process.ExitCode);
        await using var restarted = await Fixture.StartAsync(app.Root);
        Assert.Equal("ready", restarted.Ready.GetProperty("type").GetString());
    }

    [Fact]
    public async Task ShutdownAcknowledgesBeforeTheOwnedBackendExits()
    {
        await using var app = await Fixture.StartAsync();
        var response = await app.CommandAsync(new { type = "shutdown", requestId = "shutdown-1" });
        Assert.True(response.GetProperty("success").GetBoolean());
        await app.WaitForExitAsync();
        Assert.Equal(0, app.Process.ExitCode);
        Assert.DoesNotContain(app.Token, await app.Errors);
    }

    [Fact]
    public async Task TwoBackendProcessesCannotOpenTheSameDesktopDirectory()
    {
        await using var app = await Fixture.StartAsync();
        await using var other = await Fixture.LaunchAsync(app.Root);
        Assert.Equal("error", other.Ready.GetProperty("type").GetString());
        Assert.Equal("DESKTOP_DATA_BUSY", other.Ready.GetProperty("code").GetString());
        await other.WaitForExitAsync();
        Assert.NotEqual(0, other.Process.ExitCode);
        Assert.True((await app.Client.GetAsync("/api/health")).IsSuccessStatusCode);
    }

    [Fact]
    public async Task ReadyDatabaseRequiresExplicitMcpUpgradeBeforeStarting()
    {
        var root = Fixture.NewRoot();
        var business = Path.Combine(root, "business");
        Directory.CreateDirectory(Path.Combine(business, "data"));
        var path = Path.Combine(business, "data", "ssl-manager.db");
        await using (var db = Database(path))
        {
            await db.GetService<IMigrator>().MigrateAsync("20261102061651_AddMailSending");
            db.AuditLogs.Add(new() { Id = "expiry-upgrade-retained-audit", Action = "SyntheticExpiryMigration", CreatedAtUtc = DateTime.UtcNow });
            await db.SaveChangesAsync();
        }
        await File.WriteAllTextAsync(Path.Combine(business, "desktop-storage.json"), JsonSerializer.Serialize(new { application = "SslManager.Desktop", protocol = 1, state = "Ready" }));
        // 新增 MCP 后不能把它混在曾批准的到期提醒迁移中自动升级桌面存量库。
        await using (var refused = await Fixture.LaunchAsync(root))
        {
            Assert.Equal("DESKTOP_DATABASE_UPGRADE_REQUIRED", refused.Ready.GetProperty("code").GetString());
            await refused.WaitForExitAsync();
        }
        await using (var approved = Database(path))
        {
            Assert.Equal("20261102061651_AddMailSending", (await approved.Database.GetAppliedMigrationsAsync()).Last());
            await approved.Database.MigrateAsync(); // 仅本测试临时库中的显式结构升级。
        }
        await using var app = await Fixture.StartAsync(root);
        Assert.Equal("ready", app.Ready.GetProperty("type").GetString());
        await using var reopened = Database(path);
        Assert.True(await reopened.AuditLogs.AnyAsync(item => item.Id == "expiry-upgrade-retained-audit"));
        Assert.Empty(await reopened.ExpiryReminderSettings.ToListAsync());
        Assert.Empty(await reopened.CertificateExpiryAlerts.ToListAsync());
        Assert.Empty(await reopened.Database.GetPendingMigrationsAsync());
    }

    [Fact]
    public async Task ReadyDatabaseWithPendingMigrationsIsNotAutomaticallyUpgraded()
    {
        var root = Fixture.NewRoot(); var business = Path.Combine(root, "business");
        Directory.CreateDirectory(Path.Combine(business, "data"));
        var path = Path.Combine(business, "data", "ssl-manager.db");
        string[] before;
        await using (var db = Database(path))
        {
            await db.GetService<IMigrator>().MigrateAsync(db.Database.GetMigrations().First());
            before = (await db.Database.GetAppliedMigrationsAsync()).ToArray();
        }
        await File.WriteAllTextAsync(Path.Combine(business, "desktop-storage.json"), JsonSerializer.Serialize(new { application = "SslManager.Desktop", protocol = 1, state = "Ready" }));
        await using var app = await Fixture.LaunchAsync(root);
        Assert.Equal("DESKTOP_DATABASE_UPGRADE_REQUIRED", app.Ready.GetProperty("code").GetString());
        await app.WaitForExitAsync();
        await using var reopened = Database(path);
        Assert.Equal(before, await reopened.Database.GetAppliedMigrationsAsync());
    }

    [Fact]
    public async Task AnUnmarkedDatabaseIsNotClaimedOrMigratedByTheDesktop()
    {
        var root = Fixture.NewRoot(); var business = Path.Combine(root, "business");
        Directory.CreateDirectory(Path.Combine(business, "data"));
        var path = Path.Combine(business, "data", "ssl-manager.db");
        await using (var connection = new SqliteConnection("Data Source=" + path)) { await connection.OpenAsync(); }
        var original = await File.ReadAllBytesAsync(path);
        await using var app = await Fixture.LaunchAsync(root);
        Assert.Equal("DESKTOP_DATA_UNRECOGNIZED", app.Ready.GetProperty("code").GetString());
        await app.WaitForExitAsync();
        Assert.Equal(original, await File.ReadAllBytesAsync(path));
    }

    [Fact]
    public async Task ANewerDatabaseCannotBeSilentlyOpenedByAnOlderDesktop()
    {
        var root = Fixture.NewRoot();
        await using (var app = await Fixture.StartAsync(root)) { app.Process.StandardInput.Close(); await app.WaitForExitAsync(); }
        var path = Path.Combine(root, "business", "data", "ssl-manager.db");
        await using (var connection = new SqliteConnection("Data Source=" + path))
        {
            await connection.OpenAsync(); await using var command = connection.CreateCommand();
            command.CommandText = "INSERT INTO __EFMigrationsHistory (MigrationId, ProductVersion) VALUES ('99999999999999_FutureSchema', '10.0.0');";
            await command.ExecuteNonQueryAsync();
        }
        await using var older = await Fixture.LaunchAsync(root);
        Assert.Equal("DESKTOP_DATABASE_NEWER_VERSION", older.Ready.GetProperty("code").GetString());
        await older.WaitForExitAsync();
    }

    [Fact]
    public async Task MissingKeysDoNotProduceAReplacementKeyringForAnExistingAccountDatabase()
    {
        var root = Fixture.NewRoot();
        await using (var app = await Fixture.StartAsync(root))
        {
            await app.Client.GetAsync("/api/auth/csrf");
            await using var db = Database(app.Database);
            db.Users.Add(new() { Id = "user", Username = "desktop-test", NormalizedUsername = "DESKTOP-TEST" });
            await db.SaveChangesAsync();
            app.Process.StandardInput.Close(); await app.WaitForExitAsync();
        }
        // 保留原密钥现场，使用重命名模拟不完整恢复，不删除任何文件。
        Directory.Move(Path.Combine(root, "business", "keys"), Path.Combine(root, "retained-keys"));
        await using var restarted = await Fixture.LaunchAsync(root);
        Assert.Equal("DESKTOP_KEYS_MISSING", restarted.Ready.GetProperty("code").GetString());
        await restarted.WaitForExitAsync();
        Assert.Empty(Directory.GetFiles(Path.Combine(root, "business", "keys"), "*.xml"));
        Assert.NotEmpty(Directory.GetFiles(Path.Combine(root, "retained-keys"), "*.xml"));
    }

    [Fact]
    public async Task MissingReadyDatabaseDoesNotBecomeAnEmptyReplacementDatabase()
    {
        var root = Fixture.NewRoot();
        await using (var app = await Fixture.StartAsync(root)) { app.Process.StandardInput.Close(); await app.WaitForExitAsync(); }
        Directory.Move(Path.Combine(root, "business", "data"), Path.Combine(root, "retained-data"));
        await using var restarted = await Fixture.LaunchAsync(root);
        Assert.Equal("DESKTOP_DATA_INCOMPLETE", restarted.Ready.GetProperty("code").GetString());
        await restarted.WaitForExitAsync();
        Assert.False(File.Exists(Path.Combine(root, "business", "data", "ssl-manager.db")));
        Assert.True(File.Exists(Path.Combine(root, "retained-data", "ssl-manager.db")));
    }

    [Fact]
    public async Task StartingAgainReusesExistingKeysInsteadOfReplacingTheKeyring()
    {
        var root = Fixture.NewRoot(); Dictionary<string, string> original;
        await using (var app = await Fixture.StartAsync(root))
        {
            original = Directory.GetFiles(Path.Combine(app.Business, "keys"), "*.xml").ToDictionary(file => Path.GetFileName(file)!,
                file => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(file))));
            Assert.NotEmpty(original); app.Process.StandardInput.Close(); await app.WaitForExitAsync();
        }
        await using var restarted = await Fixture.StartAsync(root);
        var current = Directory.GetFiles(Path.Combine(restarted.Business, "keys"), "*.xml").ToDictionary(file => Path.GetFileName(file)!,
            file => Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(file))));
        Assert.Equal(original.OrderBy(item => item.Key), current.OrderBy(item => item.Key));
        restarted.Process.StandardInput.Close(); await restarted.WaitForExitAsync();
        Assert.DoesNotContain("SELECT ", await restarted.Errors);
    }

    [Fact]
    public async Task BackupParentLinksCannotAliasTheOriginalBusinessDirectory()
    {
        if (OperatingSystem.IsWindows()) return;
        await using var app = await Fixture.StartAsync();
        var alias = Path.Combine(app.Root, "business-alias"); Directory.CreateSymbolicLink(alias, app.Business);
        var result = await app.CommandAsync(new { type = "backup", requestId = "alias", destination = Path.Combine(alias, "backup") });
        Assert.Equal("BACKUP_PATH_INVALID", result.GetProperty("code").GetString());
        Assert.False(Directory.Exists(Path.Combine(app.Business, "backup")));
    }

    [Theory]
    [InlineData("relative/path", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "DESKTOP_PATH_INVALID")]
    [InlineData("absolute", "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG", "DESKTOP_INITIALIZATION_INVALID")]
    public void InvalidInitializationDoesNotTouchTheDataDirectory(string directory, string token, string code)
    {
        var root = Fixture.NewRoot(); var web = Path.Combine(root, "ui"); Directory.CreateDirectory(web);
        File.WriteAllText(Path.Combine(web, "index.html"), "desktop");
        var data = directory == "absolute" ? Path.Combine(root, "not-created") : directory;
        var error = Assert.Throws<DesktopStartupException>(() => DesktopRuntime.Create(new()
            { Type = "initialize", Protocol = 1, Token = token, InstanceId = "test", DataDirectory = data, WebRoot = web }));
        Assert.Equal(code, error.Code);
        if (directory == "absolute") Assert.False(Directory.Exists(data));
    }

    private static AppDbContext Database(string path) => new(new DbContextOptionsBuilder<AppDbContext>().UseSqlite("Data Source=" + path).Options);

    private sealed class Fixture(string root, Process process, Task<string> errors, string token, string instanceId, JsonElement ready) : IAsyncDisposable
    {
        public string Root => root;
        public string Business => Path.Combine(root, "business");
        public string Database => Path.Combine(Business, "data", "ssl-manager.db");
        public Process Process => process;
        public Task<string> Errors => errors;
        public string Token => token;
        public string InstanceId => instanceId;
        public JsonElement Ready => ready;
        public string Origin => ready.TryGetProperty("origin", out var origin) ? origin.GetString()! : "http://127.0.0.1";
        public HttpClient Client { get; } = ClientFor(ready, token);

        private static HttpClient ClientFor(JsonElement ready, string token)
        {
            var client = new HttpClient { BaseAddress = new(ready.TryGetProperty("origin", out var origin) ? origin.GetString()! : "http://127.0.0.1") };
            client.DefaultRequestHeaders.Add(DesktopRuntime.TokenHeader, token); return client;
        }

        public static string NewRoot() => Directory.CreateTempSubdirectory("ssl-desktop-backend-tests-").FullName;
        public static async Task<Fixture> StartAsync(string? root = null)
        {
            var result = await LaunchAsync(root);
            Assert.Equal("ready", result.Ready.GetProperty("type").GetString()); return result;
        }
        public static async Task<Fixture> LaunchAsync(string? root = null)
        {
            root ??= NewRoot(); var web = Path.Combine(root, "ui"); Directory.CreateDirectory(web);
            await File.WriteAllTextAsync(Path.Combine(web, "index.html"), "<!doctype html><title>desktop-test-ui</title>");
            var info = new ProcessStartInfo("dotnet") { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            info.ArgumentList.Add(typeof(Program).Assembly.Location); info.ArgumentList.Add("--desktop");
            // 验证桌面模式不会沿用环境中的非回环 Kestrel 监听配置。
            info.Environment["Kestrel__Endpoints__Unsafe__Url"] = "http://0.0.0.0:0";
            var process = Process.Start(info)!; var errors = process.StandardError.ReadToEndAsync();
            var token = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)); var id = Guid.NewGuid().ToString("N");
            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(new { type = "initialize", protocol = 1, token, instanceId = id, dataDirectory = Path.Combine(root, "business"), webRoot = web }));
            await process.StandardInput.FlushAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            var line = await process.StandardOutput.ReadLineAsync(timeout.Token);
            if (line is null) throw new InvalidOperationException("桌面测试后端未响应：" + await errors);
            return new(root, process, errors, token, id, JsonDocument.Parse(line).RootElement.Clone());
        }
        public async Task<JsonElement> CommandAsync(object command)
        {
            await process.StandardInput.WriteLineAsync(JsonSerializer.Serialize(command)); await process.StandardInput.FlushAsync();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            var line = await process.StandardOutput.ReadLineAsync(timeout.Token);
            Assert.NotNull(line);
            return JsonDocument.Parse(line).RootElement.Clone();
        }
        public async Task WaitForExitAsync()
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15)); await process.WaitForExitAsync(timeout.Token);
        }
        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            if (!process.HasExited)
            {
                try { process.StandardInput.Close(); await WaitForExitAsync(); }
                catch (Exception) { if (!process.HasExited) { process.Kill(entireProcessTree: true); await process.WaitForExitAsync(); } }
            }
            process.Dispose();
        }
    }
}
