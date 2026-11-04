using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>SQLite 在线备份包含 WAL 中已提交数据；随后复制不可变密钥文件，保证快照所需密钥先于数据库密文存在。</summary>
public sealed class DesktopBackupService(DesktopRuntime runtime) : IDesktopBackupService
{
    private readonly SemaphoreSlim gate = new(1, 1);

    public async Task<ApiResult<DesktopSnapshot>> CreateAsync(string? destination, CancellationToken ct)
    {
        await gate.WaitAsync(ct);
        try
        {
            var directory = DesktopRuntime.RequireAbsoluteDirectory(destination ?? Path.Combine(Path.GetDirectoryName(runtime.DataDirectory)!, "backups", "snapshot-" + Guid.NewGuid().ToString("N")));
            var actual = DesktopRuntime.PhysicalPath(directory); var business = DesktopRuntime.PhysicalPath(runtime.DataDirectory);
            if (Within(actual, business) || Within(business, actual))
                return ApiResult<DesktopSnapshot>.Fail("BACKUP_PATH_INVALID", "备份目录必须位于业务目录之外，不能覆盖业务目录或其父目录。");
            if (Directory.Exists(directory) && Directory.EnumerateFileSystemEntries(directory).Any())
                return ApiResult<DesktopSnapshot>.Fail("BACKUP_PATH_NOT_EMPTY", "备份只能写入全新的空目录，已有文件保持不变。");
            Directory.CreateDirectory(directory); DesktopRuntime.RequireOrdinaryDirectory(directory);
            var data = Path.Combine(directory, "data"); var keys = Path.Combine(directory, "keys");
            Directory.CreateDirectory(data); Directory.CreateDirectory(keys);
            if (!OperatingSystem.IsWindows())
                foreach (var path in new[] { directory, data, keys }) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            var database = Path.Combine(data, "ssl-manager.db");
            await using (var source = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = runtime.DatabasePath, Mode = SqliteOpenMode.ReadOnly }.ConnectionString))
            await using (var target = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database, Mode = SqliteOpenMode.ReadWriteCreate }.ConnectionString))
            {
                await source.OpenAsync(ct); await target.OpenAsync(ct);
                source.BackupDatabase(target);
                await using var command = target.CreateCommand(); command.CommandText = "PRAGMA integrity_check;";
                if (!string.Equals(await command.ExecuteScalarAsync(ct) as string, "ok", StringComparison.Ordinal))
                    return ApiResult<DesktopSnapshot>.Fail("BACKUP_INTEGRITY_FAILED", "SQLite 快照完整性检查未通过，未返回可恢复备份。");
            }
            // DataProtection 新密钥先写盘才参与加密；在数据库快照后复制密钥可覆盖快照中的所有已提交密文。
            var files = Directory.GetFiles(runtime.KeysDirectory, "*.xml", SearchOption.TopDirectoryOnly);
            var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var file in files)
            {
                if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0)
                    return ApiResult<DesktopSnapshot>.Fail("BACKUP_KEYS_INVALID", "密钥目录包含符号链接，已停止备份。");
                var content = await File.ReadAllBytesAsync(file, ct);
                var path = Path.Combine(keys, Path.GetFileName(file));
                await File.WriteAllBytesAsync(path, content, ct);
                hashes[Path.GetFileName(file)] = Convert.ToHexString(SHA256.HashData(content));
                if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            File.Copy(runtime.ManifestPath, Path.Combine(directory, "desktop-storage.json"), false);
            await File.WriteAllTextAsync(Path.Combine(directory, "snapshot.json"), JsonSerializer.Serialize(new
                { protocol = 1, application = "SslManager.Desktop", createdAtUtc = DateTime.UtcNow, database = "data/ssl-manager.db", keys = hashes }, DesktopRuntime.Json), ct);
            if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(database, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            return ApiResult<DesktopSnapshot>.Ok(new(directory, database, keys), "本地数据库和密钥一致性快照已完成。");
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SqliteException or DesktopStartupException)
        { return ApiResult<DesktopSnapshot>.Fail("BACKUP_FAILED", "本地备份未完成，请检查目录权限和可用空间；原数据未被覆盖。"); }
        finally { gate.Release(); }
    }

    private static bool Within(string candidate, string root)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return candidate.Equals(root, comparison) || candidate.StartsWith(root + Path.DirectorySeparatorChar, comparison);
    }
}
