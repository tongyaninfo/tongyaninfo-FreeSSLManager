using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Api.Common;

/// <summary>初始化独立数据库；既有 Ready 数据库仅执行已经逐项确认的到期提醒增表迁移。</summary>
public static class DesktopDatabase
{
    public static async Task InitializeAsync(DesktopRuntime runtime, AppDbContext db, CancellationToken ct)
    {
        DesktopStorageManifest manifest;
        if (File.Exists(runtime.ManifestPath))
        {
            if ((File.GetAttributes(runtime.ManifestPath) & FileAttributes.ReparsePoint) != 0)
                throw new DesktopStartupException("DESKTOP_DATA_INVALID", "桌面数据标记不能是符号链接。");
            try { manifest = JsonSerializer.Deserialize<DesktopStorageManifest>(await File.ReadAllTextAsync(runtime.ManifestPath, ct), DesktopRuntime.Json) ?? throw new JsonException(); }
            catch (JsonException) { throw new DesktopStartupException("DESKTOP_DATA_INVALID", "桌面数据标记损坏，请从备份恢复。"); }
            if (manifest.Application != "SslManager.Desktop" || manifest.Protocol != 1 || manifest.State is not ("Initializing" or "Ready"))
                throw new DesktopStartupException("DESKTOP_DATA_UNSUPPORTED", "此数据目录的版本或来源不受当前客户端支持。");
        }
        else
        {
            if (File.Exists(runtime.DatabasePath))
                throw new DesktopStartupException("DESKTOP_DATA_UNRECOGNIZED", "此数据库未经过桌面导入流程确认，未自动接管或迁移。");
            manifest = new();
            await WriteManifestAsync(runtime.ManifestPath, manifest, ct);
        }
        if (db.Database.HasPendingModelChanges())
            throw new DesktopStartupException("DESKTOP_MODEL_UNSUPPORTED", "程序模型与现有迁移不一致，未修改数据库结构。");
        if (manifest.State == "Ready" && !File.Exists(runtime.DatabasePath))
            throw new DesktopStartupException("DESKTOP_DATA_INCOMPLETE", "桌面数据库已缺失，请恢复完整备份，未创建替代数据库。");
        var orderedKnown = db.Database.GetMigrations().ToArray();
        var known = orderedKnown.ToHashSet(StringComparer.Ordinal);
        var applied = (await db.Database.GetAppliedMigrationsAsync(ct)).ToArray();
        if (applied.Any(value => !known.Contains(value)))
            throw new DesktopStartupException("DESKTOP_DATABASE_NEWER_VERSION", "此数据库来自更新的客户端，未用旧程序自动降级数据。");
        // 历史特许只能作用于真实连续前缀，不能把中间缺失的迁移误当成允许补跑的单条提醒升级。
        if (!applied.SequenceEqual(orderedKnown.Take(applied.Length), StringComparer.Ordinal))
            throw new DesktopStartupException("DESKTOP_DATABASE_HISTORY_INVALID", "此数据库缺失中间迁移或历史不连续，已停止启动，未自动补写迁移或修改结构。");
        var pending = (await db.Database.GetPendingMigrationsAsync(ct)).ToArray();
        // 本次已确认新增两张提醒表；其他历史或未来迁移仍须独立确认，不能扩大自动升级范围。
        var approvedExpiryUpgrade = pending.Length == 1 && pending[0].EndsWith("_AddCertificateExpiryAlerts", StringComparison.Ordinal);
        if (manifest.State == "Ready" && pending.Length > 0 && !approvedExpiryUpgrade)
            throw new DesktopStartupException("DESKTOP_DATABASE_UPGRADE_REQUIRED", "此数据库需要单独确认的结构升级，启动已停止，原数据保持不变。");
        if (manifest.State == "Ready" && approvedExpiryUpgrade)
        {
            if (!Directory.EnumerateFiles(runtime.KeysDirectory, "*.xml").Any() &&
                (await db.Users.AnyAsync(ct) || await db.CloudAccounts.AnyAsync(ct) || await db.DeploymentTargets.AnyAsync(ct) || await db.MailSettings.AnyAsync(ct)))
                throw new DesktopStartupException("DESKTOP_KEYS_MISSING", "此数据目录缺少原加密密钥，请恢复数据库与密钥的完整备份。");
            await db.Database.MigrateAsync(ct);
        }
        if (manifest.State == "Initializing")
        {
            await db.Database.MigrateAsync(ct);
            manifest.State = "Ready";
            await WriteManifestAsync(runtime.ManifestPath, manifest, ct);
        }
        if (!Directory.EnumerateFiles(runtime.KeysDirectory, "*.xml").Any() &&
            (await db.Users.AnyAsync(ct) || await db.CloudAccounts.AnyAsync(ct) || await db.DeploymentTargets.AnyAsync(ct) || await db.MailSettings.AnyAsync(ct)))
            throw new DesktopStartupException("DESKTOP_KEYS_MISSING", "此数据目录缺少原加密密钥，请恢复数据库与密钥的完整备份。");
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;", ct);
        if (!OperatingSystem.IsWindows() && File.Exists(runtime.DatabasePath))
            File.SetUnixFileMode(runtime.DatabasePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }

    private static async Task WriteManifestAsync(string path, DesktopStorageManifest manifest, CancellationToken ct)
    {
        var staged = path + ".pending-" + Guid.NewGuid().ToString("N");
        await File.WriteAllTextAsync(staged, JsonSerializer.Serialize(manifest, DesktopRuntime.Json), ct);
        if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(staged, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        File.Move(staged, path, true);
    }
}
