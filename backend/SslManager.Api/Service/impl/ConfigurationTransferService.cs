using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mail;
using SslManager.Api.Models.Mcp;
using OpenIddict.Abstractions;
using SslManager.Api.Service.impl.Deployment;
using SslManager.Api.Service.impl.Mail;

namespace SslManager.Api.Service.impl;

/// <summary>明文配置只在管理员请求内存中流转；预览承诺摘要，提交在事务中重新检查。</summary>
public sealed partial class ConfigurationTransferService(AppDbContext db, IDataProtectionProvider protection,
    IIdGenerator ids, IDeploymentExecutorResolver executors, IOpenIddictApplicationManager? mcpApplications = null) : IConfigurationTransferService
{
    internal const int MaximumPackageBytes = 5 * 1024 * 1024;
    internal const int MaximumRecords = 1000;
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        NumberHandling = JsonNumberHandling.Strict,
        MaxDepth = 64
    };
    private IDataProtector PreviewProtector => protection.CreateProtector("SslManager.ConfigurationTransfer.Preview.v1");

    public async Task<ApiResult<ConfigurationPackage>> ExportAsync(CancellationToken ct)
    {
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            var snapshot = await ReadSnapshotAsync(ct);
            var package = new ConfigurationPackage { ExportedAtUtc = DateTime.UtcNow };
            foreach (var row in snapshot.Accounts)
            {
                var protector = protection.CreateProtector(CloudAccountStore.ConfigurationProtectionPurpose, row.Id);
                package.CloudAccounts.Add(new() { SourceId = row.Id, Settings = new()
                {
                    Name = row.Name, Provider = row.Provider,
                    AccessKeyId = string.IsNullOrEmpty(row.ProtectedAccessKeyId) ? "" : protector.Unprotect(row.ProtectedAccessKeyId),
                    AccessKeySecret = string.IsNullOrEmpty(row.ProtectedAccessKeySecret) ? "" : protector.Unprotect(row.ProtectedAccessKeySecret), Enabled = row.Enabled,
                    UseForCertificates = row.UseForCertificates, UseForDns = row.UseForDns, ContactName = row.ContactName,
                    ContactEmail = row.ContactEmail, ContactPhone = row.ContactPhone, AliyunContactId = row.AliyunContactId, AcmeDirectoryUrl = row.AcmeDirectoryUrl,
                    AcmeAccountMode = row.AcmeAccountMode,
                    AutoSyncEnabled = row.AutoSyncEnabled, AutoSyncIntervalUnit = row.AutoSyncIntervalUnit,
                    AutoSyncIntervalValue = row.AutoSyncIntervalValue, AutoSyncAtLocalTime = row.AutoSyncAtLocalTime
                } });
            }
            foreach (var row in snapshot.Targets)
            {
                var settings = DeploymentTargetService.ExportConfiguration(row, protection);
                DeploymentTargetService.NormalizeConfiguration(settings);
                // 兼容旧目标时只读解析域名，不修改原目标或带出旧实例证书 ID。
                if (settings.Configuration.SourceDomain.Length == 0 && settings.Configuration.SourceCertificateId.Length > 0)
                {
                    var domain = await db.Certificates.AsNoTracking().Where(item => item.Id == settings.Configuration.SourceCertificateId)
                        .Select(item => item.Domain).SingleOrDefaultAsync(ct);
                    if (domain is not null) settings.Configuration.SourceDomain = DeploymentSourceBinding.NormalizeDomain(CertificateManagementService.PrimaryDomain(domain));
                }
                if (settings.Configuration.SourceFormat.Length > 0 && settings.Configuration.SourceDomain.Length == 0)
                    return ApiResult<ConfigurationPackage>.Fail("CONFIGURATION_INVALID", "部分部署目标缺少可移植的来源域名，请先完善配置。");
                settings.Configuration.SourceCertificateId = "";
                package.DeploymentTargets.Add(new() { SourceId = row.Id, Settings = settings });
            }
            foreach (var row in snapshot.Schedules)
            {
                var settings = CertificateScheduleService.ToScheduleInput(row);
                settings.ConfigRevision = null;
                var zone = string.IsNullOrEmpty(row.DnsZoneId) ? null : await db.Domains.AsNoTracking().SingleOrDefaultAsync(x => x.Id == row.DnsZoneId, ct);
                // 空字符串是导入后的未映射哨兵，不能导出成历史 null 并改走同账号自动匹配。
                if (row.DnsZoneId is not null && (zone is null || zone.Status == "NotPresent" ||
                    !snapshot.Accounts.Any(account => account.Id == zone.AccountId)))
                    return ApiResult<ConfigurationPackage>.Fail("DNS_ZONE_UNRESOLVED", "部分计划的 DNS 托管区域尚未映射或已不可用，请同步域名并重新绑定后再导出。");
                settings.DnsZoneId = null;
                package.CertificateSchedules.Add(new() { SourceId = row.Id, Settings = settings,
                    DnsAccountSourceId = zone?.AccountId, DnsZoneName = zone?.Name, DnsProviderZoneId = zone?.ZoneId });
            }
            if (snapshot.Mail is { } mail)
                package.MailSettings = new()
                {
                    Enabled = mail.Enabled, Host = mail.Host, Port = mail.Port, Security = mail.Security, Username = mail.Username,
                    FromAddress = mail.FromAddress, FromName = mail.FromName,
                    Password = protection.CreateProtector(MailService.ConfigurationProtectionPurpose).Unprotect(mail.ProtectedPassword)
                };
            if (snapshot.ExpiryReminders is { } reminders)
                package.ExpiryReminderSettings = new()
                {
                    Enabled = reminders.Enabled, DaysBeforeExpiry = reminders.DaysBeforeExpiry,
                    RepeatIntervalDays = reminders.RepeatIntervalDays,
                    Recipients = JsonSerializer.Deserialize<string[]>(reminders.RecipientsJson, Json) ?? throw new JsonException()
                };
            ExportMcpConfiguration(package, snapshot);
            if (RecordCount(package) > MaximumRecords || JsonSerializer.SerializeToUtf8Bytes(package, Json).Length > MaximumPackageBytes)
                return ApiResult<ConfigurationPackage>.Fail("VALIDATION", "配置数量或文件大小超过导出限制。");
            await transaction.CommitAsync(ct);
            return ApiResult<ConfigurationPackage>.Ok(package);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is CryptographicException or JsonException or InvalidOperationException or IOException or UnauthorizedAccessException or Microsoft.Data.Sqlite.SqliteException)
        { return ApiResult<ConfigurationPackage>.Fail("CONFIGURATION_UNAVAILABLE", "配置或凭据无法完整读取，请核对原密钥和配置；未生成不完整的导出文件。"); }
    }

    public async Task<ApiResult<ConfigurationImportPreview>> PreviewAsync(ConfigurationImportRequest request, string userId, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(userId)) return ApiResult<ConfigurationImportPreview>.Fail("FORBIDDEN", "当前用户无配置导入权限。");
        var parsed = ParsePackage(request);
        if (parsed.Package is null)
            return ApiResult<ConfigurationImportPreview>.Ok(new(request.Mode, "", false, 0, 0, 0, [], parsed.Errors));
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            var snapshot = await ReadSnapshotAsync(ct);
            var plan = await CreatePlanAsync(parsed.Package, request.Mode, snapshot, ct);
            var canImport = plan.Errors.Count == 0;
            var token = canImport ? PreviewProtector.Protect(JsonSerializer.Serialize(new PreviewCommitment(
                parsed.Hash, request.Mode, userId, SnapshotDigest(snapshot), DateTime.UtcNow.AddMinutes(15)), Json)) : "";
            await transaction.CommitAsync(ct);
            return ApiResult<ConfigurationImportPreview>.Ok(new(request.Mode, token, canImport, plan.Created, plan.Updated,
                plan.Items.Count(item => item.Action == "Conflict"), plan.Items, plan.Errors));
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is CryptographicException or JsonException or InvalidOperationException or Microsoft.Data.Sqlite.SqliteException)
        { return ApiResult<ConfigurationImportPreview>.Fail("CONFIGURATION_UNAVAILABLE", "配置预览暂不可用，请稍后重新预览。"); }
    }

    public async Task<ApiResult<ConfigurationImportResult>> ImportAsync(ConfigurationImportRequest request, string userId, CancellationToken ct)
    {
        var parsed = ParsePackage(request);
        if (parsed.Package is null) return ApiResult<ConfigurationImportResult>.Fail("VALIDATION", "配置包格式或内容不正确，请重新预览。");
        PreviewCommitment commitment;
        try
        {
            if (string.IsNullOrWhiteSpace(userId) || string.IsNullOrEmpty(request.PreviewToken) || request.PreviewToken.Length > 16384)
                return ApiResult<ConfigurationImportResult>.Fail("CONFLICT", "缺少有效预览，请重新预览配置包。");
            commitment = JsonSerializer.Deserialize<PreviewCommitment>(PreviewProtector.Unprotect(request.PreviewToken), Json) ?? throw new JsonException();
            if (commitment.UserId != userId || commitment.Mode != request.Mode || commitment.PackageHash != parsed.Hash || commitment.ExpiresAtUtc <= DateTime.UtcNow)
                return ApiResult<ConfigurationImportResult>.Fail("CONFLICT", "预览已失效或配置包发生变化，请重新预览。");
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException or ArgumentException)
        { return ApiResult<ConfigurationImportResult>.Fail("CONFLICT", "预览凭证无效，请重新预览。"); }
        var committed = false;
        try
        {
            // SQLite Serializable 事务先保留写锁，摘要复核与全部保存处于同一提交边界。
            await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            var snapshot = await ReadSnapshotAsync(ct);
            if (SnapshotDigest(snapshot) != commitment.ConfigurationDigest)
                return ApiResult<ConfigurationImportResult>.Fail("CONFLICT", "当前配置已发生变化，请重新预览。");
            if (!await db.Users.AsNoTracking().AnyAsync(item => item.Id == userId && item.Enabled && item.Role == "admin", ct))
                return ApiResult<ConfigurationImportResult>.Fail("FORBIDDEN", "当前用户无配置导入权限。");
            var plan = await CreatePlanAsync(parsed.Package, request.Mode, snapshot, ct);
            if (plan.Errors.Count > 0)
                return ApiResult<ConfigurationImportResult>.Fail("CONFLICT", "配置存在冲突或相关任务仍在运行，请重新预览。");
            var now = DateTime.UtcNow;
            await ApplyPlanAsync(parsed.Package, plan, userId, now, ct);
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            committed = true;
            return ApiResult<ConfigurationImportResult>.Ok(new(plan.Created, plan.Updated, now), "配置已导入，所有导入项均保持停用，请核对后逐项启用。");
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception)
        {
            // 包括加密、并发与落库失败，均由事务回滚；错误不回显输入或异常正文。
            return ApiResult<ConfigurationImportResult>.Fail("CONFLICT", "配置导入未完成，所有变更已回滚，请重新预览后重试。");
        }
        finally { if (!committed) db.ChangeTracker.Clear(); }
    }

    private static int RecordCount(ConfigurationPackage package) => package.CloudAccounts.Count + package.DeploymentTargets.Count
        + package.CertificateSchedules.Count + (package.MailSettings is null ? 0 : 1) + (package.ExpiryReminderSettings is null ? 0 : 1)
        + (package.McpSettings is null ? 0 : 1) + package.McpClients.Count
        + package.McpClients.Sum(client => client?.AllowRules?.Count ?? 0);

    private async Task<ConfigurationSnapshot> ReadSnapshotAsync(CancellationToken ct) => new(
        await db.CloudAccounts.AsNoTracking().OrderBy(item => item.Id).ToListAsync(ct),
        await db.DeploymentTargets.AsNoTracking().OrderBy(item => item.Id).ToListAsync(ct),
        await db.CertificateSchedules.AsNoTracking().OrderBy(item => item.Id).ToListAsync(ct),
        await db.MailSettings.AsNoTracking().SingleOrDefaultAsync(ct),
        await db.ExpiryReminderSettings.AsNoTracking().SingleOrDefaultAsync(ct),
        await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(ct),
        await db.McpClients.AsNoTracking().OrderBy(item => item.Id).ToListAsync(ct),
        await db.McpAllowRules.AsNoTracking().OrderBy(item => item.Id).ToListAsync(ct));

    private static string SnapshotDigest(ConfigurationSnapshot snapshot)
    {
        // 显式纳入加密凭据；实体的 JsonIgnore 不能让密码变化绕过预览失效判断。
        var content = new
        {
            Accounts = snapshot.Accounts.Select(item => new { item.Id, item.Name, item.Provider, item.ProtectedAccessKeyId,
                item.ProtectedAccessKeySecret, item.Enabled, item.UseForCertificates, item.UseForDns, item.ContactName,
                item.ContactEmail, item.ContactPhone, item.AliyunContactId, item.AcmeDirectoryUrl, item.AcmeAccountMode,
                item.AcmeRegistrationStatus, item.AcmeRegisteredAtUtc, item.AutoSyncEnabled, item.AutoSyncIntervalUnit,
                item.AutoSyncIntervalValue, item.AutoSyncAtLocalTime, item.UpdatedAtUtc }),
            Targets = snapshot.Targets.Select(item => new { item.Id, item.Name, item.Description, item.ExecutorKey, item.ExecutorRevision,
                item.Endpoint, item.Port, item.Username, item.AuthenticationMode, item.Enabled, item.TlsFingerprint,
                item.ConfigurationJson, item.ProtectedCredentials, item.ConfigRevision, item.UpdatedAtUtc }),
            Schedules = snapshot.Schedules.Select(item => new { item.Id, item.Name, item.AccountId, item.Domain, item.Alias,
                item.ValidationMode, item.DnsZoneId, item.AutoCleanup, item.RevokeOldCertificates, item.TargetIdsJson, item.IntervalValue,
                item.IntervalUnit, item.FirstRunAtUtc, item.Enabled, item.ConfigRevision, item.UpdatedAtUtc }),
            Mail = snapshot.Mail is { } mail ? new { mail.Id, mail.Enabled, mail.Host, mail.Port, mail.Security, mail.Username,
                mail.FromAddress, mail.FromName, mail.ProtectedPassword, mail.UpdatedAtUtc } : null,
            ExpiryReminders = snapshot.ExpiryReminders,
            McpSettings = snapshot.McpSettings,
            McpClients = snapshot.McpClients.Select(item => new { item.Id, item.OAuthApplicationId, item.ClientId, item.Name,
                item.ClientType, item.GrantType, item.BoundUserId, item.ScopesJson, item.RedirectUrisJson, item.Enabled,
                item.ExpiresAtUtc, item.ConfigRevision, item.UpdatedAtUtc }),
            McpAllowRules = snapshot.McpAllowRules
        };
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(content, Json)));
    }

    private sealed record PreviewCommitment(string PackageHash, string Mode, string UserId, string ConfigurationDigest, DateTime ExpiresAtUtc);
    private sealed record ConfigurationSnapshot(List<CloudAccount> Accounts, List<DeploymentTarget> Targets,
        List<CertificateSchedule> Schedules, MailSettings? Mail, ExpiryReminderSettings? ExpiryReminders,
        McpSettings? McpSettings, List<McpClient> McpClients, List<McpAllowRule> McpAllowRules);
    private sealed class ImportPlan
    {
        public List<ConfigurationImportItemPreview> Items { get; } = [];
        public List<ConfigurationImportIssue> Errors { get; } = [];
        public Dictionary<string, string?> Accounts { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, string?> Targets { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, string?> Schedules { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, string?> McpClients { get; } = new(StringComparer.Ordinal);
        public int Created => Items.Count(item => item.Action == "Create");
        public int Updated => Items.Count(item => item.Action == "Update");
    }
}
