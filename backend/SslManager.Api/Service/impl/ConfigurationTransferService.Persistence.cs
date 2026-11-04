using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Models.Mail;
using SslManager.Api.Service.impl.Deployment;
using SslManager.Api.Service.impl.Mail;

namespace SslManager.Api.Service.impl;

public sealed partial class ConfigurationTransferService
{
    private async Task ApplyPlanAsync(ConfigurationPackage package, ImportPlan plan, string userId, DateTime now, CancellationToken ct)
    {
        // 新 ID 只由项目统一入口生成，包内键从不直接作为目标数据库主键。
        var accountIds = plan.Accounts.ToDictionary(item => item.Key, item => item.Value ?? ids.NewId(), StringComparer.Ordinal);
        var targetIds = plan.Targets.ToDictionary(item => item.Key, item => item.Value ?? ids.NewId(), StringComparer.Ordinal);
        foreach (var item in package.CloudAccounts)
        {
            var existing = plan.Accounts[item.SourceId];
            var row = existing is null ? new CloudAccount { Id = accountIds[item.SourceId], Provider = item.Settings.Provider, CreatedAtUtc = now }
                : await db.CloudAccounts.SingleAsync(candidate => candidate.Id == existing, ct);
            item.Settings.Enabled = false;
            item.Settings.AutoSyncEnabled = false;
            CloudAccountStore.ApplyConfiguration(row, item.Settings, protection);
            if (existing is null && row.Provider == "Acme")
            {
                // 导入只恢复接入配置；已有 URL/私钥可复用，未注册配置仍须单独同意条款后注册。
                row.AcmeRegistrationStatus = !string.IsNullOrEmpty(item.Settings.AccessKeyId) && !string.IsNullOrEmpty(item.Settings.AccessKeySecret)
                    ? "Configured" : "New";
                row.AcmeRegisteredAtUtc = null;
            }
            row.AutoSyncNextRunAtUtc = null;
            row.UpdatedAtUtc = now;
            row.LastTestAtUtc = null; row.LastTestSuccess = null; row.LastTestCode = ""; row.LastTestMessage = "";
            if (existing is null) db.CloudAccounts.Add(row);
        }
        foreach (var item in package.DeploymentTargets)
        {
            var existing = plan.Targets[item.SourceId];
            var row = existing is null ? new DeploymentTarget { Id = targetIds[item.SourceId], CreatedAtUtc = now }
                : await db.DeploymentTargets.SingleAsync(candidate => candidate.Id == existing, ct);
            item.Settings.Enabled = false;
            item.Settings.ConfigRevision = null;
            item.Settings.Configuration.SourceCertificateId = "";
            var descriptor = executors.Resolve(item.Settings.ExecutorKey).Data?.Descriptor
                ?? throw new InvalidOperationException("配置执行器不可用。");
            DeploymentTargetService.ApplyConfiguration(row, item.Settings, descriptor,
                DeploymentTargetService.CredentialsFromInput(item.Settings), protection);
            row.ConfigRevision = existing is null ? 1 : row.ConfigRevision + 1;
            row.UpdatedAtUtc = now;
            row.LastTestAtUtc = null; row.LastTestSuccess = null; row.LastTestMessage = "配置已导入，请核对并重新测试连接。";
            if (existing is null) db.DeploymentTargets.Add(row);
        }
        foreach (var item in package.CertificateSchedules)
        {
            var existing = plan.Schedules[item.SourceId];
            var input = item.Settings;
            var row = existing is null ? new CertificateSchedule { Id = ids.NewId(), CreatedAtUtc = now, CreatedByUserId = userId }
                : await db.CertificateSchedules.SingleAsync(candidate => candidate.Id == existing, ct);
            row.Name = input.Name.Trim(); row.AccountId = accountIds[input.AccountId]; row.Domain = input.Domain; row.Alias = input.Alias;
            row.ValidationMode = input.ValidationMode; row.AutoCleanup = input.AutoCleanup; row.RevokeOldCertificates = input.RevokeOldCertificates;
            row.DnsZoneId = null;
            if (item.DnsAccountSourceId is not null)
            {
                var dnsAccountId = accountIds[item.DnsAccountSourceId];
                var matches = await db.Domains.AsNoTracking().Where(x => x.AccountId == dnsAccountId &&
                    x.Name == item.DnsZoneName && x.ZoneId == item.DnsProviderZoneId && x.Status != "NotPresent").Select(x => x.Id).ToListAsync(ct);
                // 空字符串表示尚未映射；启用入口必须要求重新同步、选择，不回落到另一个账号。
                row.DnsZoneId = matches.Count == 1 ? matches[0] : "";
            }
            row.TargetIdsJson = JsonSerializer.Serialize(input.TargetIds.Select(sourceId => targetIds[sourceId]).ToArray(), Json);
            row.IntervalValue = input.IntervalValue; row.IntervalUnit = input.IntervalUnit;
            row.FirstRunAtUtc = CertificateScheduleTiming.EnsureUtc(input.FirstRunAtUtc);
            row.NextRunAtUtc = CertificateScheduleTiming.NextAfter(row.FirstRunAtUtc, row.IntervalValue, row.IntervalUnit, now);
            row.Enabled = false; row.ConfigRevision = existing is null ? 1 : row.ConfigRevision + 1; row.UpdatedAtUtc = now;
            if (existing is null) db.CertificateSchedules.Add(row);
        }
        if (package.MailSettings is { } mail)
        {
            var row = await db.MailSettings.SingleOrDefaultAsync(ct);
            if (row is null) { row = new MailSettings(); db.MailSettings.Add(row); }
            mail.Enabled = false;
            MailService.ApplyConfiguration(row, mail,
                protection.CreateProtector(MailService.ConfigurationProtectionPurpose).Protect(mail.Password), now);
        }
        if (package.ExpiryReminderSettings is { } reminders)
        {
            var row = await db.ExpiryReminderSettings.SingleOrDefaultAsync(ct);
            if (row is null) { row = new ExpiryReminderSettings(); db.ExpiryReminderSettings.Add(row); }
            row.Enabled = false;
            row.DaysBeforeExpiry = reminders.DaysBeforeExpiry;
            row.RepeatIntervalDays = reminders.RepeatIntervalDays;
            row.RecipientsJson = JsonSerializer.Serialize(ExpiryReminderService.NormalizeRecipients(reminders.Recipients), Json);
            row.UpdatedAtUtc = now;
        }
        await ApplyMcpConfigurationAsync(package, plan, accountIds, targetIds, now, ct);
    }
}
