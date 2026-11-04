using System.Data;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Models;
using SslManager.Api.Models.Mail;

namespace SslManager.Api.Service.impl.Mail;

public sealed partial class ExpiryReminderService
{
    public async Task<int> ProcessAsync(CancellationToken ct)
    {
        // 先核对旧发送账本，Sending 超时仅转 Unknown，绝不因此生成另一个本周期请求。
        await mail.RecoverInterruptedAsync(ct);
        await ReconcileAlertsAsync(ct);
        var batch = await PrepareBatchAsync(ct);
        return batch is null ? 0 : await ProcessBatchAsync(batch, ct);
    }

    private async Task ReconcileAlertsAsync(CancellationToken ct)
    {
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            var settings = await db.ExpiryReminderSettings.AsNoTracking().SingleOrDefaultAsync(ct);
            if (settings is null) return;
            var now = Now;
            var limit = now.AddDays(settings.DaysBeforeExpiry);
            var candidates = settings.Enabled ? await db.Certificates.AsNoTracking().Where(item => item.Status == "Issued"
                && item.NotAfterUtc != null && item.NotAfterUtc > now && item.NotAfterUtc <= limit).ToListAsync(ct) : [];
            var candidateIds = candidates.Select(item => item.Id).ToArray();
            var activeCertificateIds = await db.CertificateExpiryAlerts.AsNoTracking().Where(item => item.Status == "Active")
                .Select(item => item.CertificateId).Distinct().ToArrayAsync(ct);
            var alerts = await db.CertificateExpiryAlerts.Where(item => activeCertificateIds.Contains(item.CertificateId)
                || candidateIds.Contains(item.CertificateId)).ToListAsync(ct);
            var certificateIds = alerts.Select(item => item.CertificateId).Concat(candidateIds).Distinct().ToArray();
            var certificates = await db.Certificates.AsNoTracking().Where(item => certificateIds.Contains(item.Id)).ToDictionaryAsync(item => item.Id, ct);
            var accountIds = certificates.Values.Select(item => item.AccountId).Distinct().ToArray();
            var accounts = await db.CloudAccounts.AsNoTracking().Where(item => accountIds.Contains(item.Id)).ToDictionaryAsync(item => item.Id, item => item.Name, ct);
            foreach (var alert in alerts.Where(item => item.Status == "Active").ToArray())
            {
                if (!certificates.TryGetValue(alert.CertificateId, out var certificate) || certificate.NotAfterUtc is null
                    || certificate.NotAfterUtc.Value != alert.NotAfterUtc || IsWithdrawn(certificate.Status) || certificate.NotAfterUtc.Value > limit)
                {
                    // 已有活跃预警的有效期变更仍处于范围内时续接新身份，包含仍已过期的情况。
                    // 这不是首次历史过期补发：只有本轮原先 Active 的同一证书才具备续接资格。
                    if (certificate is not null && certificate.NotAfterUtc.HasValue && certificate.NotAfterUtc.Value != alert.NotAfterUtc
                        && certificate.NotAfterUtc.Value <= limit && !IsWithdrawn(certificate.Status)
                        && candidates.All(item => item.Id != certificate.Id)) candidates.Add(certificate);
                    alert.Status = "Resolved"; alert.NextReminderAtUtc = null; alert.UpdatedAtUtc = now;
                    alert.Message = "本证书有效期已变化、已退出预警范围或已撤销/移除，本轮预警已解除。";
                    continue;
                }
                UpdateIdentitySnapshot(alert, certificate, accounts);
            }
            var identities = alerts.ToDictionary(item => (item.CertificateId, item.NotAfterUtc.Ticks));
            foreach (var certificate in candidates)
            {
                var identity = (certificate.Id, certificate.NotAfterUtc!.Value.Ticks);
                if (identities.TryGetValue(identity, out var existing))
                {
                    // 忽略对该证书及有效期永久有效；已解除记录再次进入范围时沿用原尝试次数。
                    if (existing.Status == "Resolved" && existing.PendingRequestId.Length == 0)
                    {
                        existing.Status = "Active"; existing.NextReminderAtUtc = NextAttempt(existing.LastAttemptAtUtc, settings.RepeatIntervalDays, now);
                        existing.Message = "本证书再次进入预警范围，继续沿原有效期状态检查。"; existing.UpdatedAtUtc = now;
                        UpdateIdentitySnapshot(existing, certificate, accounts);
                    }
                    continue;
                }
                var alert = new CertificateExpiryAlert
                {
                    Id = ids.NewId(), CertificateId = certificate.Id, NotAfterUtc = Utc(certificate.NotAfterUtc.Value),
                    FirstDetectedAtUtc = now, NextReminderAtUtc = now, UpdatedAtUtc = now,
                    Message = "发现即将到期证书，等待后台提醒。"
                };
                UpdateIdentitySnapshot(alert, certificate, accounts);
                db.CertificateExpiryAlerts.Add(alert); identities.Add(identity, alert);
            }
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
        }
        finally { db.ChangeTracker.Clear(); }
    }

    private static void UpdateIdentitySnapshot(CertificateExpiryAlert alert, ManagedCertificate certificate, IReadOnlyDictionary<string, string> accounts)
    {
        alert.AccountName = accounts.TryGetValue(certificate.AccountId, out var name) ? name : "已移除账号";
        alert.Domain = CertificateManagementService.PrimaryDomain(certificate.Domain);
        alert.Alias = certificate.Alias;
    }

    private async Task<PendingBatch?> PrepareBatchAsync(CancellationToken ct)
    {
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            var now = Now;
            // Pending 不限定 Active：忽略/解除后仍必须核对原账本，不能丢失已开始的发送。
            var leader = await db.CertificateExpiryAlerts.AsNoTracking().Where(item => item.PendingRequestId != ""
                && (item.PendingLeaderId == item.Id || item.PendingLeaderId == "") && (item.LeaseUntilUtc == null || item.LeaseUntilUtc <= now))
                .OrderBy(item => item.FirstDetectedAtUtc).ThenBy(item => item.Id).FirstOrDefaultAsync(ct);
            if (leader is not null)
            {
                var group = await db.CertificateExpiryAlerts.Where(item => item.PendingRequestId == leader.PendingRequestId).OrderBy(item => item.Id).ToListAsync(ct);
                if (group.Any(item => item.LeaseUntilUtc > now)) return null;
                var lease = ids.NewId();
                foreach (var alert in group) { alert.LeaseToken = lease; alert.LeaseUntilUtc = now.AddMinutes(3); alert.UpdatedAtUtc = now; }
                await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
                return new(leader.PendingRequestId, lease, leader.PendingPayloadJson, group.Select(item => item.Id).ToArray());
            }
            var settings = await db.ExpiryReminderSettings.AsNoTracking().SingleOrDefaultAsync(ct);
            var smtp = await db.MailSettings.AsNoTracking().SingleOrDefaultAsync(ct);
            // SMTP 未就绪只保留到期预警，不创建邮件账本或消耗提醒周期。
            if (settings is null || !settings.Enabled || smtp is null || !smtp.Enabled || smtp.ProtectedPassword.Length == 0) return null;
            var recipients = JsonSerializer.Deserialize<string[]>(settings.RecipientsJson, Json) ?? [];
            if (Validate(new() { Enabled = true, DaysBeforeExpiry = settings.DaysBeforeExpiry,
                RepeatIntervalDays = settings.RepeatIntervalDays, Recipients = recipients }) is not null) return null;
            var due = await db.CertificateExpiryAlerts.Where(item => item.Status == "Active" && item.PendingRequestId == ""
                && item.NextReminderAtUtc != null && item.NextReminderAtUtc <= now).OrderBy(item => item.NotAfterUtc).ThenBy(item => item.Id)
                .Take(MaximumBatchSize).ToListAsync(ct);
            if (due.Count == 0) return null;
            var views = due.Select(ToView).ToArray();
            var content = await templates.RenderAsync(views, settings.DaysBeforeExpiry, now, ct);
            // 请求键只通过统一入口生成一次并持久化；续租、重启和核对都沿用相同键。
            var generatedRequestId = ids.NewId();
            if (!Guid.TryParse(generatedRequestId, out var requestGuid)) throw new InvalidOperationException("提醒请求标识必须可转换为 GUID。");
            var requestId = requestGuid.ToString("D");
            var leaseToken = ids.NewId();
            var payload = new PendingPayload
            {
                Mail = new() { RequestId = requestId, To = recipients, Subject = content.Subject, Body = content.TextBody,
                    SettingsUpdatedAtUtc = Utc(settings.UpdatedAtUtc), AlertIds = due.Select(item => item.Id).ToArray() },
                Alerts = views, DaysBeforeExpiry = settings.DaysBeforeExpiry, GeneratedAtUtc = now
            };
            var payloadJson = JsonSerializer.Serialize(payload, Json);
            var leaderId = due[0].Id;
            foreach (var alert in due)
            {
                alert.PendingRequestId = requestId; alert.PendingLeaderId = leaderId;
                alert.PendingPayloadJson = alert.Id == leaderId ? payloadJson : "";
                alert.LeaseToken = leaseToken; alert.LeaseUntilUtc = now.AddMinutes(3); alert.UpdatedAtUtc = now;
                alert.Message = "本轮预警已排队，等待邮件服务器提交。";
            }
            await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
            return new(requestId, leaseToken, payloadJson, due.Select(item => item.Id).ToArray());
        }
        finally { db.ChangeTracker.Clear(); }
    }

    private sealed class PendingPayload
    {
        public ExpiryReminderMailInput Mail { get; set; } = new();
        public ExpiryAlertView[] Alerts { get; set; } = [];
        public int DaysBeforeExpiry { get; set; }
        public DateTime GeneratedAtUtc { get; set; }
        public override string ToString() => "PendingPayload { 邮件快照已隐藏 }";
    }
    private sealed record PendingBatch(string RequestId, string LeaseToken, string PayloadJson, string[] AlertIds)
    {
        public override string ToString() => "PendingBatch { 邮件快照已隐藏 }";
    }
}
