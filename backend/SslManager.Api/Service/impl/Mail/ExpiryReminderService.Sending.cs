using System.Data;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Models.Mail;

namespace SslManager.Api.Service.impl.Mail;

public sealed partial class ExpiryReminderService
{
    private async Task<int> ProcessBatchAsync(PendingBatch batch, CancellationToken ct)
    {
        try
        {
            var recorded = await db.MailMessages.AsNoTracking().SingleOrDefaultAsync(item => item.RequestId == batch.RequestId, ct);
            if (recorded is not null) return await ReconcileRecordedAsync(batch, recorded, ct);
            var payload = JsonSerializer.Deserialize<PendingPayload>(batch.PayloadJson, Json);
            if (payload?.Mail is null || payload.Alerts is null || payload.Mail.AlertIds is null || payload.Mail.RequestId != batch.RequestId
                || !payload.Mail.AlertIds.Order().SequenceEqual(batch.AlertIds.Order()) || payload.Alerts.Length != batch.AlertIds.Length)
            {
                await ReleaseBatchAsync(batch, "本轮邮件快照无法读取，已保留原请求键等待核对。", ct, TimeSpan.FromHours(1));
                return 0;
            }
            var state = await CheckBatchAsync(batch, payload, ct);
            if (state == "Changed") { await CancelUnsubmittedBatchAsync(batch, ct); return 0; }
            if (state == "SmtpUnavailable")
            {
                await ReleaseBatchAsync(batch, "等待 SMTP 配置启用后继续本轮提醒，尚未提交邮件。", ct); return 0;
            }
            var content = await templates.RenderAsync(payload.Alerts, payload.DaysBeforeExpiry, Utc(payload.GeneratedAtUtc), ct);
            payload.Mail.HtmlBody = content.HtmlBody;
            // MailService 在记账前和实际 SMTP 前再验证规则、活跃预警及证书有效期身份。
            var result = await mail.SendExpiryReminderAsync(payload.Mail, ct);
            recorded = await db.MailMessages.AsNoTracking().SingleOrDefaultAsync(item => item.RequestId == batch.RequestId, ct);
            if (recorded is not null) return await ReconcileRecordedAsync(batch, recorded, ct);
            if (await CheckBatchAsync(batch, payload, ct) == "Changed") await CancelUnsubmittedBatchAsync(batch, ct);
            else await ReleaseBatchAsync(batch, result.Success ? "邮件账本暂未核实，保留原请求键等待下次检查。"
                : "邮件尚未提交，保留原请求键，等待规则、SMTP 或模板恢复后再检查。", ct);
            return 0;
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception)
        {
            // 无论异常发生在记账前后，下次都先核对同一账本，不为本周期另造请求键。
            await ReleaseBatchAsync(batch, "本轮检查中断，保留原请求键等待核对；未自动重放未知发送。", CancellationToken.None);
            return 0;
        }
    }

    private async Task<string> CheckBatchAsync(PendingBatch batch, PendingPayload payload, CancellationToken ct)
    {
        var settings = await db.ExpiryReminderSettings.AsNoTracking().SingleOrDefaultAsync(ct);
        if (settings is null || !settings.Enabled || settings.UpdatedAtUtc != payload.Mail.SettingsUpdatedAtUtc) return "Changed";
        var group = await db.CertificateExpiryAlerts.AsNoTracking().Where(item => item.PendingRequestId == batch.RequestId
            && item.LeaseToken == batch.LeaseToken && item.Status == "Active").ToListAsync(ct);
        if (group.Count != batch.AlertIds.Length) return "Changed";
        var certificateIds = group.Select(item => item.CertificateId).ToArray();
        var certificates = await db.Certificates.AsNoTracking().Where(item => certificateIds.Contains(item.Id)).ToDictionaryAsync(item => item.Id, ct);
        var limit = Now.AddDays(settings.DaysBeforeExpiry);
        if (group.Any(alert => !certificates.TryGetValue(alert.CertificateId, out var certificate) || certificate.NotAfterUtc is null
            || certificate.NotAfterUtc.Value != alert.NotAfterUtc || certificate.NotAfterUtc.Value > limit || IsWithdrawn(certificate.Status))) return "Changed";
        var smtp = await db.MailSettings.AsNoTracking().SingleOrDefaultAsync(ct);
        return smtp is null || !smtp.Enabled || smtp.ProtectedPassword.Length == 0 ? "SmtpUnavailable" : "Ready";
    }

    private async Task<int> ReconcileRecordedAsync(PendingBatch batch, MailMessage recorded, CancellationToken ct)
    {
        if (recorded.CreatedByUserId != MailService.ExpiryReminderActorId)
        {
            await ReleaseBatchAsync(batch, "本轮请求键对应的邮件身份异常，保留现场等待核对。", ct, TimeSpan.FromHours(1)); return 0;
        }
        if (recorded.Status == "Sending")
        {
            await ReleaseBatchAsync(batch, "邮件正在提交或等待中断结果核对，本周期不会重复发送。", ct); return 0;
        }
        if (recorded.Status is not ("Accepted" or "Failed" or "Unknown"))
        {
            await ReleaseBatchAsync(batch, "邮件状态暂无法核实，保留原请求键等待核对。", ct); return 0;
        }
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            var settings = await db.ExpiryReminderSettings.AsNoTracking().SingleOrDefaultAsync(ct);
            var rows = await db.CertificateExpiryAlerts.Where(item => item.PendingRequestId == batch.RequestId && item.LeaseToken == batch.LeaseToken).ToListAsync(ct);
            var now = Now;
            var notSubmitted = recorded.Status == "Failed" && recorded.Code is "EXPIRY_ALERT_CHANGED"
                or "EXPIRY_REMINDER_CONFIGURATION_CHANGED" or "MAIL_CONFIGURATION_CHANGED" or "FORBIDDEN";
            var attemptAt = Utc(recorded.CreatedAtUtc);
            try
            {
                // 业务时钟生成的冻结时间作为下界，避免系统时间短暂回拨使同一周期立即再次到期。
                var generated = JsonSerializer.Deserialize<PendingPayload>(batch.PayloadJson, Json)?.GeneratedAtUtc;
                if (generated.HasValue && generated.Value > attemptAt) attemptAt = Utc(generated.Value);
            }
            catch (JsonException) { /* 账本已存在时即使模板快照损坏也完成原请求对账，不重发。 */ }
            foreach (var alert in rows)
            {
                // 发送前复核取消没有调用 SMTP，不能消耗 M=0 的首次机会，剩余 Active 项需重新组合。
                if (!notSubmitted) alert.LastAttemptAtUtc = attemptAt;
                alert.LastMailStatus = notSubmitted ? "NotSubmitted" : recorded.Status;
                alert.Message = notSubmitted ? "发送前规则或预警状态已变化，本轮未提交 SMTP，仍活跃的预警将重新排队。" : recorded.Status switch
                {
                    "Accepted" => "邮件服务器已受理；按重复间隔安排后续提醒，不代表收件人已经收到。",
                    "Unknown" => "本次邮件结果未知，需人工核验；本周期不重发，按重复间隔安排下一周期。",
                    _ => "本次邮件发送失败；本周期不重复提交，按重复间隔安排下一周期。"
                };
                if (!notSubmitted && alert.AttemptSequence < int.MaxValue) alert.AttemptSequence++;
                alert.NextReminderAtUtc = alert.Status == "Active" && settings is not null
                    ? NextAttempt(alert.LastAttemptAtUtc, settings.RepeatIntervalDays, now) : null;
                ClearPending(alert); alert.UpdatedAtUtc = now;
            }
            await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
            return notSubmitted ? 0 : rows.Count;
        }
        finally { db.ChangeTracker.Clear(); }
    }

    private async Task CancelUnsubmittedBatchAsync(PendingBatch batch, CancellationToken ct)
    {
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            // 若另一执行者刚写入账本，只保留现场等待核对，不能把同一轮重组为新请求。
            if (await db.MailMessages.AsNoTracking().AnyAsync(item => item.RequestId == batch.RequestId, ct)) return;
            var settings = await db.ExpiryReminderSettings.AsNoTracking().SingleOrDefaultAsync(ct);
            var rows = await db.CertificateExpiryAlerts.Where(item => item.PendingRequestId == batch.RequestId && item.LeaseToken == batch.LeaseToken).ToListAsync(ct);
            var now = Now;
            foreach (var alert in rows)
            {
                ClearPending(alert); alert.UpdatedAtUtc = now;
                alert.NextReminderAtUtc = alert.Status == "Active" && settings is not null
                    ? NextAttempt(alert.LastAttemptAtUtc, settings.RepeatIntervalDays, now) : null;
                if (alert.Status == "Active") alert.Message = "发送前规则或预警状态已变化，原邮件未提交，等待按当前状态重新检查。";
            }
            await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
        }
        finally { db.ChangeTracker.Clear(); }
    }

    private Task<int> ReleaseBatchAsync(PendingBatch batch, string message, CancellationToken ct, TimeSpan? delay = null)
    {
        var now = Now;
        return db.CertificateExpiryAlerts.Where(item => item.PendingRequestId == batch.RequestId && item.LeaseToken == batch.LeaseToken)
            .ExecuteUpdateAsync(update => update.SetProperty(item => item.LeaseUntilUtc, now.Add(delay ?? TimeSpan.FromMinutes(1)))
                .SetProperty(item => item.Message, message).SetProperty(item => item.UpdatedAtUtc, now), ct);
    }

    private static void ClearPending(CertificateExpiryAlert alert)
    {
        alert.PendingRequestId = ""; alert.PendingLeaderId = ""; alert.PendingPayloadJson = "";
        alert.LeaseToken = ""; alert.LeaseUntilUtc = null;
    }
}
