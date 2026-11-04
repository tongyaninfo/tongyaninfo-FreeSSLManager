using System.Data;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mail;

namespace SslManager.Api.Service.impl.Mail;

/// <summary>预警规则和每轮有效期状态持久化；数据库事务不跨越 SMTP 调用。</summary>
public sealed partial class ExpiryReminderService(AppDbContext db, IMailService mail,
    IExpiryReminderTemplateRenderer templates, IIdGenerator ids, TimeProvider timeProvider) : IExpiryReminderService
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private const int MaximumBatchSize = 20;
    private DateTime Now => timeProvider.GetUtcNow().UtcDateTime;

    public async Task<ApiResult<ExpiryReminderSettingsSummary>> GetSettingsAsync(CancellationToken ct)
    {
        var settings = await db.ExpiryReminderSettings.AsNoTracking().SingleOrDefaultAsync(ct);
        var smtp = await db.MailSettings.AsNoTracking().SingleOrDefaultAsync(ct);
        return ApiResult<ExpiryReminderSettingsSummary>.Ok(ToSummary(settings, smtp));
    }

    public async Task<ApiResult<ExpiryReminderSettingsSummary>> SaveSettingsAsync(ExpiryReminderSettingsInput input, CancellationToken ct)
    {
        var error = Validate(input);
        if (error is not null) return ApiResult<ExpiryReminderSettingsSummary>.Fail("VALIDATION", error);
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            var row = await db.ExpiryReminderSettings.SingleOrDefaultAsync(ct);
            var now = Now;
            if (row is null) { row = new(); db.ExpiryReminderSettings.Add(row); }
            else if (now <= row.UpdatedAtUtc) now = row.UpdatedAtUtc.AddTicks(1);
            row.Enabled = input.Enabled; row.DaysBeforeExpiry = input.DaysBeforeExpiry; row.RepeatIntervalDays = input.RepeatIntervalDays;
            row.RecipientsJson = JsonSerializer.Serialize(NormalizeRecipients(input.Recipients), Json); row.UpdatedAtUtc = now;
            // 改规则仅重新安排尚未发起的轮次；已有 PendingRequestId 必须先核对账本，不能丢弃发送身份。
            var active = await db.CertificateExpiryAlerts.Where(item => item.Status == "Active" && item.PendingRequestId == "").ToListAsync(ct);
            foreach (var alert in active)
            {
                alert.NextReminderAtUtc = NextAttempt(alert.LastAttemptAtUtc, input.RepeatIntervalDays, now);
                alert.UpdatedAtUtc = now;
            }
            await db.SaveChangesAsync(ct);
            await transaction.CommitAsync(ct);
            var smtp = await db.MailSettings.AsNoTracking().SingleOrDefaultAsync(ct);
            return ApiResult<ExpiryReminderSettingsSummary>.Ok(ToSummary(row, smtp), "到期提醒规则已保存，后台按规则检查，本次未直接发送邮件。");
        }
        catch (DbUpdateException)
        { db.ChangeTracker.Clear(); return ApiResult<ExpiryReminderSettingsSummary>.Fail("CONFLICT", "提醒规则或预警状态已变化，请刷新后重试。"); }
    }

    public async Task<ApiResult<PageResult<ExpiryAlertView>>> ListAsync(int page, int pageSize, string? status, CancellationToken ct)
    {
        if (page < 1 || pageSize is < 1 or > 100 || !string.IsNullOrEmpty(status) && status is not ("Active" or "Ignored" or "Resolved"))
            return ApiResult<PageResult<ExpiryAlertView>>.Fail("VALIDATION", "页码、每页数量或预警状态不正确。");
        var query = db.CertificateExpiryAlerts.AsNoTracking();
        if (!string.IsNullOrEmpty(status)) query = query.Where(item => item.Status == status);
        var total = await query.CountAsync(ct);
        var offset = (long)(page - 1) * pageSize;
        var rows = offset >= total ? [] : await query.OrderBy(item => item.NotAfterUtc).ThenBy(item => item.Id)
            .Skip((int)offset).Take(pageSize).ToListAsync(ct);
        return ApiResult<PageResult<ExpiryAlertView>>.Ok(new(rows.Select(ToView).ToArray(), total, page, pageSize));
    }

    public async Task<ApiResult<ExpiryAlertView>> IgnoreAsync(string id, CancellationToken ct)
    {
        var row = await db.CertificateExpiryAlerts.SingleOrDefaultAsync(item => item.Id == id, ct);
        if (row is null) return ApiResult<ExpiryAlertView>.Fail("NOT_FOUND", "预警记录不存在。");
        if (row.Status == "Ignored") return ApiResult<ExpiryAlertView>.Ok(ToView(row));
        if (row.Status != "Active") return ApiResult<ExpiryAlertView>.Fail("CONFLICT", "仅活跃预警可以忽略。");
        row.Status = "Ignored"; row.NextReminderAtUtc = null; row.UpdatedAtUtc = Now;
        row.Message = "管理员已忽略本证书当前有效期的后续提醒。";
        // 不清除 Pending：正在发送的请求仍需由后台按原请求键核对一次，忽略不会导致重发。
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateConcurrencyException)
        { db.ChangeTracker.Clear(); return ApiResult<ExpiryAlertView>.Fail("CONFLICT", "预警状态已变化，请刷新后重试。"); }
        return ApiResult<ExpiryAlertView>.Ok(ToView(row), "已忽略本轮预警，到期时间变化后可产生新一轮预警。");
    }

    /// <summary>配置迁移和日常保存共用校验；停用规则允许收件人为空。</summary>
    internal static string? Validate(ExpiryReminderSettingsInput input)
    {
        if (input.DaysBeforeExpiry is < 1 or > 365) return "提前预警天数须为 1～365。";
        if (input.RepeatIntervalDays is < 0 or > 365) return "重复间隔须为 0～365 天，0 表示仅首次提醒。";
        if (input.Recipients is null || input.Recipients.Length > 50 || input.Recipients.Any(value => !MailService.ValidAddress(value)))
            return "请填写最多 50 个有效收件邮箱。";
        if (input.Enabled && input.Recipients.Length == 0) return "启用到期提醒时至少填写一个收件邮箱。";
        return null;
    }

    internal static string[] NormalizeRecipients(IEnumerable<string> recipients) => recipients.Select(value => value.Trim())
        .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(value => value, StringComparer.OrdinalIgnoreCase).ToArray();
    private static DateTime Utc(DateTime value) => DateTime.SpecifyKind(value, DateTimeKind.Utc);
    private static DateTime? Utc(DateTime? value) => value.HasValue ? Utc(value.Value) : null;
    private static DateTime? NextAttempt(DateTime? lastAttempt, int repeatDays, DateTime now) => lastAttempt is null
        ? now : repeatDays == 0 ? null : Utc(lastAttempt.Value).AddDays(repeatDays);
    private static ExpiryAlertView ToView(CertificateExpiryAlert row) => new(row.Id, row.CertificateId, row.AccountName,
        row.Domain, row.Alias, Utc(row.NotAfterUtc), row.Status, Utc(row.FirstDetectedAtUtc), Utc(row.LastAttemptAtUtc),
        Utc(row.NextReminderAtUtc), row.LastMailStatus, row.Message);
    private static ExpiryReminderSettingsSummary ToSummary(ExpiryReminderSettings? settings, MailSettings? smtp) => new(
        settings is not null, settings?.Enabled ?? false, settings?.DaysBeforeExpiry ?? 30, settings?.RepeatIntervalDays ?? 1,
        settings is null ? [] : JsonSerializer.Deserialize<string[]>(settings.RecipientsJson, Json) ?? [],
        smtp is not null && !string.IsNullOrEmpty(smtp.ProtectedPassword), smtp?.Enabled ?? false, Utc(settings?.UpdatedAtUtc));
    private static bool IsWithdrawn(string status) => status is "Revoked" or "Cancelled" or "Deleted" or "NotPresent" or "Refunded" or "Removed";
}
