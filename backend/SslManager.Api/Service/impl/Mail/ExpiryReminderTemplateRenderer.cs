using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using SslManager.Api.Models.Mail;

namespace SslManager.Api.Service.impl.Mail;

/// <summary>只读取随程序发布的固定模板，不访问外部图片、脚本或网络资源。</summary>
public sealed class ExpiryReminderTemplateRenderer : IExpiryReminderTemplateRenderer
{
    public async Task<ExpiryReminderContent> RenderAsync(IReadOnlyList<ExpiryAlertView> alerts, int daysBeforeExpiry,
        DateTime generatedAtUtc, CancellationToken ct)
    {
        if (alerts is null || alerts.Count is < 1 or > 100 || daysBeforeExpiry is < 1 or > 365)
            throw new InvalidOperationException("EXPIRY_REMINDER_TEMPLATE_INVALID：提醒条数或预警阈值无效。");
        var templatePath = Path.Combine(AppContext.BaseDirectory, "Resources", "Mail", "CertificateExpiryWarning.html");
        string template;
        try { template = await File.ReadAllTextAsync(templatePath, Encoding.UTF8, ct); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        { throw new InvalidOperationException("EXPIRY_REMINDER_TEMPLATE_UNAVAILABLE：证书到期邮件模板无法读取。", exception); }

        var now = DateTime.SpecifyKind(generatedAtUtc, DateTimeKind.Utc);
        var subject = $"证书到期预警：{alerts.Count} 项证书需要检查";
        var rows = new StringBuilder();
        var text = new StringBuilder().AppendLine(subject)
            .AppendLine($"预警阈值：到期前 {daysBeforeExpiry} 天。")
            .AppendLine($"生成时间（UTC）：{FormatTime(now)}").AppendLine();
        foreach (var alert in alerts)
        {
            ct.ThrowIfCancellationRequested();
            var remaining = Remaining(alert.NotAfterUtc, now);
            rows.Append("<tr>");
            foreach (var value in new[] { alert.Domain, alert.AccountName, alert.Alias, FormatTime(alert.NotAfterUtc), remaining })
                rows.Append("<td style=\"padding:10px;border:1px solid #dce3ed;word-break:break-word;\">")
                    .Append(Encode(string.IsNullOrEmpty(value) ? "—" : value)).Append("</td>");
            rows.Append("</tr>");
            text.AppendLine($"域名：{alert.Domain}")
                .AppendLine($"云账号：{alert.AccountName}；证书别名：{alert.Alias}")
                .AppendLine($"到期时间（UTC）：{FormatTime(alert.NotAfterUtc)}；{remaining}").AppendLine();
        }
        text.AppendLine("最近检查说明：本邮件反映生成时间的最近一次本地证书记录检查，云端同步可能存在延迟，请在管理平台核验最新到期时间。")
            .AppendLine("已续签或无需处理的提醒可在平台中解除或忽略。邮件服务器受理不代表收件人已经收到。");
        var bindings = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["{{Title}}"] = Encode(subject),
            ["{{AlertCount}}"] = Encode(alerts.Count.ToString(CultureInfo.InvariantCulture)),
            ["{{DaysBeforeExpiry}}"] = Encode(daysBeforeExpiry.ToString(CultureInfo.InvariantCulture)),
            ["{{GeneratedAtUtc}}"] = Encode(FormatTime(now)),
            // 每个单元格的动态值均已转义，只有本地固定的表格标记不转义。
            ["{{AlertRows}}"] = rows.ToString()
        };
        ValidateTemplate(template, bindings.Keys);
        foreach (var (key, value) in bindings) template = template.Replace(key, value, StringComparison.Ordinal);
        var plain = text.ToString();
        if (template.Length > 100000 || plain.Length > 100000)
            throw new InvalidOperationException("EXPIRY_REMINDER_TEMPLATE_INVALID：提醒正文过长，请减少每批证书数量。");
        return new(subject, plain, template);
    }

    private static void ValidateTemplate(string template, IEnumerable<string> placeholders)
    {
        if (template.Length > 100000 || !template.Contains("<!doctype html>", StringComparison.OrdinalIgnoreCase)
            || !template.Contains("</html>", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("EXPIRY_REMINDER_TEMPLATE_INVALID：邮件模板缺少完整 HTML 文档。");
        var remainder = template;
        foreach (var placeholder in placeholders)
        {
            if (!template.Contains(placeholder, StringComparison.Ordinal))
                throw new InvalidOperationException("EXPIRY_REMINDER_TEMPLATE_INVALID：邮件模板缺少必要占位符。");
            remainder = remainder.Replace(placeholder, "", StringComparison.Ordinal);
        }
        if (remainder.Contains("{{", StringComparison.Ordinal) || remainder.Contains("}}", StringComparison.Ordinal))
            throw new InvalidOperationException("EXPIRY_REMINDER_TEMPLATE_INVALID：邮件模板包含无法识别的占位符。");
        if (Regex.IsMatch(template, @"<\s*(?:script|img|iframe|object|link)\b|\son\w+\s*=|javascript\s*:", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            throw new InvalidOperationException("EXPIRY_REMINDER_TEMPLATE_INVALID：邮件模板不能包含脚本或外部资源。");
    }

    private static string Encode(string value) => HtmlEncoder.Default.Encode(value);
    private static string FormatTime(DateTime value) => DateTime.SpecifyKind(value, DateTimeKind.Utc).ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
    private static string Remaining(DateTime expiry, DateTime now) => expiry <= now
        ? $"已过期 {Math.Max(1, (int)Math.Ceiling((now - expiry).TotalDays))} 天"
        : $"剩余 {(int)Math.Ceiling((expiry - now).TotalDays)} 天";
}
