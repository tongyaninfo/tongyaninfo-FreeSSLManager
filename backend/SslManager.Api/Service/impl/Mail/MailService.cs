using MailAddress = System.Net.Mail.MailAddress;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models.Mail;

namespace SslManager.Api.Service.impl.Mail;

/// <summary>发送前记账，网络结果单独落库；两张表完成单邮箱配置和本系统发件查询。</summary>
public sealed partial class MailService(AppDbContext db, IDataProtectionProvider protection, IIdGenerator ids,
    IMailTransport transport, IHostApplicationLifetime lifetime) : IMailService
{
    private static readonly SemaphoreSlim SettingsGate = new(1, 1);
    // 配置迁移与日常保存共用保护用途，保持已有密文可解密。
    internal const string ConfigurationProtectionPurpose = "SslManager.Mail.Settings.v1";
    private IDataProtector Protector => protection.CreateProtector(ConfigurationProtectionPurpose);

    public async Task<ApiResult<MailSettingsSummary>> GetSettingsAsync(CancellationToken ct)
    {
        var settings = await db.MailSettings.AsNoTracking().SingleOrDefaultAsync(ct);
        return ApiResult<MailSettingsSummary>.Ok(settings is null
            ? new(false, true, "", 465, "SslOnConnect", "", "", "", false, null)
            : ToSummary(settings));
    }

    public async Task<ApiResult<MailSettingsSummary>> SaveSettingsAsync(MailSettingsInput input, CancellationToken ct)
    {
        var error = ValidateSettings(input);
        if (error is not null) return ApiResult<MailSettingsSummary>.Fail("VALIDATION", error);
        await SettingsGate.WaitAsync(ct);
        try
        {
            var row = await db.MailSettings.SingleOrDefaultAsync(ct);
            if (row is null && string.IsNullOrWhiteSpace(input.Password))
                return ApiResult<MailSettingsSummary>.Fail("VALIDATION", "首次配置请填写邮箱授权码或密码。");
            var protectedPassword = row?.ProtectedPassword ?? "";
            try
            {
                if (!string.IsNullOrEmpty(input.Password)) protectedPassword = Protector.Protect(input.Password);
            }
            catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
            { return ApiResult<MailSettingsSummary>.Fail("MAIL_CONFIGURATION_UNAVAILABLE", "邮箱密码无法安全保存，请检查原加密密钥及数据目录权限。"); }
            if (protectedPassword.Length == 0)
                return ApiResult<MailSettingsSummary>.Fail("VALIDATION", "请填写邮箱授权码或密码。");
            if (row is null) { row = new MailSettings(); db.MailSettings.Add(row); }
            ApplyConfiguration(row, input, protectedPassword, DateTime.UtcNow);
            await db.SaveChangesAsync(ct);
            return ApiResult<MailSettingsSummary>.Ok(ToSummary(row), "邮箱配置已保存，密码留空时保留原值。");
        }
        finally { SettingsGate.Release(); }
    }

    public async Task<ApiResult<bool>> ProbeAsync(CancellationToken ct)
    {
        var settings = await ReadEndpointAsync(ct);
        if (!settings.Success || settings.Data is null) return ApiResult<bool>.Fail(settings.Code, settings.Message);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct, lifetime.ApplicationStopping);
        timeout.CancelAfter(TimeSpan.FromSeconds(45));
        try
        {
            var result = await transport.ProbeAsync(settings.Data.Endpoint, timeout.Token);
            return result.Success ? ApiResult<bool>.Ok(true, "SMTP 连接和认证成功，可以发送邮件。")
                : ApiResult<bool>.Fail(SafeCode(result.Code), SafeFailure(result.Code));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception) { return ApiResult<bool>.Fail("MAIL_CONNECTION_FAILED", "SMTP 检测未完成，请检查服务器、端口、加密方式和授权码。"); }
    }

    public async Task<ApiResult<MailMessageDetail>> SendAsync(MailSendInput input, string userId, CancellationToken ct)
    {
        var error = ValidateMessage(input);
        if (error is not null) return ApiResult<MailMessageDetail>.Fail("VALIDATION", error);
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == userId && x.Enabled && x.Role == "admin", ct);
        if (user is null) return ApiResult<MailMessageDetail>.Fail("FORBIDDEN", "当前用户无邮件发送权限。");
        return await SendRecordedAsync(input, userId, user.DisplayName, null, false,
            async token => await db.Users.AsNoTracking().AnyAsync(x => x.Id == userId && x.Enabled && x.Role == "admin", token)
                ? null : "FORBIDDEN", ct);
    }

    /// <summary>人工与系统共用记账、唯一请求键、发送前复核和未知结果恢复，绝不因重试再次提交 SMTP。</summary>
    private async Task<ApiResult<MailMessageDetail>> SendRecordedAsync(MailSendInput input, string actorId, string actorName,
        string? htmlBody, bool systemRequest, Func<CancellationToken, Task<string?>> authorize, CancellationToken ct)
    {
        var requestId = Guid.Parse(input.RequestId).ToString("D");
        var recipients = input.To.Select(value => value.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        var subject = input.Subject.Trim();
        await RecoverInterruptedAsync(ct);
        var existing = await db.MailMessages.AsNoTracking().SingleOrDefaultAsync(x => x.RequestId == requestId, ct);
        if (existing is not null) return RecordedResult(existing, actorId, recipients, subject, input.Body, systemRequest);
        var authorizationError = await authorize(ct);
        if (authorizationError is not null)
            return ApiResult<MailMessageDetail>.Fail(SafeCode(authorizationError), SafeFailure(authorizationError));
        var configuration = await ReadEndpointAsync(ct);
        if (!configuration.Success || configuration.Data is null)
            return ApiResult<MailMessageDetail>.Fail(configuration.Code, configuration.Message);
        var settings = configuration.Data.Settings;
        var row = new MailMessage
        {
            Id = ids.NewId(), RequestId = requestId, ToJson = JsonSerializer.Serialize(recipients),
            FromAddress = settings.FromAddress, Subject = subject, Body = input.Body,
            Status = "Sending", Code = "MAIL_SENDING", Message = "正在提交邮件服务器，请勿重复发送。",
            CreatedByUserId = actorId, CreatedByName = actorName, CreatedAtUtc = DateTime.UtcNow
        };
        row.MessageId = row.Id + "@ssl-manager.local";
        db.MailMessages.Add(row);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateException ex) when (ex.InnerException is SqliteException { SqliteErrorCode: 19 })
        {
            // 唯一索引是跨请求并发边界，竞争失败者只读取已存在的意图。
            db.Entry(row).State = EntityState.Detached;
            existing = await db.MailMessages.AsNoTracking().SingleOrDefaultAsync(x => x.RequestId == requestId, ct);
            if (existing is null) throw;
            return RecordedResult(existing, actorId, recipients, subject, input.Body, systemRequest);
        }

        // 记账后独立于浏览器连接完成发送及结果保存，关闭页面不能触发第二次 SMTP 提交。
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(lifetime.ApplicationStopping);
        timeout.CancelAfter(TimeSpan.FromSeconds(45));
        MailTransportResult result;
        try
        {
            authorizationError = await authorize(timeout.Token);
            var unchanged = await db.MailSettings.AsNoTracking().AnyAsync(x => x.Enabled && x.UpdatedAtUtc == settings.UpdatedAtUtc, timeout.Token);
            result = authorizationError is not null ? new("Failed", authorizationError, "")
                : !unchanged ? new("Failed", "MAIL_CONFIGURATION_CHANGED", "")
                : await transport.SendAsync(configuration.Data.Endpoint,
                    new(row.MessageId, row.FromAddress, settings.FromName, recipients, row.Subject, row.Body, row.CreatedAtUtc, htmlBody), timeout.Token);
        }
        catch (Exception)
        {
            // 未获得可靠协议结论时保守标为未知，绝不依据异常文字自动重发。
            result = new("Unknown", "MAIL_RESULT_UNKNOWN", "");
        }
        row.Status = result.Status is "Accepted" or "Failed" ? result.Status : "Unknown";
        row.Code = row.Status == "Accepted" ? "MAIL_ACCEPTED" : row.Status == "Unknown" ? "MAIL_RESULT_UNKNOWN" : SafeCode(result.Code);
        row.Message = row.Status == "Accepted" ? "邮件服务器已受理，不代表收件人已收到。"
            : row.Status == "Unknown" ? "发送结果未知，请先向收件人或邮件服务器核验，勿重复发送。" : SafeFailure(result.Code);
        row.CompletedAtUtc = DateTime.UtcNow;
        using var saveTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await db.SaveChangesAsync(saveTimeout.Token);
        return ApiResult<MailMessageDetail>.Ok(ToDetail(row), row.Message);
    }

    public async Task<ApiResult<PageResult<MailMessageSummary>>> ListAsync(int page, int pageSize, string? search, string? status, CancellationToken ct)
    {
        if (page < 1 || pageSize is < 1 or > 100 || search?.Length > 300)
            return ApiResult<PageResult<MailMessageSummary>>.Fail("VALIDATION", "页码须大于 0，每页条数为 1～100，搜索词最多 300 字。");
        if (!string.IsNullOrEmpty(status) && status is not ("Sending" or "Accepted" or "Failed" or "Unknown"))
            return ApiResult<PageResult<MailMessageSummary>>.Fail("VALIDATION", "邮件状态筛选无效。");
        await RecoverInterruptedAsync(ct);
        var query = db.MailMessages.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var keyword = search.Trim();
            query = query.Where(x => x.Subject.Contains(keyword) || x.ToJson.Contains(keyword) || x.FromAddress.Contains(keyword));
        }
        if (!string.IsNullOrEmpty(status)) query = query.Where(x => x.Status == status);
        var total = await query.CountAsync(ct);
        var offset = (long)(page - 1) * pageSize;
        // 列表不查询正文；正文只在管理员明确打开详情时返回。
        var rows = offset >= total ? [] : await query.OrderByDescending(x => x.CreatedAtUtc).ThenByDescending(x => x.Id)
            .Skip((int)offset).Take(pageSize).Select(x => new MailMessage { Id = x.Id, ToJson = x.ToJson,
                FromAddress = x.FromAddress, Subject = x.Subject, Status = x.Status, Code = x.Code, Message = x.Message,
                CreatedByUserId = x.CreatedByUserId, CreatedByName = x.CreatedByName, CreatedAtUtc = x.CreatedAtUtc,
                CompletedAtUtc = x.CompletedAtUtc }).ToListAsync(ct);
        return ApiResult<PageResult<MailMessageSummary>>.Ok(new(rows.Select(ToSummary).ToArray(), total, page, pageSize));
    }

    public async Task<ApiResult<MailMessageDetail>> GetAsync(string id, CancellationToken ct)
    {
        await RecoverInterruptedAsync(ct);
        var row = await db.MailMessages.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        return row is null ? ApiResult<MailMessageDetail>.Fail("NOT_FOUND", "发件记录不存在。")
            : ApiResult<MailMessageDetail>.Ok(ToDetail(row));
    }

    /// <summary>协议调用最多 45 秒；超过两分钟仍在发送的记录仅转未知，不重新提交。</summary>
    public Task<int> RecoverInterruptedAsync(CancellationToken ct)
    {
        var cutoff = DateTime.UtcNow.AddMinutes(-2);
        var now = DateTime.UtcNow;
        return db.MailMessages.Where(x => x.Status == "Sending" && x.CreatedAtUtc <= cutoff).ExecuteUpdateAsync(setters => setters
            .SetProperty(x => x.Status, "Unknown").SetProperty(x => x.Code, "MAIL_RESULT_UNKNOWN")
            .SetProperty(x => x.Message, "发送过程已中断，结果未知，请核验后再决定是否重新发送。")
            .SetProperty(x => x.CompletedAtUtc, now), ct);
    }

    private async Task<ApiResult<SettingsAndEndpoint>> ReadEndpointAsync(CancellationToken ct)
    {
        var row = await db.MailSettings.AsNoTracking().SingleOrDefaultAsync(ct);
        if (row is null || row.ProtectedPassword.Length == 0)
            return ApiResult<SettingsAndEndpoint>.Fail("CONFIGURATION_MISSING", "请先保存 SMTP 服务器、发件邮箱和授权码。");
        if (!row.Enabled) return ApiResult<SettingsAndEndpoint>.Fail("MAIL_DISABLED", "邮件发送已停用，请在邮箱设置中启用。");
        try
        {
            return ApiResult<SettingsAndEndpoint>.Ok(new(row,
                new(row.Host, row.Port, row.Security, row.Username, Protector.Unprotect(row.ProtectedPassword))));
        }
        catch (CryptographicException)
        { return ApiResult<SettingsAndEndpoint>.Fail("MAIL_CONFIGURATION_UNAVAILABLE", "邮箱密码无法解密，请恢复原加密密钥或重新保存邮箱授权码。"); }
    }

    /// <summary>普通保存与配置导入复用字段规范化；密码由调用方按原目的串保护。</summary>
    internal static void ApplyConfiguration(MailSettings row, MailSettingsInput input, string protectedPassword, DateTime now)
    {
        row.Host = input.Host.Trim().TrimEnd('.'); row.Port = input.Port; row.Security = input.Security;
        row.FromAddress = input.FromAddress.Trim();
        row.Username = string.IsNullOrWhiteSpace(input.Username) ? row.FromAddress : input.Username.Trim();
        row.FromName = (input.FromName ?? "").Trim(); row.Enabled = input.Enabled;
        row.ProtectedPassword = protectedPassword; row.UpdatedAtUtc = now;
    }

    internal static string? ValidateSettings(MailSettingsInput input)
    {
        if (string.IsNullOrWhiteSpace(input.Host) || input.Host.Length > 253 || Uri.CheckHostName(input.Host.Trim().TrimEnd('.')) == UriHostNameType.Unknown)
            return "请填写 SMTP 服务器主机名，不含协议和端口。";
        if (input.Port is < 1 or > 65535) return "端口须为 1～65535。";
        if (input.Security is not ("SslOnConnect" or "StartTls")) return "加密方式须为 SSL/TLS 或 STARTTLS。";
        if (!ValidAddress(input.FromAddress)) return "请填写有效的发件邮箱。";
        if (input.Username?.Length > 254 || (input.Username ?? "").Any(char.IsControl)) return "登录账号格式无效。";
        if (input.FromName?.Length > 100 || (input.FromName ?? "").Any(char.IsControl)) return "发件名称最多 100 字，不能包含换行或控制字符。";
        if (input.Password?.Length > 4096 || (input.Password ?? "").Any(char.IsControl)) return "授权码或密码格式无效。";
        return null;
    }

    private static string? ValidateMessage(MailSendInput input)
    {
        if (!Guid.TryParse(input.RequestId, out var requestId) || requestId == Guid.Empty) return "发送请求标识无效，请重新打开写邮件窗口。";
        if (input.To is null || input.To.Length is < 1 or > 50 || input.To.Any(x => !ValidAddress(x))) return "请填写 1～50 个有效收件邮箱。";
        if (string.IsNullOrWhiteSpace(input.Subject) || input.Subject.Length > 300 || input.Subject.Any(char.IsControl)) return "主题须为 1～300 字，不能包含换行或控制字符。";
        if (string.IsNullOrWhiteSpace(input.Body) || input.Body.Length > 100000) return "正文须为 1～100000 字。";
        return null;
    }

    internal static bool ValidAddress(string? value) => !string.IsNullOrWhiteSpace(value) && value.Length <= 254
        && !value.Any(char.IsControl) && MailAddress.TryCreate(value.Trim(), out var address)
        && string.Equals(address.Address, value.Trim(), StringComparison.OrdinalIgnoreCase) && address.Host.Contains('.');

    private static ApiResult<MailMessageDetail> ExistingResult(MailMessage row, string userId, string[] recipients, string subject, string body) =>
        row.CreatedByUserId == userId && row.Subject == subject && row.Body == body && Recipients(row).SequenceEqual(recipients, StringComparer.OrdinalIgnoreCase)
            ? ApiResult<MailMessageDetail>.Ok(ToDetail(row), "此发送请求已记录，未重复发送。")
            : ApiResult<MailMessageDetail>.Fail("CONFLICT", "同一请求标识已用于其他内容，请重新打开写邮件窗口。");

    private static ApiResult<MailMessageDetail> RecordedResult(MailMessage row, string actorId, string[] recipients, string subject, string body, bool systemRequest) =>
        // 提醒重试只读取固定系统请求原结果；模板或证书状态变化不能产生第二封邮件。
        systemRequest && row.CreatedByUserId == actorId
            ? ApiResult<MailMessageDetail>.Ok(ToDetail(row), "此提醒请求已记录，未重复发送。")
            : ExistingResult(row, actorId, recipients, subject, body);

    private static string SafeCode(string code) => code switch
    {
        "MAIL_AUTH_FAILED" or "MAIL_AUTHENTICATION_FAILED" => "MAIL_AUTH_FAILED",
        "MAIL_ENDPOINT_REJECTED" or "MAIL_ENDPOINT_INVALID" => "MAIL_ENDPOINT_REJECTED",
        "MAIL_TLS_FAILED" => "MAIL_TLS_FAILED",
        "MAIL_RECIPIENT_REJECTED" => "MAIL_RECIPIENT_REJECTED",
        "MAIL_SMTP_REJECTED" => "MAIL_SMTP_REJECTED",
        "MAIL_INVALID_CONFIGURATION" => "MAIL_ENDPOINT_REJECTED",
        "MAIL_CONNECTION_FAILED" or "MAIL_CANCELLED" or "MAIL_TIMEOUT" => "MAIL_CONNECTION_FAILED",
        "MAIL_CONFIGURATION_CHANGED" => "MAIL_CONFIGURATION_CHANGED",
        "EXPIRY_REMINDER_CONFIGURATION_CHANGED" => "EXPIRY_REMINDER_CONFIGURATION_CHANGED",
        "EXPIRY_ALERT_CHANGED" => "EXPIRY_ALERT_CHANGED",
        "FORBIDDEN" => "FORBIDDEN",
        _ => "MAIL_SEND_FAILED"
    };

    private static string SafeFailure(string code) => SafeCode(code) switch
    {
        "MAIL_AUTH_FAILED" => "邮箱认证失败，请检查登录账号和授权码。",
        "MAIL_ENDPOINT_REJECTED" => "SMTP 地址不符合连接规则；内网服务器请配置 Mail:AllowedPrivateHosts。",
        "MAIL_TLS_FAILED" => "SMTP 加密连接失败，请检查端口、加密方式和服务器证书。",
        "MAIL_RECIPIENT_REJECTED" => "邮件服务器拒绝了收件人，本次未提交邮件正文。",
        "MAIL_SMTP_REJECTED" => "邮件服务器明确拒绝本次发送，请检查发件邮箱和收件地址。",
        "MAIL_CONNECTION_FAILED" => "SMTP 连接未完成，请检查服务器、端口和网络。",
        "MAIL_CONFIGURATION_CHANGED" => "邮箱配置已变更，本次未发送，请重新操作。",
        "EXPIRY_REMINDER_CONFIGURATION_CHANGED" => "到期提醒已停用或配置已变更，本次未发送。",
        "EXPIRY_ALERT_CHANGED" => "证书提醒状态已变更，本次未发送。",
        "FORBIDDEN" => "发送前权限已变化，本次未发送。",
        _ => "邮件发送失败，请检查服务器连接、邮箱账号和收件地址。"
    };

    private static string[] Recipients(MailMessage row) => JsonSerializer.Deserialize<string[]>(row.ToJson) ?? [];
    // SQLite 不保留 DateTime.Kind；输出显式标记 UTC，避免刷新后的时间被浏览器当成本地时间。
    private static DateTime Utc(DateTime value) => DateTime.SpecifyKind(value, DateTimeKind.Utc);
    private static DateTime? Utc(DateTime? value) => value.HasValue ? Utc(value.Value) : null;
    private static MailSettingsSummary ToSummary(MailSettings row) => new(true, row.Enabled, row.Host, row.Port, row.Security,
        row.Username, row.FromAddress, row.FromName, row.ProtectedPassword.Length > 0, Utc(row.UpdatedAtUtc));
    private static MailMessageSummary ToSummary(MailMessage row) => new(row.Id, Recipients(row), row.FromAddress, row.Subject,
        row.Status, row.Code, row.Message, row.CreatedByUserId, row.CreatedByName, Utc(row.CreatedAtUtc), Utc(row.CompletedAtUtc));
    private static MailMessageDetail ToDetail(MailMessage row) => new(row.Id, Recipients(row), row.FromAddress, row.Subject,
        row.Status, row.Code, row.Message, row.CreatedByUserId, row.CreatedByName, Utc(row.CreatedAtUtc), Utc(row.CompletedAtUtc), row.Body, row.MessageId);
    private sealed record SettingsAndEndpoint(MailSettings Settings, MailTransportEndpoint Endpoint);
}
