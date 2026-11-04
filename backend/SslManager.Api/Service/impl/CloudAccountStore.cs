using System.ComponentModel.DataAnnotations;
using System.Data;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

public sealed class CloudAccountStore(AppDbContext db, IDataProtectionProvider protection, IIdGenerator ids) : ICloudAccountStore
{
    internal const string ConfigurationProtectionPurpose = "SslManager.CloudAccount.v1";
    private IDataProtector Protector(string id) => protection.CreateProtector(ConfigurationProtectionPurpose, id);

    public Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, CancellationToken ct) =>
        ListAsync(page, pageSize, null, null, null, ct);

    public async Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, string? search, string? provider, bool? enabled, CancellationToken ct)
    {
        if (page < 1 || pageSize is < 1 or > 100)
            return ApiResult<CloudAccountPage>.Fail("VALIDATION", "页码必须大于 0，每页条数须为 1～100。");
        if (!string.IsNullOrWhiteSpace(provider) && provider is not ("TencentCloud" or "Aliyun" or "Cloudflare" or "Acme"))
            return ApiResult<CloudAccountPage>.Fail("VALIDATION", "不支持的云平台筛选条件。");
        var query = db.CloudAccounts.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search))
        {
            var keyword = search.Trim();
            query = query.Where(x => x.Name.Contains(keyword) || x.ContactName.Contains(keyword) || x.ContactEmail.Contains(keyword));
        }
        if (!string.IsNullOrWhiteSpace(provider)) query = query.Where(x => x.Provider == provider);
        if (enabled.HasValue) query = query.Where(x => x.Enabled == enabled.Value);
        // 先计算总数，超大页码按空页处理，避免乘法溢出。
        var total = await query.CountAsync(ct);
        var offset = (long)(page - 1) * pageSize;
        List<CloudAccount> rows = offset >= total ? [] : await query.OrderByDescending(x => x.CreatedAtUtc)
            .ThenBy(x => x.Id).Skip((int)offset).Take(pageSize).ToListAsync(ct);
        return ApiResult<CloudAccountPage>.Ok(new(rows.Select(ToSummary).ToArray(), total, page, pageSize));
    }

    public async Task<ApiResult<IReadOnlyList<CloudAccountOption>>> ListOptionsAsync(CancellationToken ct)
    {
        var options = await db.CloudAccounts.AsNoTracking().Where(x => x.Enabled)
            .OrderBy(x => x.Name).Select(x => new CloudAccountOption(x.Id, x.Name, x.Provider, x.Enabled,
                x.UseForCertificates, x.UseForDns, x.AcmeDirectoryUrl)).ToListAsync(ct);
        return ApiResult<IReadOnlyList<CloudAccountOption>>.Ok(options);
    }

    public async Task<ApiResult<CloudAccountSummary>> CreateAsync(CloudAccountInput input, CancellationToken ct)
    {
        var validation = Validate(input, true);
        if (validation is not null) return ApiResult<CloudAccountSummary>.Fail("VALIDATION", validation);
        var now = DateTime.UtcNow;
        var row = new CloudAccount { Id = ids.NewId(), Provider = input.Provider, CreatedAtUtc = now, UpdatedAtUtc = now };
        Apply(row, input);
        db.CloudAccounts.Add(row);
        await db.SaveChangesAsync(ct);
        return ApiResult<CloudAccountSummary>.Ok(ToSummary(row), "云账号已加密保存。");
    }

    public async Task<ApiResult<CloudAccountSummary>> UpdateAsync(string id, CloudAccountInput input, CancellationToken ct)
    {
        var validation = Validate(input, false);
        if (validation is not null) return ApiResult<CloudAccountSummary>.Fail("VALIDATION", validation);
        // 与注册的凭据 CAS 串行，避免先读到空密钥、随后覆盖刚生成的唯一账号私钥。
        await using var transaction = input.Provider == "Acme" ? await db.Database.BeginTransactionAsync(IsolationLevel.Serializable, ct) : null;
        var row = await db.CloudAccounts.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return ApiResult<CloudAccountSummary>.Fail("ACCOUNT_NOT_FOUND", "云账号不存在。");
        // 域名和证书关联的是具体平台账号，禁止原地切换平台改变既有记录含义。
        if (row.Provider != input.Provider)
            return ApiResult<CloudAccountSummary>.Fail("CONFLICT", "已有云账号不能更换平台，请新增账号并停用旧账号。");
        if (row.Provider == "Acme" && (row.AcmeRegistrationStatus is "Prepared" or "Submitting" or "Unknown"))
            return ApiResult<CloudAccountSummary>.Fail("CONFLICT", "ACME 账号正在注册或结果待核对，请先恢复同一注册记录，不能覆盖原凭据。");
        // 同一配置不可切换 CA 目录，否则已有订单与周期计划会指向另一个环境。
        if (row.Provider == "Acme" && row.AcmeDirectoryUrl != input.AcmeDirectoryUrl)
            return ApiResult<CloudAccountSummary>.Fail("CONFLICT", "ACME 正式与测试目录不能原地切换，请分别创建账号配置。");
        if (row.Provider == "Acme" && row.AcmeAccountMode != input.AcmeAccountMode)
            return ApiResult<CloudAccountSummary>.Fail("CONFLICT", "ACME 账号接入模式不能原地切换，请新增接入配置。");
        if (row.Provider == "Acme" && !string.IsNullOrEmpty(input.AccessKeyId) &&
            (row.ProtectedAccessKeyId.Length == 0 || input.AccessKeyId != Protector(row.Id).Unprotect(row.ProtectedAccessKeyId)))
            return ApiResult<CloudAccountSummary>.Fail("CONFLICT", "已有 ACME 接入不能切换账号 URL，请为另一个外部账号新增接入配置。");
        if (row.Provider == "Acme" && row.ProtectedAccessKeySecret.Length > 0 && !string.IsNullOrEmpty(input.AccessKeySecret))
        {
            try
            {
                if (AcmeProtocolClient.Thumbprint(Protector(row.Id).Unprotect(row.ProtectedAccessKeySecret)) != AcmeProtocolClient.Thumbprint(input.AccessKeySecret))
                    return ApiResult<CloudAccountSummary>.Fail("CONFLICT", "ACME 账号公钥身份不能更换，请为不同私钥新增接入配置。");
            }
            catch (Exception exception) when (exception is CryptographicException or ArgumentException)
            { return ApiResult<CloudAccountSummary>.Fail("ACME_ACCOUNT_KEY_UNREADABLE", "无法读取原始账号私钥，未生成或覆盖凭据。"); }
        }
        Apply(row, input);
        row.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        if (transaction is not null) await transaction.CommitAsync(ct);
        return ApiResult<CloudAccountSummary>.Ok(ToSummary(row), "云账号已更新，留空的密钥保持原值。");
    }

    public Task<ApiResult<CloudAccountCredentials>> GetCredentialsAsync(string accountId, CancellationToken ct) =>
        ReadCredentialsAsync(accountId, true, ct);

    public Task<ApiResult<CloudAccountCredentials>> GetCredentialsForContactSyncAsync(string accountId, CancellationToken ct) =>
        ReadCredentialsAsync(accountId, false, ct);

    public async Task<ApiResult<bool>> RecordTestAsync(string accountId, bool success, string code, string message, CancellationToken ct)
    {
        var row = await db.CloudAccounts.SingleOrDefaultAsync(x => x.Id == accountId, ct);
        if (row is null) return ApiResult<bool>.Fail("ACCOUNT_NOT_FOUND", "云账号不存在。");
        row.LastTestAtUtc = DateTime.UtcNow;
        row.LastTestSuccess = success;
        row.LastTestCode = code.Length > 100 ? code[..100] : code;
        row.LastTestMessage = message.Length > 500 ? message[..500] : message;
        await db.SaveChangesAsync(ct);
        return ApiResult<bool>.Ok(true);
    }

    public async Task<ApiResult<CloudAccountSecrets>> RevealSecretsAsync(string accountId, CancellationToken ct)
    {
        // 管理员的主动恢复入口不要求两项凭据齐全：ACME 注册回执未知时仍可取回原账号私钥。
        var row = await db.CloudAccounts.AsNoTracking().SingleOrDefaultAsync(x => x.Id == accountId, ct);
        if (row is null) return ApiResult<CloudAccountSecrets>.Fail("ACCOUNT_NOT_FOUND", "云账号不存在。");
        if (row.ProtectedAccessKeyId.Length == 0 && row.ProtectedAccessKeySecret.Length == 0)
            return ApiResult<CloudAccountSecrets>.Fail("CONFIGURATION_MISSING", "尚未配置或生成账号凭据。");
        var protector = Protector(row.Id);
        return ApiResult<CloudAccountSecrets>.Ok(new(
            row.ProtectedAccessKeyId.Length == 0 ? "" : protector.Unprotect(row.ProtectedAccessKeyId),
            row.ProtectedAccessKeySecret.Length == 0 ? "" : protector.Unprotect(row.ProtectedAccessKeySecret)));
    }

    private async Task<ApiResult<CloudAccountCredentials>> ReadCredentialsAsync(string accountId, bool requireEnabled, CancellationToken ct)
    {
        var row = await db.CloudAccounts.AsNoTracking().SingleOrDefaultAsync(x => x.Id == accountId, ct);
        if (row is null) return ApiResult<CloudAccountCredentials>.Fail("ACCOUNT_NOT_FOUND", "云账号不存在。");
        if (requireEnabled && !row.Enabled) return ApiResult<CloudAccountCredentials>.Fail("FORBIDDEN", "云账号已停用。");
        if (((row.Provider is "TencentCloud" or "Aliyun" or "Acme") && string.IsNullOrEmpty(row.ProtectedAccessKeyId)) ||
            string.IsNullOrEmpty(row.ProtectedAccessKeySecret))
            return ApiResult<CloudAccountCredentials>.Fail("CONFIGURATION_MISSING", row.Provider == "Acme" && row.AcmeAccountMode == "Automatic"
                ? "请先在云账号页面明确确认并注册 ACME 账号；连接测试和证书申请不会代为注册。" : "云账号尚未配置完整密钥。");
        var protector = Protector(row.Id);
        return ApiResult<CloudAccountCredentials>.Ok(new(row.Id, row.Name, row.Provider,
            string.IsNullOrEmpty(row.ProtectedAccessKeyId) ? "" : protector.Unprotect(row.ProtectedAccessKeyId),
            string.IsNullOrEmpty(row.ProtectedAccessKeySecret) ? "" : protector.Unprotect(row.ProtectedAccessKeySecret), row.Enabled,
            row.UseForCertificates, row.UseForDns, row.ContactName, row.ContactEmail, row.ContactPhone, row.AliyunContactId, row.AcmeDirectoryUrl));
    }

    private void Apply(CloudAccount row, CloudAccountInput input) => ApplyConfiguration(row, input, protection);

    /// <summary>普通保存与配置导入复用同一字段映射和保护目的，导入方负责强制停用。</summary>
    internal static void ApplyConfiguration(CloudAccount row, CloudAccountInput input, IDataProtectionProvider protection)
    {
        row.Name = input.Name.Trim();
        row.Enabled = input.Enabled;
        row.UseForCertificates = input.UseForCertificates;
        row.UseForDns = input.UseForDns;
        row.ContactName = (input.ContactName ?? "").Trim();
        row.ContactEmail = (input.ContactEmail ?? "").Trim();
        row.ContactPhone = (input.ContactPhone ?? "").Trim();
        row.AcmeDirectoryUrl = input.Provider == "Acme" ? input.AcmeDirectoryUrl : "https://acme-v02.api.letsencrypt.org/directory";
        row.AcmeAccountMode = input.Provider == "Acme" ? input.AcmeAccountMode : "Existing";
        if (input.Provider == "Acme" && row.AcmeRegistrationStatus.Length == 0)
            row.AcmeRegistrationStatus = input.AcmeAccountMode == "Automatic" ? "New" : "Provided";
        // 联系人 ID 只属于阿里云；切换到腾讯云时清除旧值，避免后续误带入申请。
        row.AliyunContactId = string.Equals(input.Provider, "Aliyun", StringComparison.OrdinalIgnoreCase)
            ? (input.AliyunContactId ?? "").Trim()
            : "";
        row.AutoSyncEnabled = input.AutoSyncEnabled;
        row.AutoSyncIntervalUnit = input.AutoSyncIntervalUnit;
        row.AutoSyncIntervalValue = input.AutoSyncIntervalValue;
        row.AutoSyncAtLocalTime = input.AutoSyncAtLocalTime;
        row.AutoSyncNextRunAtUtc = input.AutoSyncEnabled ? AutoSyncSchedule.NextRun(row, DateTime.UtcNow) : null;
        var protector = protection.CreateProtector(ConfigurationProtectionPurpose, row.Id);
        if (!string.IsNullOrEmpty(input.AccessKeyId)) row.ProtectedAccessKeyId = protector.Protect(input.AccessKeyId);
        // ACME 接入的同一公钥只保留原密文；注册回执 CAS 与恢复台账都依赖这份原始身份。
        if (!string.IsNullOrEmpty(input.AccessKeySecret) && (input.Provider != "Acme" || row.ProtectedAccessKeySecret.Length == 0))
            row.ProtectedAccessKeySecret = protector.Protect(input.AccessKeySecret);
    }

    private CloudAccountSummary ToSummary(CloudAccount row)
    {
        var value = string.IsNullOrEmpty(row.ProtectedAccessKeyId) ? "" : Protector(row.Id).Unprotect(row.ProtectedAccessKeyId);
        var masked = value.Length == 0 ? "" : value.Length <= 8 ? "********" : value[..4] + "********" + value[^4..];
        var thumbprint = "";
        if (row.Provider == "Acme" && row.ProtectedAccessKeySecret.Length > 0)
        {
            var key = Protector(row.Id).Unprotect(row.ProtectedAccessKeySecret);
            if (AcmeProtocolClient.IsValidAccountKey(key)) thumbprint = AcmeProtocolClient.Thumbprint(key);
        }
        return new(row.Id, row.Name, row.Provider, masked, !string.IsNullOrEmpty(row.ProtectedAccessKeySecret),
            row.Enabled, row.UseForCertificates, row.UseForDns, row.ContactName, row.ContactEmail, row.ContactPhone,
            row.CreatedAtUtc, row.UpdatedAtUtc, row.AutoSyncEnabled, row.AutoSyncIntervalUnit,
            row.AutoSyncIntervalValue, row.AutoSyncAtLocalTime, row.AutoSyncNextRunAtUtc, row.LastAutoSyncAtUtc,
            row.LastTestAtUtc, row.LastTestSuccess, row.LastTestCode, row.LastTestMessage, row.AliyunContactId, row.AcmeDirectoryUrl,
            row.AcmeAccountMode, row.AcmeRegistrationStatus, row.Provider == "Acme" ? value : "", thumbprint, row.AcmeRegisteredAtUtc);
    }

    internal static string? Validate(CloudAccountInput input, bool create)
    {
        if (string.IsNullOrWhiteSpace(input.Name) || input.Name.Length > 100) return "云账号名称须为 1～100 个字符。";
        if (input.Provider is not ("TencentCloud" or "Aliyun" or "Cloudflare" or "Acme")) return "不支持的云平台。";
        if (input.Provider == "Cloudflare" && (input.UseForCertificates || !input.UseForDns)) return "Cloudflare 账号仅用于 DNS 托管与域名验证。";
        if (input.Provider == "Acme")
        {
            if (input.AcmeAccountMode is not ("Existing" or "Automatic")) return "请选择使用已有 ACME 账号或由系统显式注册账号。";
            if (input.UseForDns) return "ACME 账号仅用于证书申请，请另选 DNS 托管账号。";
            if (input.AcmeDirectoryUrl is not ("https://acme-v02.api.letsencrypt.org/directory" or "https://acme-staging-v02.api.letsencrypt.org/directory"))
                return "仅支持 Let's Encrypt 正式或测试 ACME 目录。";
            if (create && input.AcmeAccountMode == "Existing" && (string.IsNullOrEmpty(input.AccessKeyId) || string.IsNullOrEmpty(input.AccessKeySecret)))
                return "请先自行注册 ACME 账号，再提供既有账号 URL 与 PEM 格式账号私钥；系统不代注册。";
            if (input.AcmeAccountMode == "Automatic" && string.IsNullOrWhiteSpace(input.ContactEmail)) return "系统注册模式需要联系邮箱；保存后请单独确认注册及 CA 条款。";
            if (!string.IsNullOrEmpty(input.AccessKeyId) &&
                (!AcmeProtocolClient.IsAllowedResource(input.AcmeDirectoryUrl, input.AccessKeyId) ||
                 !new Uri(input.AccessKeyId).AbsolutePath.StartsWith("/acme/acct/", StringComparison.Ordinal)))
                return "ACME 账号 URL 必须属于所选 CA 目录的 /acme/acct/ 路径。";
            if (!string.IsNullOrEmpty(input.AccessKeySecret) && !AcmeProtocolClient.IsValidAccountKey(input.AccessKeySecret))
                return "请提供受支持的 PEM 格式 ACME 账号私钥，不能使用邮箱密码、API Key 或证书私钥代替。";
        }
        if (input.AutoSyncEnabled && !input.UseForCertificates && !input.UseForDns)
            return "启用自动同步时，至少需要启用证书管理或 DNS 管理用途。";
        if (input.AutoSyncIntervalUnit is not ("minute" or "hour" or "day" or "month")) return "自动同步周期单位无效。";
        if (input.AutoSyncIntervalValue is < 1 or > 366) return "自动同步周期必须在 1～366 之间。";
        if (string.IsNullOrWhiteSpace(input.AutoSyncAtLocalTime) ||
            !TimeOnly.TryParseExact(input.AutoSyncAtLocalTime, "HH:mm", out _)) return "自动同步时间必须为 HH:mm。";
        if (create && (input.Provider is "TencentCloud" or "Aliyun") && (string.IsNullOrEmpty(input.AccessKeyId) || string.IsNullOrEmpty(input.AccessKeySecret)))
            return "首次保存必须填写 AccessKeyId 和 AccessKeySecret。";
        if (create && input.Provider == "Cloudflare" && string.IsNullOrEmpty(input.AccessKeySecret)) return "首次保存必须填写 Cloudflare API Token。";
        if (input.Provider == "Cloudflare" && !string.IsNullOrEmpty(input.AccessKeyId) &&
            (input.AccessKeyId.Length != 32 || !input.AccessKeyId.All(Uri.IsHexDigit))) return "Cloudflare Account ID 应为 32 位十六进制，或留空。";
        if (input.AccessKeyId?.Length > 4096 || input.AccessKeySecret?.Length > 8192) return "云账号密钥超出长度限制。";
        if (!string.IsNullOrWhiteSpace(input.AliyunContactId))
        {
            if (!long.TryParse(input.AliyunContactId.Trim(), out var contactId) || contactId < 1)
                return "阿里云联系人 ID 必须是正整数。";
        }
        if ((input.AccessKeyId ?? "").Any(c => char.IsWhiteSpace(c) || char.IsControl(c)) ||
            (input.Provider != "Acme" && (input.AccessKeySecret ?? "").Any(c => char.IsWhiteSpace(c) || char.IsControl(c))))
            return "密钥不能包含空白或控制字符；ACME PEM 账号私钥允许换行，留空表示保留原值。";
        if (input.ContactName?.Length > 100 || input.ContactEmail?.Length > 254 || input.ContactPhone?.Length > 40)
            return "联系人信息超出长度限制。";
        if (!string.IsNullOrWhiteSpace(input.ContactEmail) && !new EmailAddressAttribute().IsValid(input.ContactEmail.Trim()))
            return "请输入有效的联系人邮箱。";
        return null;
    }
}
