using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>
/// 只有管理员显式调用才自动注册。账户私钥先 CAS 持久化且仅生成一次；
/// 提交结果未知后仅查找同一公钥账户，不因普通 Test、Apply 或后台恢复创建账户。
/// </summary>
public sealed class AcmeAccountRegistrationService(AppDbContext db, IDataProtectionProvider protection,
    AcmeProtocolClient api) : IAcmeAccountRegistrationService
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private IDataProtector Protector(string id) => protection.CreateProtector(CloudAccountStore.ConfigurationProtectionPurpose, id);

    public async Task<ApiResult<AcmeAccountRegistrationView>> RegisterAsync(string accountId, bool agreeTerms, CancellationToken ct = default)
    {
        if (!agreeTerms) return ApiResult<AcmeAccountRegistrationView>.Fail("ACME_TERMS_REQUIRED", "自动注册前须明确同意所选 CA 的服务条款。");
        await Gate.WaitAsync(ct);
        try
        {
            var row = await ReadAsync(accountId, ct);
            if (row is null) return ApiResult<AcmeAccountRegistrationView>.Fail("ACCOUNT_NOT_FOUND", "ACME 账号配置不存在。");
            if (row.Provider != "Acme" || row.AcmeAccountMode != "Automatic" || !row.Enabled || !row.UseForCertificates)
                return ApiResult<AcmeAccountRegistrationView>.Fail("ACME_REGISTRATION_NOT_ALLOWED", "仅已启用且选择系统自动注册的 ACME 账号可调用此入口。");
            if (!AcmeProtocolClient.IsAllowedDirectory(row.AcmeDirectoryUrl))
                return ApiResult<AcmeAccountRegistrationView>.Fail("ACME_DIRECTORY_NOT_ALLOWED", "请选择支持的 Let’s Encrypt 目录。");
            if (string.IsNullOrWhiteSpace(row.ContactEmail) || !new EmailAddressAttribute().IsValid(row.ContactEmail))
                return ApiResult<AcmeAccountRegistrationView>.Fail("ACME_EMAIL_REQUIRED", "自动注册需要有效联系人邮箱。");

            var newlyPrepared = false;
            if (row.ProtectedAccessKeySecret == "")
            {
                // 多进程竞争只允许一份密文成为原始账户密钥；失败者必须丢弃自己临时生成的候选值。
                using var candidate = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                var encrypted = Protector(row.Id).Protect(candidate.ExportPkcs8PrivateKeyPem());
                var changed = await db.CloudAccounts.Where(x => x.Id == row.Id && x.Provider == "Acme" && x.Enabled && x.UseForCertificates &&
                        x.AcmeAccountMode == "Automatic" && x.AcmeDirectoryUrl == row.AcmeDirectoryUrl &&
                        x.ProtectedAccessKeySecret == "" && x.ProtectedAccessKeyId == "")
                    .ExecuteUpdateAsync(update => update.SetProperty(x => x.ProtectedAccessKeySecret, encrypted)
                        .SetProperty(x => x.AcmeRegistrationStatus, "Prepared").SetProperty(x => x.UpdatedAtUtc, DateTime.UtcNow), ct);
                newlyPrepared = changed == 1;
                row = await ReadAsync(accountId, ct);
                if (row is null || row.ProtectedAccessKeySecret == "")
                    return ApiResult<AcmeAccountRegistrationView>.Fail("ACME_REGISTRATION_CONFLICT", "账号配置已变化，未提交外部注册。");
            }
            string privateKey, accountUrl;
            try
            {
                privateKey = Protector(row.Id).Unprotect(row.ProtectedAccessKeySecret);
                accountUrl = row.ProtectedAccessKeyId == "" ? "" : Protector(row.Id).Unprotect(row.ProtectedAccessKeyId);
            }
            catch (CryptographicException)
            { return ApiResult<AcmeAccountRegistrationView>.Fail("ACME_ACCOUNT_KEY_UNREADABLE", "原账户凭据无法解密，请恢复原始密钥；不会生成替代账户私钥。"); }
            if (!AcmeProtocolClient.IsValidAccountKey(privateKey))
                return ApiResult<AcmeAccountRegistrationView>.Fail("ACME_ACCOUNT_KEY_INVALID", "已保存的原账户私钥无效，不会重新生成或覆盖。");
            var thumbprint = AcmeProtocolClient.Thumbprint(privateKey);
            if (accountUrl != "")
            {
                if (!ValidAccountUrl(row.AcmeDirectoryUrl, accountUrl))
                    return ApiResult<AcmeAccountRegistrationView>.Fail("ACME_ACCOUNT_URL_INVALID", "已保存账户 URL 不属于当前 CA 目录。");
                // 已成功注册的重复调用直接返回同一身份，不再次注册或维护外部账户。
                return ApiResult<AcmeAccountRegistrationView>.Ok(View(row, accountUrl, thumbprint, "Registered"), "返回已保存的同一 ACME 账户信息。");
            }
            var directory = await api.RegistrationDirectoryAsync(row.AcmeDirectoryUrl, ct);
            if (!directory.Success || directory.Data is null) return Failure(row, thumbprint, directory.Code, directory.Message);
            if (!newlyPrepared)
            {
                // 已有密钥但无回执时先只读恢复；未知提交绝不再次发送 create。
                var found = await api.FindExistingAccountAsync(directory.Data, privateKey, ct);
                if (found.Success && found.Data is not null) return await SaveRegisteredAsync(row, found.Data, thumbprint, ct);
                if (found.Code != "ACME_ACCOUNT_NOT_FOUND") return Failure(row, thumbprint, found.Code, found.Message);
                if (row.AcmeRegistrationStatus is "Unknown" or "Submitting")
                {
                    await SetStatusAsync(row, "Unknown", ct);
                    return Failure(row, thumbprint, "ACME_REGISTRATION_RESULT_UNKNOWN", "原注册结果仍未知，仅核对同一账户；未重复注册。", "Unknown");
                }
                if (row.AcmeRegistrationStatus is not ("Prepared" or "Failed"))
                {
                    await SetStatusAsync(row, "Failed", ct);
                    return Failure(row, thumbprint, "ACME_REGISTRATION_RETRY_REQUIRED", "原账户公钥在 CA 尚不存在；已保留原密钥，请再次显式注册后重试。", "Failed");
                }
                // Prepared 尚未记录任何远端提交意图；当前显式重试确认 CA 不存在后，可用原密钥继续首次注册。
            }
            // 网络调用前原子记录提交意图；多个进程不可能同时获得同一状态的派发资格。
            var claimed = await db.CloudAccounts.Where(x => x.Id == row.Id && x.Enabled && x.UseForCertificates && x.AcmeAccountMode == "Automatic" &&
                    x.AcmeDirectoryUrl == row.AcmeDirectoryUrl && x.ContactEmail == row.ContactEmail &&
                    x.ProtectedAccessKeySecret == row.ProtectedAccessKeySecret && x.ProtectedAccessKeyId == "" &&
                    x.AcmeRegistrationStatus == row.AcmeRegistrationStatus)
                .ExecuteUpdateAsync(update => update.SetProperty(x => x.AcmeRegistrationStatus, "Submitting").SetProperty(x => x.UpdatedAtUtc, DateTime.UtcNow), ct);
            if (claimed != 1) return Failure(row, thumbprint, "ACME_REGISTRATION_CONFLICT", "另一个执行者已接管或配置已变化，未重复提交。");
            row.AcmeRegistrationStatus = "Submitting";
            var created = await api.CreateAccountAsync(directory.Data, privateKey, row.ContactEmail, ct);
            if (created.Success && created.Data is not null) return await SaveRegisteredAsync(row, created.Data, thumbprint, ct);
            var status = created.Code == "OutcomeUnknown" ? "Unknown" : "Failed";
            await SetStatusAsync(row, status, ct);
            return Failure(row, thumbprint, created.Code, created.Message, status);
        }
        finally { Gate.Release(); }
    }

    private async Task<ApiResult<AcmeAccountRegistrationView>> SaveRegisteredAsync(CloudAccount row, AcmeProtocolResponse response,
        string thumbprint, CancellationToken ct)
    {
        var accountUrl = response.Location;
        if (!ValidAccountUrl(row.AcmeDirectoryUrl, accountUrl))
        {
            await SetStatusAsync(row, "Unknown", ct);
            return Failure(row, thumbprint, "OutcomeUnknown", "CA 回执缺少可信账户 URL，保留原账户私钥，仅继续只读核对。", "Unknown");
        }
        if (response.Json.ValueKind != JsonValueKind.Object || !response.Json.TryGetProperty("status", out var status) ||
            status.ValueKind != JsonValueKind.String || status.GetString() != "valid")
        {
            await SetStatusAsync(row, "Failed", ct);
            return Failure(row, thumbprint, "ACME_ACCOUNT_NOT_VALID", "CA 未确认账户有效，请核对账户状态。", "Failed");
        }
        var now = DateTime.UtcNow;
        var protectedUrl = Protector(row.Id).Protect(accountUrl);
        var changed = await db.CloudAccounts.Where(x => x.Id == row.Id && x.AcmeAccountMode == "Automatic" &&
                x.AcmeDirectoryUrl == row.AcmeDirectoryUrl && x.ProtectedAccessKeySecret == row.ProtectedAccessKeySecret && x.ProtectedAccessKeyId == "")
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.ProtectedAccessKeyId, protectedUrl)
                .SetProperty(x => x.AcmeRegistrationStatus, "Registered").SetProperty(x => x.AcmeRegisteredAtUtc, now)
                .SetProperty(x => x.UpdatedAtUtc, now), ct);
        if (changed != 1) return Failure(row, thumbprint, "ACME_REGISTRATION_CONFLICT", "外部已返回账户，但本地配置已变化；保留原始凭据后核对。");
        row.AcmeRegisteredAtUtc = now; row.AcmeRegistrationStatus = "Registered";
        return ApiResult<AcmeAccountRegistrationView>.Ok(View(row, accountUrl, thumbprint, "Registered"), "ACME 账户已注册并加密保存，可主动查看凭据后复用。");
    }

    private Task<CloudAccount?> ReadAsync(string id, CancellationToken ct) => db.CloudAccounts.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
    private Task<int> SetStatusAsync(CloudAccount row, string status, CancellationToken ct) =>
        db.CloudAccounts.Where(x => x.Id == row.Id && x.AcmeAccountMode == "Automatic" && x.ProtectedAccessKeySecret == row.ProtectedAccessKeySecret &&
                x.ProtectedAccessKeyId == "" && x.AcmeRegistrationStatus == row.AcmeRegistrationStatus)
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.AcmeRegistrationStatus, status).SetProperty(x => x.UpdatedAtUtc, DateTime.UtcNow), ct);
    private static bool ValidAccountUrl(string directory, string value) => AcmeProtocolClient.IsAllowedResource(directory, value) &&
        new Uri(value).AbsolutePath.StartsWith("/acme/acct/", StringComparison.Ordinal);
    private static AcmeAccountRegistrationView View(CloudAccount row, string url, string thumbprint, string? status = null) =>
        new(url, row.AcmeDirectoryUrl, thumbprint, status ?? row.AcmeRegistrationStatus, row.AcmeRegisteredAtUtc);
    private static ApiResult<AcmeAccountRegistrationView> Failure(CloudAccount row, string thumbprint, string code, string message, string? status = null) =>
        new(false, code, message, View(row, "", thumbprint, status));
}
