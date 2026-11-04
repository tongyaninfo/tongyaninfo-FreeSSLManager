using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>免费 Let’s Encrypt DNS-01 签发。订单、原始私钥和 CSR 持久化，刷新查询不接受挑战或 finalize。</summary>
public sealed class AcmeCloudService(AcmeProtocolClient api, ICertificateIssuanceStore materials, AppDbContext db,
    IAcmeDnsPropagationChecker propagation) : ICloudCertificateService
{
    public string Provider => "Acme";
    private const string ApiVersion = "AcmeV2";
    private sealed record Session(AcmeDirectory Directory, string AccountUrl, string PrivateKeyPem)
    { public override string ToString() => "AcmeSession { 账号私钥已隐藏 }"; }

    public async Task<ApiResult<CloudConnectionTest>> TestAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        var imported = await ValidateImportedAccountAsync(account, ct);
        return imported.Success ? ApiResult<CloudConnectionTest>.Ok(new(Provider, "", "用户提供的既有 ACME 账户签名校验成功，账户状态有效；未创建或维护外部账户。"))
            : ApiResult<CloudConnectionTest>.Fail(imported.Code, imported.Message);
    }

    public async Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        // ACME 没有腾讯云式全量证书列表；本实例的长期订单台账是同步范围，不能返回空列表误删本地证书。
        var states = await db.CertificateIssuanceStates.Where(x => x.AccountId == account.Id && x.Provider == Provider &&
            x.OrderUrl != "" && x.Stage != "Deleted").ToListAsync(ct);
        var result = new List<CloudCertificate>();
        foreach (var state in states)
        {
            var item = await GetAsync(account, Reference(state), ct);
            if (!item.Success || item.Data is null) return ApiResult<IReadOnlyList<CloudCertificate>>.Fail(item.Code, item.Message);
            result.Add(item.Data.Certificate);
        }
        return ApiResult<IReadOnlyList<CloudCertificate>>.Ok(result);
    }

    public async Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default)
    {
        if (!CloudJson.Domain(request.Domain) || request.ValidationMode is not ("ManagedDns" or "ManualDns") ||
            string.IsNullOrWhiteSpace(request.LocalCertificateId))
            return ApiResult<CloudCertificateDetail>.Fail("INVALID_ACME_APPLICATION", "ACME 仅支持有效单域名的 DNS-01 验证，并要求本地申请 ID。");
        var material = await materials.GetOrCreateAsync(request.LocalCertificateId, Provider, request.Domain, account.Id, ct);
        if (!material.Success) return ApiResult<CloudCertificateDetail>.Fail(material.Code, material.Message);
        var state = await db.CertificateIssuanceStates.SingleAsync(x => x.Id == request.LocalCertificateId, ct);
        if (!string.IsNullOrEmpty(state.OrderUrl)) return await GetAsync(account, Reference(state), ct);
        if (state.Stage != "Prepared")
            return ApiResult<CloudCertificateDetail>.Fail("OutcomeUnknown", "本轮 ACME 订单提交曾中断，已保留原私钥，不会重复创建订单。");
        var sessionResult = await ValidateImportedAccountAsync(account, ct);
        if (!sessionResult.Success || sessionResult.Data is null) return ApiResult<CloudCertificateDetail>.Fail(sessionResult.Code, sessionResult.Message);
        var session = sessionResult.Data;
        state.AcmeAccountUrl = session.AccountUrl; state.AccountKeyThumbprint = AcmeProtocolClient.Thumbprint(session.PrivateKeyPem);
        state.IsStaging = session.Directory.Url == AcmeProtocolClient.StagingDirectory;
        state.Stage = "OrderSubmitting"; await SaveAsync(state, ct);
        var order = await api.PostAsync(session.Directory, session.Directory.NewOrder, session.PrivateKeyPem, session.AccountUrl,
            new { identifiers = new[] { new { type = "dns", value = state.Domain } } }, ct);
        if (!order.Success || order.Data is null)
        {
            if (order.Code != "OutcomeUnknown") { state.Stage = "Failed"; await SaveAsync(state, ct); }
            return ApiResult<CloudCertificateDetail>.Fail(order.Code, order.Message);
        }
        if (!AcmeProtocolClient.IsAllowedResource(session.Directory.Url, order.Data.Location))
            return ApiResult<CloudCertificateDetail>.Fail("OutcomeUnknown", "CA 未返回可信订单地址，不能再次下单。");
        // 先保存唯一订单引用；后续查询失败仍以原订单继续，不能重新创建申请。
        state.OrderUrl = order.Data.Location; state.Stage = "PendingValidation";
        await SaveAsync(state, ct);
        var parsed = await ReadOrderAsync(state, session, order.Data.Json, ct);
        if (parsed.Success) return parsed;
        return ApiResult<CloudCertificateDetail>.Ok(new(await CertificateAsync(state, "PendingValidation", "pending", [], ct), [], parsed.Message));
    }

    public async Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
    {
        var state = await FindStateAsync(account.Id, reference, ct);
        if (state is null) return ApiResult<CloudCertificateDetail>.Fail("NOT_FOUND", "ACME 订单不属于当前账号或本实例未保存此订单。");
        if (state.Stage == "Deleted") return ApiResult<CloudCertificateDetail>.Fail("NOT_FOUND", "ACME 本地证书已归档删除。");
        if (state.Stage is "Revoked" or "RevokeSubmitting")
            return ApiResult<CloudCertificateDetail>.Ok(new(await CertificateAsync(state, state.Stage == "Revoked" ? "Revoked" : "Revoking", state.Stage, [], ct), []));
        var session = await ReadSessionAsync(account, state, ct);
        if (!session.Success || session.Data is null) return ApiResult<CloudCertificateDetail>.Fail(session.Code, session.Message);
        var order = await api.PostAsync(session.Data.Directory, state.OrderUrl, session.Data.PrivateKeyPem, session.Data.AccountUrl, null, ct);
        if (!order.Success || order.Data is null) return ApiResult<CloudCertificateDetail>.Fail(order.Code, order.Message);
        return await ReadOrderAsync(state, session.Data, order.Data.Json, ct);
    }

    public async Task<ApiResult<CloudCertificateDetail>> ContinueApplicationAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
    {
        var state = await FindStateAsync(account.Id, reference, ct);
        if (state is null) return ApiResult<CloudCertificateDetail>.Fail("NOT_FOUND", "ACME 订单不存在。");
        var sessionResult = await ReadSessionAsync(account, state, ct);
        if (!sessionResult.Success || sessionResult.Data is null) return ApiResult<CloudCertificateDetail>.Fail(sessionResult.Code, sessionResult.Message);
        var session = sessionResult.Data;
        var current = await GetAsync(account, reference, ct);
        if (!current.Success || current.Data is null || current.Data.Certificate.Status is "Issued" or "Failed" or "Revoked") return current;
        var rawStatus = current.Data.Certificate.RawStatus;
        if (rawStatus == "pending")
        {
            var challenges = current.Data.Challenges;
            if (!await propagation.IsVisibleAsync(challenges, ct))
                return ApiResult<CloudCertificateDetail>.Fail("ACME_DNS_PROPAGATION_PENDING", "权威 DNS 尚未完整返回本轮 TXT 验证值，等待传播后再通知 CA。");
            var authorizations = ReadAuthorizations(state);
            for (var i = 0; i < authorizations.Count; i++)
            {
                var authorization = authorizations[i];
                if (authorization.Status != "pending" || authorization.NotificationSubmitted) continue;
                authorizations[i] = authorization with { NotificationSubmitted = true };
                state.AuthorizationsJson = JsonSerializer.Serialize(authorizations); await SaveAsync(state, ct);
                var accepted = await api.PostAsync(session.Directory, authorization.ChallengeUrl, session.PrivateKeyPem, session.AccountUrl, new { }, ct);
                if (!accepted.Success)
                {
                    // 确定拒绝可再检查参数后重试；结果未知保留通知意图，先轮询同一挑战。
                    if (accepted.Code != "OutcomeUnknown")
                    { authorizations[i] = authorization; state.AuthorizationsJson = JsonSerializer.Serialize(authorizations); await SaveAsync(state, ct); }
                    return ApiResult<CloudCertificateDetail>.Fail(accepted.Code, accepted.Message);
                }
            }
            return await GetAsync(account, reference, ct);
        }
        if (rawStatus == "ready")
        {
            if (state.Stage == "FinalizeSubmitting")
                return ApiResult<CloudCertificateDetail>.Fail("ACME_FINALIZATION_UNKNOWN", "原订单 finalize 结果仍待核对，保留原 CSR，不重复提交。");
            var material = await materials.GetAsync(state.Id, ct);
            if (!material.Success || material.Data is null) return ApiResult<CloudCertificateDetail>.Fail(material.Code, material.Message);
            if (!AcmeProtocolClient.IsAllowedResource(session.Directory.Url, state.FinalizeUrl))
                return ApiResult<CloudCertificateDetail>.Fail("ACME_UNSAFE_RESOURCE", "CA 未返回可信签发地址。");
            var pem = PemEncoding.Find(material.Data.CsrPem.AsSpan());
            var csr = Convert.FromBase64String(material.Data.CsrPem[pem.Base64Data]);
            state.Stage = "FinalizeSubmitting"; await SaveAsync(state, ct);
            var finalized = await api.PostAsync(session.Directory, state.FinalizeUrl, session.PrivateKeyPem, session.AccountUrl,
                new { csr = AcmeProtocolClient.Encode(csr) }, ct);
            if (!finalized.Success || finalized.Data is null)
            {
                if (finalized.Code != "OutcomeUnknown") { state.Stage = "Ready"; await SaveAsync(state, ct); }
                return ApiResult<CloudCertificateDetail>.Fail(finalized.Code, finalized.Message);
            }
            var result = await ReadOrderAsync(state, session, finalized.Data.Json, ct);
            if (!result.Success || result.Data is null || result.Data.Certificate.RawStatus != "valid") return result;
            rawStatus = "valid";
        }
        if (rawStatus == "valid")
        {
            if (!AcmeProtocolClient.IsAllowedResource(session.Directory.Url, state.CertificateUrl))
                return ApiResult<CloudCertificateDetail>.Fail("ACME_UNSAFE_RESOURCE", "CA 未返回可信证书下载地址。");
            var certificate = await api.PostAsync(session.Directory, state.CertificateUrl, session.PrivateKeyPem, session.AccountUrl, null, ct);
            if (!certificate.Success || certificate.Data is null) return ApiResult<CloudCertificateDetail>.Fail(certificate.Code, certificate.Message);
            var blocks = Regex.Matches(certificate.Data.Body, @"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----").Select(x => x.Value).ToArray();
            if (blocks.Length is 0 or > 16) return ApiResult<CloudCertificateDetail>.Fail("ACME_CERTIFICATE_INVALID", "CA 未返回有效的证书链。");
            string serial;
            try { using var leaf = X509Certificate2.CreateFromPem(blocks[0]); serial = leaf.SerialNumber; }
            catch (Exception ex) when (ex is CryptographicException or ArgumentException)
            { return ApiResult<CloudCertificateDetail>.Fail("ACME_CERTIFICATE_INVALID", "CA 返回的叶子证书无法解析，原私钥和订单台账已保留。"); }
            var stored = await materials.StoreIssuedAsync(state.Id, blocks[0], string.Join("\n", blocks.Skip(1)), serial, ct);
            if (!stored.Success) return ApiResult<CloudCertificateDetail>.Fail(stored.Code, stored.Message);
            return ApiResult<CloudCertificateDetail>.Ok(new(await CertificateAsync(state, "Issued", "valid", [], ct), []));
        }
        return current;
    }

    public async Task<ApiResult<CertificateDownload>> DownloadAsync(CloudAccountCredentials account, CloudCertificateReference reference, string format, CancellationToken ct = default)
    {
        var state = await FindStateAsync(account.Id, reference, ct);
        if (state is null) return ApiResult<CertificateDownload>.Fail("NOT_FOUND", "ACME 证书不存在。");
        var material = await materials.GetAsync(state.Id, ct);
        if (!material.Success || material.Data is null) return ApiResult<CertificateDownload>.Fail(material.Code, material.Message);
        return CertificateDownloadHelper.FromPem(material.Data.CertificatePem + "\n" + material.Data.ChainPem, material.Data.PrivateKeyPem, state.Id, format, "");
    }

    public async Task<ApiResult<CloudOperation>> RevokeAsync(CloudAccountCredentials account, CloudCertificateReference reference, string reason, CancellationToken ct = default)
    {
        var state = await FindStateAsync(account.Id, reference, ct);
        if (state is null) return ApiResult<CloudOperation>.Fail("NOT_FOUND", "ACME 证书不存在。");
        if (state.Stage == "Revoked") return ApiResult<CloudOperation>.Ok(new("", "Revoked"));
        if (state.Stage == "RevokeSubmitting") return ApiResult<CloudOperation>.Fail("OutcomeUnknown", "原证书吊销结果未知，不能重复提交，请核对 CA 状态。");
        var session = await ReadSessionAsync(account, state, ct);
        var material = await materials.GetAsync(state.Id, ct);
        if (!session.Success || session.Data is null) return ApiResult<CloudOperation>.Fail(session.Code, session.Message);
        if (!material.Success || material.Data is null || material.Data.CertificatePem == "") return ApiResult<CloudOperation>.Fail("CERTIFICATE_MATERIAL_MISSING", "缺少原始证书材料，无法吊销。");
        using var certificate = X509Certificate2.CreateFromPem(material.Data.CertificatePem);
        state.Stage = "RevokeSubmitting"; await SaveAsync(state, ct);
        var revoked = await api.PostAsync(session.Data.Directory, session.Data.Directory.RevokeCertificate, session.Data.PrivateKeyPem, session.Data.AccountUrl,
            new { certificate = AcmeProtocolClient.Encode(certificate.RawData), reason = 0 }, ct);
        if (!revoked.Success && revoked.Code != "ACME_ALREADY_REVOKED")
        {
            if (revoked.Code != "OutcomeUnknown") { state.Stage = "Issued"; await SaveAsync(state, ct); }
            return ApiResult<CloudOperation>.Fail(revoked.Code, revoked.Message);
        }
        state.Stage = "Revoked"; await SaveAsync(state, ct);
        return ApiResult<CloudOperation>.Ok(new("", "Revoked"));
    }

    public async Task<ApiResult<CloudOperation>> DeleteAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
    {
        var state = await FindStateAsync(account.Id, reference, ct);
        if (state is null) return ApiResult<CloudOperation>.Ok(new("", "Deleted"));
        if (state.Stage != "Revoked")
        {
            var material = await materials.GetAsync(state.Id, ct);
            if (!material.Success || material.Data is null || material.Data.CertificatePem == "")
                return ApiResult<CloudOperation>.Fail("INVALID_STATE", "仅已过期或已吊销 ACME 证书可以删除。");
            using var certificate = X509Certificate2.CreateFromPem(material.Data.CertificatePem);
            if (certificate.NotAfter.ToUniversalTime() > DateTime.UtcNow) return ApiResult<CloudOperation>.Fail("INVALID_STATE", "ACME 证书尚未过期或吊销。");
        }
        // ACME 没有云端“删除证书”接口；归档台账避免下次同步重新加入，原密文保留以便审计和备份恢复。
        state.Stage = "Deleted"; await SaveAsync(state, ct);
        return ApiResult<CloudOperation>.Ok(new("", "Deleted"));
    }

    private async Task<ApiResult<CloudCertificateDetail>> ReadOrderAsync(CertificateIssuanceState state, Session session, JsonElement order, CancellationToken ct)
    {
        if (order.ValueKind != JsonValueKind.Object || !order.TryGetProperty("identifiers", out var identifiers) || identifiers.ValueKind != JsonValueKind.Array || identifiers.GetArrayLength() != 1 ||
            Text(identifiers[0], "type") != "dns" || !Text(identifiers[0], "value").Equals(state.Domain, StringComparison.OrdinalIgnoreCase))
            return ApiResult<CloudCertificateDetail>.Fail("ACME_IDENTITY_MISMATCH", "CA 返回的订单域名与本轮申请不一致。");
        var raw = Text(order, "status");
        var finalize = Text(order, "finalize"); var certificateUrl = Text(order, "certificate");
        if (finalize != "" && !AcmeProtocolClient.IsAllowedResource(session.Directory.Url, finalize) ||
            certificateUrl != "" && !AcmeProtocolClient.IsAllowedResource(session.Directory.Url, certificateUrl))
            return ApiResult<CloudCertificateDetail>.Fail("ACME_UNSAFE_RESOURCE", "订单包含不受信任的签发或下载地址。");
        state.FinalizeUrl = finalize; state.CertificateUrl = certificateUrl;
        var previous = ReadAuthorizations(state);
        var authorizations = new List<AcmeAuthorizationState>();
        if (raw is "pending" or "ready")
        {
            if (!order.TryGetProperty("authorizations", out var urls) || urls.ValueKind != JsonValueKind.Array || urls.GetArrayLength() is 0 or > 8)
                return ApiResult<CloudCertificateDetail>.Fail("ACME_AUTHORIZATION_MISSING", "订单缺少有效的域名授权。");
            foreach (var urlItem in urls.EnumerateArray())
            {
                var url = urlItem.ValueKind == JsonValueKind.String ? urlItem.GetString() ?? "" : "";
                if (!AcmeProtocolClient.IsAllowedResource(session.Directory.Url, url)) return ApiResult<CloudCertificateDetail>.Fail("ACME_UNSAFE_RESOURCE", "域名授权地址不受信任。");
                var resource = await api.PostAsync(session.Directory, url, session.PrivateKeyPem, session.AccountUrl, null, ct);
                if (!resource.Success || resource.Data is null) return ApiResult<CloudCertificateDetail>.Fail(resource.Code, resource.Message);
                var authorization = resource.Data.Json;
                if (authorization.ValueKind != JsonValueKind.Object || !authorization.TryGetProperty("identifier", out var identifier) || Text(identifier, "type") != "dns" ||
                    !Text(identifier, "value").Equals(state.Domain, StringComparison.OrdinalIgnoreCase) ||
                    authorization.TryGetProperty("wildcard", out var wildcard) && wildcard.ValueKind == JsonValueKind.True)
                    return ApiResult<CloudCertificateDetail>.Fail("ACME_IDENTITY_MISMATCH", "域名授权与申请域名不一致。");
                var authStatus = Text(authorization, "status");
                if (authStatus == "valid") continue;
                if (authStatus is "invalid" or "expired" or "revoked" or "deactivated") raw = "invalid";
                if (!authorization.TryGetProperty("challenges", out var challenges) || challenges.ValueKind != JsonValueKind.Array)
                    return ApiResult<CloudCertificateDetail>.Fail("ACME_DNS_CHALLENGE_MISSING", "CA 未提供 DNS-01 挑战。");
                var dns = challenges.EnumerateArray().FirstOrDefault(x => Text(x, "type") == "dns-01");
                var challengeUrl = Text(dns, "url"); var token = Text(dns, "token");
                if (!AcmeProtocolClient.IsAllowedResource(session.Directory.Url, challengeUrl) || token.Length is < 16 or > 512 ||
                    token.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')))
                    return ApiResult<CloudCertificateDetail>.Fail("ACME_DNS_CHALLENGE_INVALID", "CA 返回的 DNS-01 挑战格式无效。");
                authorizations.Add(new(url, challengeUrl, token, state.Domain, Text(dns, "status"), previous.Any(x => x.ChallengeUrl == challengeUrl && x.NotificationSubmitted)));
            }
            state.AuthorizationsJson = JsonSerializer.Serialize(authorizations);
        }
        var status = raw switch { "pending" => "PendingValidation", "ready" or "processing" or "valid" => "Processing", "invalid" => "Failed", _ => "Unknown" };
        if (raw == "valid")
        {
            var material = await materials.GetAsync(state.Id, ct);
            if (material.Success && material.Data?.CertificatePem.Length > 0) status = "Issued";
        }
        if (state.Stage != "FinalizeSubmitting" || raw != "ready") state.Stage = raw switch { "valid" when status == "Issued" => "Issued", "ready" => "Ready", "processing" => "Processing", "invalid" => "Failed", _ => status };
        await SaveAsync(state, ct);
        var thumbprint = AcmeProtocolClient.Thumbprint(session.PrivateKeyPem);
        var dnsChallenges = authorizations.Where(x => x.Status is "pending" or "processing").Select(x => new DnsChallenge(x.Domain,
            "_acme-challenge." + x.Domain, "TXT", AcmeProtocolClient.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(x.Token + "." + thumbprint))))).ToArray();
        return ApiResult<CloudCertificateDetail>.Ok(new(await CertificateAsync(state, status, raw, dnsChallenges, ct), dnsChallenges,
            status == "Failed" ? "ACME 域名验证失败，请检查 TXT、CAA 与权威 DNS 后重新创建申请。" : null));
    }

    private async Task<CloudCertificate> CertificateAsync(CertificateIssuanceState state, string status, string raw, IReadOnlyList<DnsChallenge> challenges, CancellationToken ct)
    {
        DateTimeOffset? before = null, after = null; var hasKey = false;
        var material = await materials.GetAsync(state.Id, ct);
        if (material.Success && material.Data?.CertificatePem.Length > 0)
        {
            using var certificate = X509Certificate2.CreateFromPem(material.Data.CertificatePem);
            before = certificate.NotBefore.ToUniversalTime(); after = certificate.NotAfter.ToUniversalTime(); hasKey = true;
            if (status == "Issued" && after <= DateTimeOffset.UtcNow) status = "Expired";
        }
        var local = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(x => x.Id == state.Id, ct);
        return new(Reference(state), state.Domain, local?.Alias ?? "", status, raw, true, "LetsEncrypt", before, after,
            local?.ValidationMode ?? "ManagedDns", "", hasKey, state.IsStaging);
    }

    private async Task<ApiResult<Session>> ValidateImportedAccountAsync(CloudAccountCredentials credentials, CancellationToken ct)
    {
        if (!AcmeProtocolClient.IsValidAccountKey(credentials.AccessKeySecret))
            return ApiResult<Session>.Fail("ACME_ACCOUNT_KEY_INVALID", "请提供用户自行准备的既有 ACME 账户 PEM 私钥；不接受网站密码或 API token。");
        if (!AcmeProtocolClient.IsAllowedDirectory(credentials.AcmeDirectoryUrl) ||
            !AcmeProtocolClient.IsAllowedResource(credentials.AcmeDirectoryUrl, credentials.AccessKeyId) ||
            !new Uri(credentials.AccessKeyId).AbsolutePath.StartsWith("/acme/acct/", StringComparison.Ordinal))
            return ApiResult<Session>.Fail("ACME_ACCOUNT_URL_INVALID", "既有 ACME 账户 URL 必须属于所选 Let’s Encrypt 目录。");
        var directory = await api.DirectoryAsync(credentials.AcmeDirectoryUrl, ct);
        if (!directory.Success || directory.Data is null) return ApiResult<Session>.Fail(directory.Code, directory.Message);
        // 唯一账号操作为 RFC 8555 POST-as-GET：不更新联系邮箱、条款、密钥或账户状态。
        var existing = await api.PostAsync(directory.Data, credentials.AccessKeyId, credentials.AccessKeySecret, credentials.AccessKeyId, null, ct);
        if (!existing.Success || existing.Data is null) return ApiResult<Session>.Fail(existing.Code, existing.Message);
        if (Text(existing.Data.Json, "status") != "valid")
            return ApiResult<Session>.Fail("ACME_ACCOUNT_NOT_VALID", "用户提供的既有 ACME 账户不可用，请自行处理账户状态后重新接入。");
        return ApiResult<Session>.Ok(new(directory.Data, credentials.AccessKeyId, credentials.AccessKeySecret));
    }

    private async Task<ApiResult<Session>> ReadSessionAsync(CloudAccountCredentials credentials, CertificateIssuanceState state, CancellationToken ct)
    {
        if (!AcmeProtocolClient.IsValidAccountKey(credentials.AccessKeySecret))
            return ApiResult<Session>.Fail("ACME_ACCOUNT_KEY_INVALID", "原 ACME 账户私钥不可用，请重新提供用户自行准备的原始凭据。");
        if (credentials.AccessKeyId != state.AcmeAccountUrl ||
            AcmeProtocolClient.Thumbprint(credentials.AccessKeySecret) != state.AccountKeyThumbprint ||
            credentials.AcmeDirectoryUrl != (state.IsStaging ? AcmeProtocolClient.StagingDirectory : AcmeProtocolClient.ProductionDirectory))
            return ApiResult<Session>.Fail("ACME_ACCOUNT_IDENTITY_CHANGED", "账户 URL、私钥或 CA 目录已变化，原订单只能使用最初导入的账户凭据恢复，系统不会替换或维护外部账户。");
        return await ValidateImportedAccountAsync(credentials, ct);
    }

    private async Task<CertificateIssuanceState?> FindStateAsync(string accountId, CloudCertificateReference reference, CancellationToken ct)
    {
        if (reference.ApiVersion != ApiVersion || reference.OrderId == "" && reference.CertificateId == "") return null;
        var state = await db.CertificateIssuanceStates.SingleOrDefaultAsync(x => x.AccountId == accountId && x.Provider == Provider &&
            (reference.OrderId != "" ? x.OrderUrl == reference.OrderId : x.RemoteCertificateId == reference.CertificateId), ct);
        // 同时提供订单和证书引用时必须指向同一台账，不能用任一字段匹配后取得另一张证书材料。
        return state is not null && reference.CertificateId != "" && state.RemoteCertificateId != reference.CertificateId ? null : state;
    }
    private static CloudCertificateReference Reference(CertificateIssuanceState state) => new(state.RemoteCertificateId, state.OrderUrl, "", ApiVersion);
    private static List<AcmeAuthorizationState> ReadAuthorizations(CertificateIssuanceState state) =>
        JsonSerializer.Deserialize<List<AcmeAuthorizationState>>(state.AuthorizationsJson) ?? [];
    private async Task SaveAsync(CertificateIssuanceState state, CancellationToken ct)
    { state.Revision++; state.UpdatedAtUtc = DateTime.UtcNow; await db.SaveChangesAsync(ct); }
    private static string Text(JsonElement value, string key) => value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var item) && item.ValueKind == JsonValueKind.String ? item.GetString() ?? "" : "";
}
