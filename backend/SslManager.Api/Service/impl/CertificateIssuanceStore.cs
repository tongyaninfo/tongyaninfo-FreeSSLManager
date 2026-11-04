using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>先落库本地私钥及 CSR，再允许任何远端申请，避免签发成功后丢失配套私钥。</summary>
public sealed class CertificateIssuanceStore(AppDbContext db, IDataProtectionProvider protection) : ICertificateIssuanceStore
{
    private IDataProtector Protector(string id) => protection.CreateProtector("SslManager.CertificateIssuance.v1", id);

    public async Task<ApiResult<CertificateIssuancePayload>> GetOrCreateAsync(string localId, string provider, string domain, string accountId, CancellationToken ct = default)
    {
        var row = await db.CertificateIssuanceStates.SingleOrDefaultAsync(x => x.Id == localId, ct);
        if (row is not null)
        {
            if (row.Provider != provider || row.Domain != domain || row.AccountId != accountId)
                return ApiResult<CertificateIssuancePayload>.Fail("ISSUANCE_IDENTITY_MISMATCH", "签发台账与当前账号或域名不一致。");
            return Read(row);
        }
        if (string.IsNullOrWhiteSpace(localId) || string.IsNullOrWhiteSpace(accountId) || !CloudJson.Domain(domain))
            return ApiResult<CertificateIssuancePayload>.Fail("INVALID_ISSUANCE_CONTEXT", "本地证书 ID、账号或域名无效。");
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(new X500DistinguishedName("CN=" + domain), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder();
        names.AddDnsName(domain);
        request.CertificateExtensions.Add(names.Build());
        var payload = new ProtectedIssuancePayload(key.ExportPkcs8PrivateKeyPem(), request.CreateSigningRequestPem());
        row = new() { Id = localId, AccountId = accountId, Provider = provider, Domain = domain, Stage = "Prepared",
            ProtectedPayload = Protector(localId).Protect(JsonSerializer.Serialize(payload)), CreatedAtUtc = DateTime.UtcNow, UpdatedAtUtc = DateTime.UtcNow };
        db.CertificateIssuanceStates.Add(row);
        await db.SaveChangesAsync(ct);
        return Read(row);
    }

    public async Task<ApiResult<CertificateIssuancePayload>> GetAsync(string localId, CancellationToken ct = default)
    {
        var row = await db.CertificateIssuanceStates.SingleOrDefaultAsync(x => x.Id == localId, ct);
        return row is null ? ApiResult<CertificateIssuancePayload>.Fail("CERTIFICATE_MATERIAL_MISSING", "本实例没有保存此证书的私钥材料。") : Read(row);
    }

    public async Task<ApiResult<bool>> SetStageAsync(string localId, string stage, CancellationToken ct = default)
    {
        var row = await db.CertificateIssuanceStates.SingleOrDefaultAsync(x => x.Id == localId, ct);
        if (row is null) return ApiResult<bool>.Fail("ISSUANCE_NOT_FOUND", "签发台账不存在。");
        row.Stage = stage; row.Revision++; row.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        return ApiResult<bool>.Ok(true);
    }

    public async Task<ApiResult<bool>> StoreIssuedAsync(string localId, string certificatePem, string chainPem, string remoteCertificateId, CancellationToken ct = default)
    {
        var row = await db.CertificateIssuanceStates.SingleOrDefaultAsync(x => x.Id == localId, ct);
        if (row is null) return ApiResult<bool>.Fail("ISSUANCE_NOT_FOUND", "签发台账不存在。");
        var material = Read(row);
        if (!material.Success || material.Data is null) return ApiResult<bool>.Fail(material.Code, material.Message);
        // 独立校验 SAN、有效期和密钥配对，不把仅有云端元数据误认为完整可部署材料。
        var validated = CertificateMaterialHelper.FromPem([certificatePem, chainPem], [material.Data.PrivateKeyPem], localId, row.Domain);
        if (!validated.Success) return ApiResult<bool>.Fail(validated.Code, validated.Message);
        var payload = new ProtectedIssuancePayload(material.Data.PrivateKeyPem, material.Data.CsrPem, certificatePem, chainPem);
        row.ProtectedPayload = Protector(localId).Protect(JsonSerializer.Serialize(payload));
        row.RemoteCertificateId = remoteCertificateId; row.Stage = "Issued"; row.Revision++; row.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        return ApiResult<bool>.Ok(true);
    }

    private ApiResult<CertificateIssuancePayload> Read(CertificateIssuanceState row)
    {
        try
        {
            var payload = JsonSerializer.Deserialize<ProtectedIssuancePayload>(Protector(row.Id).Unprotect(row.ProtectedPayload));
            if (payload is null || string.IsNullOrEmpty(payload.PrivateKeyPem) || string.IsNullOrEmpty(payload.CsrPem))
                return ApiResult<CertificateIssuancePayload>.Fail("CERTIFICATE_MATERIAL_INVALID", "签发台账缺少原始私钥或 CSR。");
            return ApiResult<CertificateIssuancePayload>.Ok(new(payload.PrivateKeyPem, payload.CsrPem, payload.CertificatePem, payload.ChainPem, row.Stage, row.RemoteCertificateId));
        }
        catch (Exception ex) when (ex is CryptographicException or JsonException)
        { return ApiResult<CertificateIssuancePayload>.Fail("CERTIFICATE_MATERIAL_UNREADABLE", "证书私钥无法解密，请恢复原数据库配套密钥，不能生成替代私钥。"); }
    }
}
