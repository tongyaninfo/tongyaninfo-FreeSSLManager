using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using SslManager.Api.Models;

namespace SslManager.Api.Common;

/// <summary>从受限证书包提取唯一匹配的证书私钥，公共结果不包含材料正文。</summary>
public static class CertificateMaterialHelper
{
    public static ApiResult<CertificateMaterial> FromArchive(byte[] bytes, string id, string expectedDomain)
    {
        var archiveCheck = CertificateDownloadHelper.ValidateZip(bytes);
        if (!archiveCheck.Success) return ApiResult<CertificateMaterial>.Fail(archiveCheck.Code, archiveCheck.Message);
        try
        {
            using var input = new MemoryStream(bytes);
            using var archive = new ZipArchive(input, ZipArchiveMode.Read);
            var certificates = new List<string>();
            var keys = new List<string>();
            foreach (var entry in archive.Entries)
            {
                if (entry.Length == 0) continue;
                using var reader = new StreamReader(entry.Open(), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
                var text = reader.ReadToEnd();
                foreach (Match match in Regex.Matches(text, @"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----"))
                    if (!certificates.Contains(match.Value)) certificates.Add(match.Value);
                foreach (Match match in Regex.Matches(text, @"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----"))
                    if (!keys.Contains(match.Value)) keys.Add(match.Value);
            }
            return FromPem(certificates, keys, id, expectedDomain);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or CryptographicException or ArgumentException)
        {
            return Invalid("证书包解析失败，未读取到有效的证书和私钥。");
        }
    }

    public static ApiResult<CertificateMaterial> FromPem(IReadOnlyList<string> certificatePems,
        IReadOnlyList<string> privateKeys, string id, string expectedDomain)
    {
        var parsed = new List<X509Certificate2>();
        X509Certificate2? leaf = null;
        try
        {
            foreach (var pem in certificatePems)
            {
                var items = new X509Certificate2Collection();
                items.ImportFromPem(pem);
                foreach (var item in items)
                {
                    if (parsed.Any(existing => existing.RawData.AsSpan().SequenceEqual(item.RawData))) item.Dispose();
                    else parsed.Add(item);
                }
            }
            string keyPem = "";
            foreach (var cert in parsed)
            foreach (var key in privateKeys)
            {
                X509Certificate2 candidate;
                try { candidate = X509Certificate2.CreateFromPem(cert.ExportCertificatePem(), key); }
                catch (Exception ex) when (ex is CryptographicException or ArgumentException) { continue; }
                if (leaf is not null)
                {
                    if (candidate.RawData.AsSpan().SequenceEqual(leaf.RawData))
                    {
                        candidate.Dispose();
                        continue; // 同一私钥的 PKCS1/PKCS8 重复副本不构成多组材料。
                    }
                    candidate.Dispose();
                    return Invalid("证书包包含多组证书和私钥，无法确定本次部署材料。");
                }
                leaf = candidate;
                keyPem = key.Trim() + "\n";
            }
            if (leaf is null) return Invalid("未找到匹配的证书和私钥，或私钥不可导出。");
            var now = DateTime.UtcNow;
            if (leaf.NotBefore.ToUniversalTime() > now || leaf.NotAfter.ToUniversalTime() <= now)
                return ApiResult<CertificateMaterial>.Fail("CERTIFICATE_NOT_VALID", "证书尚未生效或已经过期。");
            var names = leaf.Extensions.OfType<X509SubjectAlternativeNameExtension>()
                .SelectMany(extension => extension.EnumerateDnsNames()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            if (names.Length == 0) return Invalid("证书没有可用于部署的 DNS SAN。");
            if (!string.IsNullOrWhiteSpace(expectedDomain) &&
                !(expectedDomain.StartsWith("*.", StringComparison.Ordinal)
                    ? names.Contains(expectedDomain.TrimEnd('.'), StringComparer.OrdinalIgnoreCase)
                    : leaf.MatchesHostname(expectedDomain.TrimEnd('.'), allowWildcards: true, allowCommonName: false)))
                return ApiResult<CertificateMaterial>.Fail("DOMAIN_MISMATCH", "实际证书 SAN 不覆盖当前证书记录的域名。");

            // 按签发关系排列链，去掉不相关证书，避免直接拼接 ZIP 中的任意文件。
            var chain = new List<X509Certificate2>();
            var current = leaf;
            while (!current.SubjectName.RawData.AsSpan().SequenceEqual(current.IssuerName.RawData))
            {
                var issuer = parsed.FirstOrDefault(item =>
                    item.SubjectName.RawData.AsSpan().SequenceEqual(current.IssuerName.RawData) &&
                    !item.RawData.AsSpan().SequenceEqual(leaf.RawData) &&
                    !chain.Any(existing => existing.RawData.AsSpan().SequenceEqual(item.RawData)));
                if (issuer is null) break;
                chain.Add(issuer);
                current = issuer;
                if (chain.Count > 16) return Invalid("证书链长度异常。");
            }
            using (var validation = new X509Chain())
            {
                validation.ChainPolicy.ExtraStore.AddRange(parsed.ToArray());
                validation.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                validation.ChainPolicy.DisableCertificateDownloads = true;
                validation.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                validation.Build(leaf);
                var allowed = X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain;
                if (validation.ChainStatus.Any(status => (status.Status & ~allowed) != 0))
                    return Invalid("证书链签名、有效期或约束校验未通过。");
                chain.Clear();
                foreach (var element in validation.ChainElements.Cast<X509ChainElement>().Skip(1))
                {
                    var supplied = parsed.FirstOrDefault(item => item.RawData.AsSpan().SequenceEqual(element.Certificate.RawData));
                    if (supplied is not null) chain.Add(supplied);
                }
            }
            var certificatePem = leaf.ExportCertificatePem() + "\n";
            var chainPem = string.Join("", chain.Select(cert => cert.ExportCertificatePem() + "\n"));
            var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(certificatePem + chainPem)));
            var metadata = new CertificateMaterialMetadata(id,
                string.IsNullOrWhiteSpace(expectedDomain) ? names[0] : expectedDomain, names,
                leaf.GetCertHashString(HashAlgorithmName.SHA256), digest,
                leaf.NotBefore.ToUniversalTime(), leaf.NotAfter.ToUniversalTime());
            return ApiResult<CertificateMaterial>.Ok(new CertificateMaterial
            {
                Metadata = metadata, CertificatePem = certificatePem, ChainPem = chainPem,
                FullChainPem = certificatePem + chainPem, PrivateKeyPem = keyPem
            });
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            return Invalid("证书或私钥格式无效。");
        }
        finally
        {
            leaf?.Dispose();
            foreach (var item in parsed) item.Dispose();
        }
    }

    public static bool CoversDomains(string certificatePem, IEnumerable<string> domains)
    {
        try
        {
            var requested = domains.ToArray();
            if (requested.Length == 0) return false;
            using var certificate = X509Certificate2.CreateFromPem(certificatePem);
            return requested.All(domain => !string.IsNullOrWhiteSpace(domain) &&
                (domain.StartsWith("*.", StringComparison.Ordinal)
                    ? certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>()
                        .SelectMany(item => item.EnumerateDnsNames())
                        .Contains(domain.TrimEnd('.'), StringComparer.OrdinalIgnoreCase)
                    : certificate.MatchesHostname(domain.TrimEnd('.'), allowWildcards: true, allowCommonName: false)));
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException) { return false; }
    }

    private static ApiResult<CertificateMaterial> Invalid(string message) =>
        ApiResult<CertificateMaterial>.Fail("CERTIFICATE_MATERIAL_INVALID", message);
}
