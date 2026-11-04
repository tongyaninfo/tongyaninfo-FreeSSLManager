using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using SslManager.Api.Models;

namespace SslManager.Api.Common;

/// <summary>校验源格式包身份并保留真实文件字节；密码、私钥及密钥库仅在内存中处理。</summary>
public static class CertificateSourcePackageHelper
{
    public static ApiResult<CertificateSourcePackage> FromArchive(byte[] bytes, string format, CertificateMaterialMetadata expected)
    {
        format = format.Trim().ToLowerInvariant();
        if (format is not ("nginx" or "apache" or "iis" or "tomcat"))
            return ApiResult<CertificateSourcePackage>.Fail("SOURCE_FORMAT_UNSUPPORTED", "请选择 Nginx、Apache、IIS 或 Tomcat 源格式。");
        var check = CertificateDownloadHelper.ValidateZip(bytes);
        if (!check.Success) return ApiResult<CertificateSourcePackage>.Fail(check.Code, check.Message);
        var certificates = new List<X509Certificate2>();
        try
        {
            using var input = new MemoryStream(bytes, writable: false);
            using var archive = new ZipArchive(input, ZipArchiveMode.Read);
            var files = new List<CertificateSourceFile>();
            var keys = new List<string>();
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var entry in archive.Entries)
            {
                var name = entry.FullName.Replace('\\', '/');
                if (name.Length > 1024 || name.Any(char.IsControl) || !names.Add(name)) return Invalid("源证书包包含无效或重复的文件路径。");
                if (name.EndsWith('/')) continue;
                if (string.IsNullOrEmpty(name) || name.Split('/').Any(string.IsNullOrEmpty)) return Invalid("源证书文件路径无效。");
                using var source = entry.Open();
                using var output = new MemoryStream();
                source.CopyTo(output);
                var content = output.ToArray();
                var text = Encoding.UTF8.GetString(content);
                var pems = Regex.Matches(text, @"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----");
                var privateKeys = Regex.Matches(text, @"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----");
                var fileCertificates = new List<X509Certificate2>();
                foreach (Match pem in pems)
                {
                    var certificate = X509Certificate2.CreateFromPem(pem.Value);
                    certificates.Add(certificate);
                    fileCertificates.Add(certificate);
                }
                foreach (Match key in privateKeys) if (!keys.Contains(key.Value)) keys.Add(key.Value);
                var extension = Path.GetExtension(name).ToLowerInvariant();
                if (extension == ".key" && privateKeys.Count == 0)
                    return Invalid("源包中的私钥文件格式无法核对。");
                var role = privateKeys.Count > 0 ? "PrivateKey"
                    : fileCertificates.Any(cert => cert.GetCertHashString(HashAlgorithmName.SHA256) == expected.Fingerprint)
                        ? fileCertificates.Count > 1 ? "FullChain" : "Leaf"
                    : fileCertificates.Count > 0 ? "Chain"
                    : extension is ".pfx" or ".p12" ? "Pfx"
                    : extension is ".jks" or ".keystore" ? "Jks"
                    : IsPasswordFile(name) ? "Password" : "Auxiliary";
                // 无法识别的附加文件可能含密码或配置凭据，使用保守权限，但不会在响应中发送正文。
                files.Add(new(name, role, content, Convert.ToHexString(SHA256.HashData(content)),
                    role is "PrivateKey" or "Pfx" or "Jks" or "Password" or "Auxiliary"));
            }
            if (files.Count == 0) return Invalid("源格式包不包含可部署文件。");
            var matched = false;
            if (certificates.Count > 0)
            {
                if (keys.Count > 0)
                {
                    var normalized = CertificateMaterialHelper.FromPem(certificates.Select(cert => cert.ExportCertificatePem()).ToArray(),
                        keys, expected.CertificateId, expected.Domain);
                    if (!normalized.Success || normalized.Data?.Metadata.Fingerprint != expected.Fingerprint ||
                        normalized.Data?.Metadata.MaterialDigest != expected.MaterialDigest)
                        return Mismatch();
                }
                else if (!PublicMaterialMatches(certificates, expected)) return Mismatch();
                matched = true;
            }
            var passwords = files.Where(file => file.Role == "Password" && file.Content.Length <= 4096)
                .Select(file => Encoding.UTF8.GetString(file.Content).Trim('\uFEFF', '\r', '\n', ' ', '\t'))
                .Append("").Distinct(StringComparer.Ordinal).Take(16).ToArray();
            foreach (var file in files.Where(file => file.Role is "Pfx" or "Jks").ToArray())
            {
                // 部分 Tomcat 包使用 PFX，部分 .keystore 也使用 PKCS#12；以字节格式识别，不伪造转换。
                var jks = file.Content.Length >= 4 && BinaryPrimitives.ReadUInt32BigEndian(file.Content) == 0xFEEDFEED;
                var valid = jks ? JksMatches(file.Content, passwords, expected) : PfxMatches(file.Content, passwords, expected);
                if (!valid) return Invalid("源密钥库无法使用配套密码核对，或其证书及完整链与当前证书不一致。");
                var detectedRole = jks ? "Jks" : "Pfx";
                if (file.Role != detectedRole)
                {
                    var index = files.IndexOf(file);
                    files[index] = file with { Role = detectedRole };
                }
                matched = true;
            }
            if (!matched) return Invalid("源格式包中未找到与当前证书一致的证书或密钥库。");
            return ApiResult<CertificateSourcePackage>.Ok(new(format, files.OrderBy(file => file.Name, StringComparer.Ordinal).ToArray()));
        }
        catch (Exception exception) when (exception is IOException or InvalidDataException or CryptographicException or
            ArgumentException or OverflowException or CryptoException or SecurityUtilityException or InvalidCastException)
        {
            return Invalid("源证书包内容无法解析或证书材料校验未通过。");
        }
        finally
        {
            foreach (var certificate in certificates) certificate.Dispose();
        }
    }

    private static bool IsPasswordFile(string name)
    {
        var file = Path.GetFileName(name);
        return file.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) && file.Contains("pass", StringComparison.OrdinalIgnoreCase);
    }

    private static bool PfxMatches(byte[] content, string[] passwords, CertificateMaterialMetadata expected)
    {
        foreach (var password in passwords)
        {
            var chars = password.ToCharArray();
            try
            {
                // 复用现有 SSH.NET 依赖的托管解析器；macOS 不支持 PFX EphemeralKeySet，不能降级写入钥匙串。
                var store = new Pkcs12StoreBuilder().Build();
                using var input = new MemoryStream(content, writable: false);
                store.Load(input, chars);
                if (store.Count > 64) return false;
                foreach (var alias in store.Aliases.Where(store.IsKeyEntry))
                {
                    var chain = store.GetCertificateChain(alias)?.Select(entry => entry.Certificate).ToArray();
                    if (StoreEntryMatches(chain, store.GetKey(alias)?.Key, expected)) return true;
                }
            }
            catch (Exception exception) when (exception is IOException or CryptographicException or ArgumentException or
                InvalidOperationException or CryptoException or SecurityUtilityException or InvalidCastException) { }
            finally { Array.Clear(chars); }
        }
        return false;
    }

    private static bool StoreEntryMatches(Org.BouncyCastle.X509.X509Certificate[]? sourceChain,
        AsymmetricKeyParameter? privateKey, CertificateMaterialMetadata expected)
    {
        if (sourceChain is not { Length: > 0 and <= 17 } || privateKey?.IsPrivate != true ||
            Convert.ToHexString(SHA256.HashData(sourceChain[0].GetEncoded())) != expected.Fingerprint) return false;
        var algorithm = privateKey switch { RsaKeyParameters => "SHA256withRSA", ECPrivateKeyParameters => "SHA256withECDSA", _ => "" };
        if (string.IsNullOrEmpty(algorithm)) return false;
        var challenge = RandomNumberGenerator.GetBytes(32);
        var signer = SignerUtilities.GetSigner(algorithm);
        signer.Init(true, privateKey);
        signer.BlockUpdate(challenge, 0, challenge.Length);
        var signature = signer.GenerateSignature();
        var verifier = SignerUtilities.GetSigner(algorithm);
        verifier.Init(false, sourceChain[0].GetPublicKey());
        verifier.BlockUpdate(challenge, 0, challenge.Length);
        if (!verifier.VerifySignature(signature)) return false;
        var certificates = new List<X509Certificate2>();
        try
        {
            foreach (var certificate in sourceChain) certificates.Add(X509CertificateLoader.LoadCertificate(certificate.GetEncoded()));
            return PublicMaterialMatches(certificates, expected);
        }
        finally { foreach (var certificate in certificates) certificate.Dispose(); }
    }

    private static bool PublicMaterialMatches(IReadOnlyList<X509Certificate2> certificates, CertificateMaterialMetadata expected)
    {
        var leaf = certificates.FirstOrDefault(cert => cert.GetCertHashString(HashAlgorithmName.SHA256) == expected.Fingerprint);
        if (leaf is null) return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.ExtraStore.AddRange(certificates.ToArray());
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        chain.Build(leaf);
        var allowed = X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.PartialChain;
        if (chain.ChainStatus.Any(status => (status.Status & ~allowed) != 0)) return false;
        var pem = leaf.ExportCertificatePem() + "\n";
        foreach (var element in chain.ChainElements.Cast<X509ChainElement>().Skip(1))
            if (certificates.Any(cert => cert.RawData.AsSpan().SequenceEqual(element.Certificate.RawData)))
                pem += element.Certificate.ExportCertificatePem() + "\n";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(pem))) == expected.MaterialDigest;
    }

    /// <summary>托管解析 JKS 并验证配套密码、私钥与完整链；只保留原包字节，不重新生成密钥库。</summary>
    private static bool JksMatches(byte[] content, string[] passwords, CertificateMaterialMetadata expected)
    {
        foreach (var password in passwords)
        {
            var chars = password.ToCharArray();
            try
            {
                var store = new JksStore();
                using var input = new MemoryStream(content, writable: false);
                store.Load(input, chars);
                if (store.Count > 64) return false;
                foreach (var alias in store.Aliases.Where(store.IsKeyEntry))
                {
                    if (StoreEntryMatches(store.GetCertificateChain(alias), store.GetKey(alias, chars), expected)) return true;
                }
            }
            catch (Exception exception) when (exception is IOException or CryptographicException or ArgumentException or
                CryptoException or SecurityUtilityException or InvalidCastException) { }
            finally { Array.Clear(chars); }
        }
        return false;
    }

    private static ApiResult<CertificateSourcePackage> Invalid(string message) =>
        ApiResult<CertificateSourcePackage>.Fail("CERTIFICATE_SOURCE_INVALID", message);
    private static ApiResult<CertificateSourcePackage> Mismatch() =>
        ApiResult<CertificateSourcePackage>.Fail("SOURCE_CERTIFICATE_MISMATCH", "源格式包的证书、完整链或私钥与当前部署材料不一致。");
}
