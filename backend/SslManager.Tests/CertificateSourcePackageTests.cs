using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Security;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Tests;

/// <summary>源包测试核对实际文件字节、格式身份和秘密隔离，不访问云端或写入密钥文件。</summary>
public sealed class CertificateSourcePackageTests
{
    [Fact]
    public void NginxKeepsRealNamesDuplicateBundleRepresentationsAndOriginalBytes()
    {
        using var fixture = new Fixture();
        var bundle = Utf8("\uFEFF" + fixture.Material.FullChainPem.Replace("\n", "\r\n"));
        var key = Utf8(fixture.Key.ExportRSAPrivateKeyPem());
        var result = CertificateSourcePackageHelper.FromArchive(Archive(
            ("one.example.test_nginx/one.example.test_bundle.crt", bundle),
            ("one.example.test_nginx/one.example.test_bundle.pem", bundle),
            ("one.example.test_nginx/one.example.test.key", key),
            ("one.example.test_nginx/request.csr", Utf8("public certificate request"))), "nginx", fixture.Material.Metadata);
        Assert.True(result.Success, result.Message);
        Assert.Equal(4, result.Data!.Files.Count);
        Assert.Equal(2, result.Data.Files.Count(file => file.Role == "FullChain"));
        Assert.Equal(bundle, result.Data.Files.First(file => file.Role == "FullChain").Content);
        var privateKey = Assert.Single(result.Data.Files, file => file.Role == "PrivateKey");
        Assert.Equal(key, privateKey.Content);
        Assert.True(privateKey.ContainsSecrets);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(key)), privateKey.Sha256);
        var serialized = JsonSerializer.Serialize(result.Data);
        Assert.DoesNotContain("Content", serialized);
        Assert.DoesNotContain(Convert.ToBase64String(key), serialized);
        Assert.DoesNotContain("PRIVATE KEY", privateKey.ToString());
    }

    [Fact]
    public void ApacheClassifiesLeafChainAndPrivateKeyFromActualFiles()
    {
        using var fixture = new Fixture();
        var result = CertificateSourcePackageHelper.FromArchive(Archive(
            ("apache/one.example.test.crt", Utf8(fixture.Material.CertificatePem)),
            ("apache/root_bundle.crt", Utf8(fixture.Material.ChainPem)),
            ("apache/one.example.test.key", Utf8(fixture.Material.PrivateKeyPem))), "apache", fixture.Material.Metadata);
        Assert.True(result.Success, result.Message);
        Assert.Equal(new[] { "Chain", "Leaf", "PrivateKey" }, result.Data!.Files.Select(file => file.Role).Order().ToArray());
    }

    [Theory]
    [InlineData("iis", "certificate.pfx")]
    [InlineData("tomcat", "certificate.pfx")]
    [InlineData("tomcat", "certificate.keystore")]
    public void PfxSourcesPreserveOriginalContainerAndPasswordWithoutConversion(string format, string fileName)
    {
        using var fixture = new Fixture();
        const string password = "source-password-35";
        var container = fixture.Pfx(password);
        var passwordBytes = Utf8(password + "\r\n");
        var result = CertificateSourcePackageHelper.FromArchive(Archive(
            (format + "/" + fileName, container), (format + "/keystorePass.txt", passwordBytes)), format, fixture.Material.Metadata);
        Assert.True(result.Success, result.Message);
        Assert.Equal(container, result.Data!.Files.Single(file => file.Role == "Pfx").Content);
        Assert.Equal(passwordBytes, result.Data.Files.Single(file => file.Role == "Password").Content);
        Assert.All(result.Data.Files, file => Assert.True(file.ContainsSecrets));
        Assert.DoesNotContain(password, JsonSerializer.Serialize(result.Data));
    }

    [Fact]
    public void PfxWithWrongPasswordOrDifferentIdentityIsRejected()
    {
        using var fixture = new Fixture();
        using var other = new Fixture();
        var source = Archive(("cert.pfx", fixture.Pfx("correct-password")), ("keystorePass.txt", Utf8("wrong-password")));
        Assert.False(CertificateSourcePackageHelper.FromArchive(source, "iis", fixture.Material.Metadata).Success);
        var wrongIdentity = Archive(("cert.pfx", other.Pfx("source-password")), ("keystorePass.txt", Utf8("source-password")));
        Assert.False(CertificateSourcePackageHelper.FromArchive(wrongIdentity, "tomcat", fixture.Material.Metadata).Success);
    }

    [Fact]
    public void EmptyPasswordPfxFromAliyunIsAcceptedWithoutInventingAPasswordFile()
    {
        using var fixture = new Fixture();
        var result = CertificateSourcePackageHelper.FromArchive(Archive(("certificate.pfx", fixture.Pfx(""))), "iis", fixture.Material.Metadata);
        Assert.True(result.Success, result.Message);
        Assert.Equal("Pfx", Assert.Single(result.Data!.Files).Role);
    }

    [Fact]
    public void DifferentPemPrivateKeyOrMissingChainCannotMasqueradeAsCurrentSource()
    {
        using var fixture = new Fixture();
        using var other = new Fixture();
        var wrongKey = Archive(("fullchain.pem", Utf8(fixture.Material.FullChainPem)), ("private.key", Utf8(other.Material.PrivateKeyPem)));
        Assert.Equal("SOURCE_CERTIFICATE_MISMATCH", CertificateSourcePackageHelper.FromArchive(wrongKey, "nginx", fixture.Material.Metadata).Code);
        var noChain = Archive(("certificate.crt", Utf8(fixture.Material.CertificatePem)), ("private.key", Utf8(fixture.Material.PrivateKeyPem)));
        Assert.Equal("SOURCE_CERTIFICATE_MISMATCH", CertificateSourcePackageHelper.FromArchive(noChain, "nginx", fixture.Material.Metadata).Code);
        var malformedKey = Archive(("fullchain.pem", Utf8(fixture.Material.FullChainPem)), ("private.key", Utf8("not a private key")));
        Assert.False(CertificateSourcePackageHelper.FromArchive(malformedKey, "nginx", fixture.Material.Metadata).Success);
    }

    [Theory]
    [InlineData("../private.key")]
    [InlineData("/private.key")]
    [InlineData("folder\u0000/private.key")]
    public void UnsafeSourcePathsAreRejected(string name)
    {
        using var fixture = new Fixture();
        Assert.False(CertificateSourcePackageHelper.FromArchive(Archive((name, Utf8(fixture.Material.PrivateKeyPem))), "nginx", fixture.Material.Metadata).Success);
    }

    [Fact]
    public void DuplicateNamesAndPackagesWithoutCertificateAreRejected()
    {
        using var fixture = new Fixture();
        var duplicate = Archive(("same.pem", Utf8(fixture.Material.FullChainPem)), ("same.pem", Utf8(fixture.Material.FullChainPem)));
        Assert.False(CertificateSourcePackageHelper.FromArchive(duplicate, "nginx", fixture.Material.Metadata).Success);
        Assert.False(CertificateSourcePackageHelper.FromArchive(Archive(("README.txt", Utf8("no certificate"))), "nginx", fixture.Material.Metadata).Success);
        Assert.Equal("SOURCE_FORMAT_UNSUPPORTED", CertificateSourcePackageHelper.FromArchive(duplicate, "unrecognized", fixture.Material.Metadata).Code);
    }

    [Fact]
    public void JksChecksPrivateKeyPublicChainAndPasswordIntegrityWithoutReencodingTheContainer()
    {
        using var fixture = new Fixture();
        const string password = "source-store-password";
        var jks = Jks(fixture, password);
        var source = Archive(("certificate.jks", jks), ("keystorePass.txt", Utf8(password)));
        var result = CertificateSourcePackageHelper.FromArchive(source, "tomcat", fixture.Material.Metadata);
        Assert.True(result.Success, result.Message);
        Assert.Equal(jks, result.Data!.Files.Single(file => file.Role == "Jks").Content);
        jks[^1] ^= 1;
        Assert.False(CertificateSourcePackageHelper.FromArchive(Archive(("certificate.jks", jks),
            ("keystorePass.txt", Utf8(password))), "tomcat", fixture.Material.Metadata).Success);
        using var wrongKey = RSA.Create(2048);
        Assert.False(CertificateSourcePackageHelper.FromArchive(Archive(("certificate.jks", Jks(fixture, password, wrongKey)),
            ("keystorePass.txt", Utf8(password))), "tomcat", fixture.Material.Metadata).Success);
    }

    private static byte[] Utf8(string value) => Encoding.UTF8.GetBytes(value);
    private static byte[] Archive(params (string Name, byte[] Content)[] files)
    {
        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var file in files)
            {
                using var entry = zip.CreateEntry(file.Name).Open();
                entry.Write(file.Content);
            }
        return output.ToArray();
    }

    // 使用库生成真实加密的 JKS 测试材料，全程内存，不依赖 Java 安装或临时私钥文件。
    private static byte[] Jks(Fixture fixture, string password, RSA? privateKey = null)
    {
        var store = new JksStore();
        var parser = new Org.BouncyCastle.X509.X509CertificateParser();
        var chars = password.ToCharArray();
        store.SetKeyEntry("source-key", PrivateKeyFactory.CreateKey((privateKey ?? fixture.Key).ExportPkcs8PrivateKey()), chars,
            new[] { parser.ReadCertificate(fixture.Certificate.RawData), parser.ReadCertificate(fixture.Authority.RawData) });
        using var data = new MemoryStream();
        store.Save(data, chars);
        Array.Clear(chars);
        return data.ToArray();
    }

    private sealed class Fixture : IDisposable
    {
        private readonly RSA authorityKey = RSA.Create(2048);
        public RSA Key { get; } = RSA.Create(2048);
        public X509Certificate2 Authority { get; }
        public X509Certificate2 Certificate { get; }
        public CertificateMaterial Material { get; }
        public Fixture()
        {
            var authority = new CertificateRequest("CN=Source Test CA", authorityKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            authority.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            authority.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign, true));
            Authority = authority.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
            var request = new CertificateRequest("CN=one.example.test", Key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var sans = new SubjectAlternativeNameBuilder(); sans.AddDnsName("one.example.test");
            request.CertificateExtensions.Add(sans.Build());
            using var issued = request.Create(Authority, DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(30), RandomNumberGenerator.GetBytes(16));
            Certificate = issued.CopyWithPrivateKey(Key);
            Material = CertificateMaterialHelper.FromPem([Certificate.ExportCertificatePem(), Authority.ExportCertificatePem()],
                [Key.ExportPkcs8PrivateKeyPem()], "source-certificate", "one.example.test").Data!;
        }
        public byte[] Pfx(string password) => new X509Certificate2Collection(new[] { Certificate, Authority }).Export(X509ContentType.Pkcs12, password)!;
        public void Dispose() { Certificate.Dispose(); Authority.Dispose(); Key.Dispose(); authorityKey.Dispose(); }
    }
}
