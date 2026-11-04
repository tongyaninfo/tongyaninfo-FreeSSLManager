using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SslManager.Api.Common;

namespace SslManager.Tests;

public sealed class DeploymentMaterialTests
{
    [Fact]
    public void ReadsActualSansAndDoesNotSerializePrivateKey()
    {
        using var key = RSA.Create(2048);
        using var cert = Create(key, "one.example.com", "two.example.com");
        var result = CertificateMaterialHelper.FromArchive(Package(cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem()),
            "certificate", "one.example.com");
        Assert.True(result.Success);
        Assert.Equal(new[] { "one.example.com", "two.example.com" }, result.Data!.Metadata.Domains);
        Assert.DoesNotContain("PRIVATE KEY", JsonSerializer.Serialize(result.Data));
        Assert.DoesNotContain("PRIVATE KEY", result.Data.ToString());
    }

    [Fact]
    public void RejectsWrongDomainAndMismatchedKey()
    {
        using var key = RSA.Create(2048);
        using var otherKey = RSA.Create(2048);
        using var cert = Create(key, "one.example.com");
        var domain = CertificateMaterialHelper.FromArchive(Package(cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem()),
            "certificate", "other.example.com");
        Assert.Equal("DOMAIN_MISMATCH", domain.Code);
        var mismatch = CertificateMaterialHelper.FromArchive(Package(cert.ExportCertificatePem(), otherKey.ExportPkcs8PrivateKeyPem()),
            "certificate", "one.example.com");
        Assert.False(mismatch.Success);
    }

    [Fact]
    public void RejectsArchiveTraversalAndAmbiguousMaterial()
    {
        using var key = RSA.Create(2048);
        using var second = RSA.Create(2048);
        using var cert = Create(key, "one.example.com");
        using var secondCert = Create(second, "two.example.com");
        Assert.False(CertificateMaterialHelper.FromArchive(Package(cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem(), "../key"),
            "certificate", "one.example.com").Success);
        Assert.False(CertificateMaterialHelper.FromPem(new[] { cert.ExportCertificatePem(), secondCert.ExportCertificatePem() },
            new[] { key.ExportPkcs8PrivateKeyPem(), second.ExportPkcs8PrivateKeyPem() }, "certificate", "one.example.com").Success);
    }

    [Fact]
    public void WildcardDoesNotCoverApexOrNestedSubdomain()
    {
        using var key = RSA.Create(2048);
        using var cert = Create(key, "*.example.com");
        Assert.True(CertificateMaterialHelper.CoversDomains(cert.ExportCertificatePem(), new[] { "one.example.com" }));
        Assert.False(CertificateMaterialHelper.CoversDomains(cert.ExportCertificatePem(), new[] { "example.com" }));
        Assert.False(CertificateMaterialHelper.CoversDomains(cert.ExportCertificatePem(), new[] { "one.two.example.com" }));
        Assert.False(CertificateMaterialHelper.CoversDomains(cert.ExportCertificatePem(), []));
        var read = CertificateMaterialHelper.FromPem([cert.ExportCertificatePem()],
            [key.ExportPkcs8PrivateKeyPem(), key.ExportRSAPrivateKeyPem()], "certificate", "*.example.com");
        Assert.True(read.Success);
    }

    private static X509Certificate2 Create(RSA key, params string[] domains)
    {
        var request = new CertificateRequest("CN=" + domains[0], key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var sans = new SubjectAlternativeNameBuilder();
        foreach (var domain in domains) sans.AddDnsName(domain);
        request.CertificateExtensions.Add(sans.Build());
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }
    private static byte[] Package(string cert, string key, string keyPath = "privkey.pem")
    {
        using var stream = new MemoryStream();
        using (var archive = new ZipArchive(stream, ZipArchiveMode.Create, true))
        {
            using (var writer = new StreamWriter(archive.CreateEntry("fullchain.pem").Open(), Encoding.UTF8)) writer.Write(cert);
            using (var writer = new StreamWriter(archive.CreateEntry(keyPath).Open(), Encoding.UTF8)) writer.Write(key);
        }
        return stream.ToArray();
    }
}
