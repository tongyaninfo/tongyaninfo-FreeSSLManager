using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Tests;

/// <summary>验证域名复用及续签源包文件重定位边界，不连接数据库、云平台或部署目标。</summary>
public sealed class DeploymentSourceBindingTests
{
    [Theory]
    [InlineData("EXAMPLE.COM.", "example.com", true)]
    [InlineData(" example.com ", "EXAMPLE.COM.", true)]
    [InlineData("example.com", "other.example.com", false)]
    [InlineData("*.example.com", "example.com", false)]
    public void DomainBindingUsesExactNormalizedDomainAcrossCertificateIds(string configuredDomain, string currentDomain, bool expected)
    {
        var configuration = new DeploymentTargetConfiguration { SourceDomain = configuredDomain, SourceCertificateId = "old-id" };

        Assert.Equal(expected, DeploymentSourceBinding.Matches(configuration, Metadata("renewed-id", currentDomain)));
    }

    [Theory]
    [InlineData("old-id", true)]
    [InlineData("new-id", false)]
    public void HistoricalSnapshotsWithoutDomainRetainExactCertificateIdBinding(string certificateId, bool expected)
    {
        var configuration = new DeploymentTargetConfiguration { SourceCertificateId = "old-id" };

        Assert.Equal(expected, DeploymentSourceBinding.Matches(configuration, Metadata(certificateId, "example.com")));
    }

    [Fact]
    public void ExactSourcePathWinsOverOtherFilesWithTheSameBasename()
    {
        var exact = File("original/certificate.pem", "FullChain");
        var package = new CertificateSourcePackage("nginx", [exact, File("another/certificate.pem", "FullChain")]);

        var result = DeploymentSourceBinding.ResolveSourceFile(package,
            new("FullChain", "stable.pem", "/ssl", "original/certificate.pem"));

        Assert.True(result.Success, result.Message);
        Assert.Same(exact, result.Data);
    }

    [Fact]
    public void ExistingSourcePathWithChangedRoleCannotSelectAnotherFileInstead()
    {
        var package = new CertificateSourcePackage("nginx",
            [File("original/certificate.pem", "PrivateKey"), File("another/certificate.pem", "FullChain")]);

        var result = DeploymentSourceBinding.ResolveSourceFile(package,
            new("FullChain", "stable.pem", "/ssl", "original/certificate.pem"));

        Assert.Equal("SOURCE_FILE_CHANGED", result.Code);
        Assert.Null(result.Data);
    }

    private static CertificateMaterialMetadata Metadata(string certificateId, string domain) => new(certificateId, domain,
        [domain], "fingerprint", "digest", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30));
    private static CertificateSourceFile File(string name, string role) => new(name, role, [], "empty-content-digest", false);
}
