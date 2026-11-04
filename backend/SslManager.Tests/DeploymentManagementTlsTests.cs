using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service.impl;

namespace SslManager.Tests;

/// <summary>真实回环 TLS 握手验证管理连接策略，不依赖模拟校验证书回调。</summary>
public sealed class DeploymentManagementTlsTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SafeLineManagementAcceptsUntrustedMismatchedAndExpiredCertificates(bool expired)
    {
        await using var server = await UntrustedManagementServer.StartAsync(expired);
        // 错误的历史指纹也不应阻止管理接口连接；该测试使用实际默认 HttpClient。
        var target = server.Target("ApiToken");
        var opened = await new SafeLineCe9ApiClient().OpenAsync(target, default);
        Assert.True(opened.Success, opened.Message);
        using var session = opened.Data!;
        Assert.Equal("9.3.9", session.ProductVersion);
        Assert.Equal(1, server.SafeLineReads);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SynologyManagementAcceptsUntrustedMismatchedAndExpiredCertificates(bool expired)
    {
        await using var server = await UntrustedManagementServer.StartAsync(expired);
        var opened = await new SynologyDsmApiClient().OpenAsync(server.Target("Password"), default);
        Assert.True(opened.Success, opened.Message);
        await using (var session = opened.Data!)
            Assert.Equal("DSM 7.4.1-90080 Update 1", session.ProductVersion);
        Assert.Equal(1, server.SynologyLogins);
        Assert.Equal(1, server.SynologyLogouts);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task BusinessTlsVerificationStillRejectsTheSameUntrustedEndpoint(bool expired)
    {
        await using var server = await UntrustedManagementServer.StartAsync(expired);
        var endpoint = new Uri(server.Endpoint);
        // 预期指纹与实际证书相同，也不能替代业务 HTTPS 的信任链和域名校验。
        var material = new CertificateMaterialMetadata("test-certificate", "unrelated.invalid", ["unrelated.invalid"],
            server.Certificate.GetCertHashString(HashAlgorithmName.SHA256), "unused", DateTime.UtcNow.AddDays(-5), DateTime.UtcNow.AddDays(1));
        var verified = await DeploymentTlsVerification.VerifyAsync(new()
        {
            VerificationHost = endpoint.Host, VerificationPort = endpoint.Port,
            VerificationServerName = "different.invalid", ConnectionTimeoutSeconds = 5
        }, material, default);
        Assert.False(verified.Success);
        Assert.Equal("VERIFICATION_FAILED", verified.Code);
    }

    private sealed class UntrustedManagementServer(WebApplication application, RSA key, X509Certificate2 certificate) : IAsyncDisposable
    {
        public string Endpoint { get; private set; } = "";
        public X509Certificate2 Certificate { get; } = certificate;
        public int SafeLineReads { get; private set; }
        public int SynologyLogins { get; private set; }
        public int SynologyLogouts { get; private set; }

        public DeploymentTargetContext Target(string authentication) => new()
        {
            Endpoint = Endpoint, Username = "local-admin", AuthenticationMode = authentication,
            TlsFingerprint = new string('0', 64),
            Credentials = new() { ApiToken = "local-test-token", Password = "local-test-password" },
            Configuration = new() { ConnectionTimeoutSeconds = 5, OperationTimeoutSeconds = 10 }
        };

        public static async Task<UntrustedManagementServer> StartAsync(bool expired)
        {
            var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=unrelated.invalid", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("unrelated.invalid");
            request.CertificateExtensions.Add(san.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new("1.3.6.1.5.5.7.3.1") }, true));
            var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-5), DateTimeOffset.UtcNow.AddDays(expired ? -1 : 1));
            var builder = WebApplication.CreateSlimBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(certificate)));
            var application = builder.Build();
            var server = new UntrustedManagementServer(application, key, certificate);
            application.MapGet("/api/open/system", (HttpContext context) =>
            {
                if (context.Request.Headers["X-SLCE-API-TOKEN"] != "local-test-token") return Results.Unauthorized();
                server.SafeLineReads++;
                return Results.Json(new { data = new { version = "9.3.9" } });
            });
            application.MapPost("/webapi/query.cgi", () => Results.Json(new
            {
                success = true, data = new Dictionary<string, object>
                {
                    ["SYNO.API.Auth"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 7 },
                    ["SYNO.Core.System"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 3, requestFormat = "JSON" },
                    ["SYNO.Core.Certificate"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 1, requestFormat = "JSON" },
                    ["SYNO.Core.Certificate.CRT"] = new { path = "entry.cgi", minVersion = 1, maxVersion = 1, requestFormat = "JSON" }
                }
            }));
            application.MapPost("/webapi/entry.cgi", async (HttpContext context) =>
            {
                var form = await context.Request.ReadFormAsync();
                if (form["api"] == "SYNO.API.Auth" && form["method"] == "login")
                {
                    if (form["account"] != "local-admin" || form["passwd"] != "local-test-password")
                        return Results.Json(new { success = false, error = new { code = 400 } });
                    server.SynologyLogins++;
                    return Results.Json(new { success = true, data = new { sid = "local-session", synotoken = "local-csrf" } });
                }
                if (form["_sid"] != "local-session" || context.Request.Headers["X-SYNO-TOKEN"] != "local-csrf")
                    return Results.Unauthorized();
                if (form["api"] == "SYNO.Core.System" && form["method"] == "info")
                    return Results.Json(new { success = true, data = new { firmware_ver = "DSM 7.4.1-90080 Update 1" } });
                if (form["api"] == "SYNO.API.Auth" && form["method"] == "logout")
                {
                    server.SynologyLogouts++;
                    return Results.Json(new { success = true });
                }
                return Results.Json(new { success = false, error = new { code = 103 } });
            });
            await application.StartAsync();
            server.Endpoint = application.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            return server;
        }

        public async ValueTask DisposeAsync()
        {
            await application.DisposeAsync();
            Certificate.Dispose();
            key.Dispose();
        }
    }
}
