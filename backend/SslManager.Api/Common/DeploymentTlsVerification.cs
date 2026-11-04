using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using SslManager.Api.Models;

namespace SslManager.Api.Common;

/// <summary>业务 TLS 验证独立于管理端信任例外，连接地址和 SNI 分别指定。</summary>
public static class DeploymentTlsVerification
{
    public static async Task<ApiResult<bool>> VerifyAsync(DeploymentTargetConfiguration config,
        CertificateMaterialMetadata material, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(config.ConnectionTimeoutSeconds, 5, 120)));
        try
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(config.VerificationHost, config.VerificationPort, timeout.Token);
            using var tls = new SslStream(tcp.GetStream(), false);
            var name = string.IsNullOrWhiteSpace(config.VerificationServerName) ? material.Domain : config.VerificationServerName;
            await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = name, EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.Online
            }, timeout.Token);
            if (tls.RemoteCertificate is null)
                return ApiResult<bool>.Fail("VERIFICATION_FAILED", "服务未返回 TLS 证书。");
            using var certificate = new X509Certificate2(tls.RemoteCertificate);
            return certificate.GetCertHashString(HashAlgorithmName.SHA256) == material.Fingerprint
                ? ApiResult<bool>.Ok(true)
                : ApiResult<bool>.Fail("VERIFICATION_FAILED", "服务实际返回的证书指纹与本次部署不一致。");
        }
        catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException or OperationCanceledException)
        {
            return ApiResult<bool>.Fail("VERIFICATION_FAILED", "平台或文件可能已更新，但业务 TLS 生效检查未通过，请核对服务。");
        }
    }
}
