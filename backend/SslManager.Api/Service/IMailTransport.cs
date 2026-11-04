using SslManager.Api.Models.Mail;

namespace SslManager.Api.Service;

/// <summary>SMTP 协议端口；权限、凭据加解密与发件记录归应用服务管理。</summary>
public interface IMailTransport
{
    Task<MailTransportProbeResult> ProbeAsync(MailTransportEndpoint endpoint, CancellationToken ct);
    Task<MailTransportResult> SendAsync(MailTransportEndpoint endpoint, MailTransportMessage message, CancellationToken ct);
}
