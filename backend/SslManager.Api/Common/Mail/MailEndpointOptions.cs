namespace SslManager.Api.Common.Mail;

/// <summary>企业内网 SMTP 须通过 Mail:AllowedPrivateHosts 精确配置获准主机名。</summary>
public sealed class MailEndpointOptions
{
    public string[] AllowedPrivateHosts { get; set; } = [];
}
