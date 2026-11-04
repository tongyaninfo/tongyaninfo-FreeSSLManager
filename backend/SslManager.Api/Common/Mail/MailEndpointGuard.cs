using System.Net;
using System.Net.Sockets;
using MailKit;
using MailKit.Security;
using Microsoft.Extensions.Options;
using SslManager.Api.Models.Mail;

namespace SslManager.Api.Common.Mail;

/// <summary>校验全部 DNS 结果后连接同一 IP，TLS 仍核验原主机名，避免 DNS 重绑定。</summary>
public class MailEndpointGuard(IOptions<MailEndpointOptions> options)
{
    public static SecureSocketOptions TlsOption(string security) => security switch
    {
        "SslOnConnect" => SecureSocketOptions.SslOnConnect,
        "StartTls" => SecureSocketOptions.StartTls,
        _ => throw new ArgumentException("必须使用 TLS 或强制 STARTTLS。")
    };

    public virtual async Task ConnectAsync(MailService client, MailTransportEndpoint endpoint, CancellationToken ct)
    {
        var security = TlsOption(endpoint.Security);
        if (endpoint.Port is < 1 or > 65535 || string.IsNullOrWhiteSpace(endpoint.Host)
            || endpoint.Host.Length > 253 || Uri.CheckHostName(endpoint.Host) == UriHostNameType.Unknown)
            throw new ArgumentException("SMTP 主机或端口无效。");
        var addresses = await Dns.GetHostAddressesAsync(endpoint.Host, ct);
        var allowPrivate = options.Value.AllowedPrivateHosts.Contains(endpoint.Host, StringComparer.OrdinalIgnoreCase);
        if (addresses.Length == 0 || addresses.Any(ip => IsForbidden(ip) || !allowPrivate && IsPrivate(ip)))
            throw new ArgumentException("SMTP 主机解析到未获允许的网络地址。");

        Exception? last = null;
        foreach (var address in addresses)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, endpoint.Port), ct);
                await client.ConnectAsync(socket, endpoint.Host, endpoint.Port, security, ct);
                return;
            }
            catch (SocketException ex) { last = ex; socket.Dispose(); }
            catch { socket.Dispose(); throw; }
        }
        throw last ?? new IOException("SMTP 主机无法连接。");
    }

    /// <summary>回环、未指定、链路本地、元数据和组播地址不允许作为 SMTP 目标。</summary>
    public static bool IsForbidden(IPAddress value)
    {
        var ip = value.IsIPv4MappedToIPv6 ? value.MapToIPv4() : value;
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)
            || ip.IsIPv6LinkLocal || ip.IsIPv6Multicast) return true;
        var bytes = ip.GetAddressBytes();
        return ip.AddressFamily == AddressFamily.InterNetwork
            && (bytes[0] is 0 or 127 || bytes[0] >= 224 || bytes[0] == 169 && bytes[1] == 254);
    }

    public static bool IsPrivate(IPAddress value)
    {
        var ip = value.IsIPv4MappedToIPv6 ? value.MapToIPv4() : value;
        var bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetworkV6) return (bytes[0] & 0xfe) == 0xfc || ip.IsIPv6SiteLocal;
        return bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31
            || bytes[0] == 192 && bytes[1] == 168 || bytes[0] == 100 && bytes[1] is >= 64 and <= 127;
    }
}
