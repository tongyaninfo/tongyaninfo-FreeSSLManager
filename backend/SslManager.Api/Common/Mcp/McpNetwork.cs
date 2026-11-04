using System.Net;

namespace SslManager.Api.Common.Mcp;

/// <summary>来源网络与业务域名按边界匹配，不读取客户端伪造的转发头。</summary>
public static class McpNetwork
{
    public static bool ValidCidr(string value) => IPNetwork.TryParse(value, out _) || IPAddress.TryParse(value, out _);
    public static bool Contains(IEnumerable<string> ranges, string address)
    {
        if (!IPAddress.TryParse(address, out var ip)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ranges.Any(value => IPNetwork.TryParse(value, out var network) ? network.Contains(ip)
            : IPAddress.TryParse(value, out var exact) && (exact.IsIPv4MappedToIPv6 ? exact.MapToIPv4() : exact).Equals(ip));
    }
    public static bool DomainMatches(string allowed, string actual)
    {
        allowed = NormalizeDomain(allowed); actual = NormalizeDomain(actual);
        return allowed.StartsWith("*.", StringComparison.Ordinal)
            ? actual.EndsWith(allowed[1..], StringComparison.Ordinal) && actual.Length > allowed.Length - 1
            : allowed == actual;
    }
    public static string NormalizeDomain(string value) => value.Trim().TrimEnd('.').ToLowerInvariant();
    public static bool ValidOrigin(string value) => TryOrigin(value, out var uri)
        && (uri.Scheme == "https" || uri.Scheme == "http" && (uri.HostNameType == UriHostNameType.Dns || IsPrivateAddress(uri.DnsSafeHost)));
    public static bool ValidBaseUrl(string value) => ValidOrigin(value);

    public static bool ValidHttpsOrigin(string value) => TryOrigin(value, out var uri) && uri.Scheme == "https";
    public static string NormalizeOrigin(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri)
        ? uri.GetComponents(UriComponents.SchemeAndServer, UriFormat.UriEscaped).TrimEnd('/') : "";
    public static bool SameHost(string first, string second) => Uri.TryCreate(first, UriKind.Absolute, out var left)
        && Uri.TryCreate(second, UriKind.Absolute, out var right) && HostsEqual(left.IdnHost, right.IdnHost);

    /// <summary>仅RFC1918、回环及IPv6 ULA可明文调用；链路本地、CGNAT、文档网段和公网不算受信任内网。</summary>
    public static bool IsPrivateAddress(string value)
    {
        if (!IPAddress.TryParse(value.Trim('[', ']'), out var ip)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return true;
        var bytes = ip.GetAddressBytes();
        return bytes.Length == 4 ? bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 || bytes[0] == 192 && bytes[1] == 168
            : (bytes[0] & 0xfe) == 0xfc;
    }

    /// <summary>主基址的标准80/443端口可配对；显式非标准端口只匹配自身，OAuth issuer作为另一个明确HTTPS入口。</summary>
    public static bool MatchesServiceAddress(HttpRequest request, string configured, McpRuntimeOptions runtime)
    {
        if (!ValidBaseUrl(configured) || !Uri.TryCreate(configured, UriKind.Absolute, out var address)) return false;
        // 内网IP主入口和HTTPS公开issuer可以不同主机；只接受这两个管理员明确配置的origin，不接受其他别名。
        if (request.IsHttps && ValidHttpsOrigin(runtime.Issuer) && MatchesExactAddress(request, runtime.Issuer)) return true;
        if (!request.IsHttps && !ValidOrigin("http://" + request.Host.Value)) return false;
        if (!HostsEqual(request.Host.Host, address.IdnHost)) return false;
        var port = request.Host.Port ?? (request.IsHttps ? 443 : 80);
        var expected = address.IsDefaultPort ? request.IsHttps ? 443 : 80 : address.Port;
        return port == expected;
    }
    public static bool MatchesExactAddress(HttpRequest request, string origin) => Uri.TryCreate(origin, UriKind.Absolute, out var address)
        && request.Scheme.Equals(address.Scheme, StringComparison.OrdinalIgnoreCase) && HostsEqual(request.Host.Host, address.IdnHost)
        && (request.Host.Port ?? (request.IsHttps ? 443 : 80)) == address.Port;

    /// <summary>私网代理不能替公网调用方“变成内网”；明文链必须完整消费至已核验源，任何无法还原的转发信息拒绝。</summary>
    public static bool VerifiedPrivateHttpSource(HttpContext context, McpRuntimeOptions runtime, out string code)
    {
        var source = context.Connection.RemoteIpAddress?.ToString() ?? "";
        var peer = context.Items.TryGetValue("McpActualRemoteIp", out var actual) ? actual?.ToString() ?? "" : source;
        code = "HTTP_PRIVATE_NETWORK_REQUIRED";
        if (!IsPrivateAddress(source) || !IsPrivateAddress(peer)) return false;
        var original = (context.Items.TryGetValue("McpOriginalForwardedFor", out var raw) && raw is string[] values ? values : context.Request.Headers["X-Forwarded-For"].ToArray())
            .Select(value => value ?? "").ToArray();
        code = "HTTP_SOURCE_UNVERIFIED";
        if (Contains(runtime.TrustedProxyRanges, peer))
        {
            if (original.Length != 1 || context.Request.Headers["X-Forwarded-For"].Count > 0) return false;
            var chain = original[0].Split(',').Select(value => value.Trim()).ToArray();
            if (chain.Length is < 1 or > 2 || !TryEndpointAddress(chain[0], out var first) || !IPAddress.TryParse(source, out var resolved)
                || !Equivalent(first, resolved)) return false;
            foreach (var middle in chain.Skip(1))
                if (!TryEndpointAddress(middle, out var proxy) || !Contains(runtime.TrustedProxyRanges, proxy.ToString())) return false;
        }
        else if (original.Length > 0 || context.Request.Headers.ContainsKey("X-Forwarded-Proto") || context.Request.Headers.ContainsKey("Forwarded")
            || context.Request.Headers.ContainsKey("X-Original-For")) return false;
        code = ""; return true;
    }

    private static bool TryOrigin(string value, out Uri uri)
    {
        uri = null!;
        return !string.IsNullOrWhiteSpace(value) && !value.Any(char.IsControl) && Uri.TryCreate(value, UriKind.Absolute, out uri!)
            && uri.Scheme is "http" or "https" && uri.Host.Length > 0 && uri.Port is >= 1 and <= 65535
            && string.IsNullOrEmpty(uri.UserInfo) && uri.AbsolutePath == "/" && uri.Query == "" && uri.Fragment == "";
    }
    private static bool HostsEqual(string first, string second) => string.Equals(first.Trim('[', ']').TrimEnd('.'), second.Trim('[', ']').TrimEnd('.'), StringComparison.OrdinalIgnoreCase);
    private static bool TryEndpointAddress(string value, out IPAddress address)
    {
        if (IPAddress.TryParse(value, out address!)) return true;
        if (IPEndPoint.TryParse(value, out var endpoint)) { address = endpoint.Address; return true; }
        address = IPAddress.None; return false;
    }
    private static bool Equivalent(IPAddress first, IPAddress second) => (first.IsIPv4MappedToIPv6 ? first.MapToIPv4() : first)
        .Equals(second.IsIPv4MappedToIPv6 ? second.MapToIPv4() : second);
}
