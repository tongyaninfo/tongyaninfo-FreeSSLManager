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
    public static bool ValidOrigin(string value) => Uri.TryCreate(value, UriKind.Absolute, out var uri)
        && uri.Scheme == "https" && string.IsNullOrEmpty(uri.UserInfo) && uri.AbsolutePath == "/" && uri.Query == "" && uri.Fragment == "";
    public static bool ValidBaseUrl(string value) => ValidOrigin(value);
}
