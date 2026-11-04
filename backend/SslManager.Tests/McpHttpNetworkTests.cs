using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.Extensions.DependencyInjection;
using SslManager.Api.Common.Mcp;

namespace SslManager.Tests;

/// <summary>真实转发头中间件与受限HTTP验源，不使用网络、真实凭据或数据库。</summary>
public sealed class McpHttpNetworkTests
{
    [Theory]
    [InlineData("10.1.2.3", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("172.31.255.254", true)]
    [InlineData("192.168.1.1", true)]
    [InlineData("127.8.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("::ffff:192.168.1.1", true)]
    [InlineData("fd12:3456::1", true)]
    [InlineData("fc00::1", true)]
    [InlineData("172.32.0.1", false)]
    [InlineData("169.254.1.1", false)]
    [InlineData("fe80::1", false)]
    [InlineData("100.64.1.1", false)]
    [InlineData("203.0.113.1", false)]
    [InlineData("8.8.8.8", false)]
    [InlineData("2001:4860::1", false)]
    public void HttpPrivateAddressClassificationIsNarrow(string address, bool expected) => Assert.Equal(expected, McpNetwork.IsPrivateAddress(address));

    [Theory]
    [InlineData("http://192.168.1.10:8080", true)]
    [InlineData("http://[fd12:3456::1]:8080", true)]
    [InlineData("http://localhost", true)]
    [InlineData("http://ssl.internal.example", true)]
    [InlineData("https://203.0.113.1", true)]
    [InlineData("http://203.0.113.1", false)]
    [InlineData("http://169.254.1.1", false)]
    [InlineData("http://user:password@192.168.1.1", false)]
    [InlineData("http://localhost/path", false)]
    [InlineData("http://localhost/?token=synthetic", false)]
    [InlineData("http://localhost/#fragment", false)]
    public void ServiceOriginValidationKeepsPathsAndCredentialsOut(string origin, bool expected)
    { Assert.Equal(expected, McpNetwork.ValidBaseUrl(origin)); Assert.Equal(origin.StartsWith("https://"), McpNetwork.ValidHttpsOrigin(origin)); }

    [Theory]
    [InlineData("https://ssl.example.test", "http", "ssl.example.test", true)]
    [InlineData("http://ssl.example.test", "https", "ssl.example.test", true)]
    [InlineData("http://ssl.example.test:8080", "https", "ssl.example.test:8080", true)]
    [InlineData("http://ssl.example.test:8080", "https", "ssl.example.test:8443", false)]
    [InlineData("http://ssl.example.test:8080", "http", "ssl.example.test:8443", false)]
    [InlineData("https://ssl.example.test", "https", "attacker.test", false)]
    [InlineData("https://ssl.example.test", "https", "ssl.example.test:8443", false)]
    [InlineData("https://203.0.113.8", "http", "203.0.113.8", false)]
    public void ServiceHostAndPortRemainBounded(string configured, string scheme, string host, bool expected)
    {
        var context = new DefaultHttpContext(); context.Request.Scheme = scheme; context.Request.Host = new(host);
        Assert.Equal(expected, McpNetwork.MatchesServiceAddress(context.Request, configured, new(true, false, "isolated")));
    }

    [Theory]
    [InlineData("http", "192.168.1.20:5080", true)]
    [InlineData("https", "ssl.example.test", true)]
    [InlineData("https", "third.example.test", false)]
    [InlineData("https", "ssl.example.test:8443", false)]
    [InlineData("http", "ssl.example.test", false)]
    [InlineData("http", "192.168.1.20:5081", false)]
    public void SeparatePrivatePrimaryAndHttpsIssuerAreTheOnlyExplicitHosts(string scheme, string host, bool expected)
    {
        var context = new DefaultHttpContext(); context.Request.Scheme = scheme; context.Request.Host = new(host);
        foreach (var oauthReady in new[] { false, true })
            Assert.Equal(expected, McpNetwork.MatchesServiceAddress(context.Request, "http://192.168.1.20:5080", new(true, oauthReady, "isolated", "https://ssl.example.test")));
    }

    [Theory]
    [InlineData("192.168.10.2", "192.168.10.8", null, true)]
    [InlineData("192.168.10.2", "203.0.113.9", null, false)]
    [InlineData("192.168.10.2", null, null, false)]
    [InlineData("192.168.10.2", "garbage", null, false)]
    [InlineData("192.168.10.2", "192.168.10.8, 10.0.0.2", null, true)]
    [InlineData("192.168.10.2", "192.168.10.8, 203.0.113.9", null, false)]
    [InlineData("192.168.10.2", "192.168.10.8, 10.0.0.2, 10.0.0.3", null, false)]
    [InlineData("203.0.113.2", "192.168.10.8", "https", false)]
    [InlineData("192.168.20.2", "192.168.10.8", "https", false)]
    public async Task HttpProxyMustFullyRestorePrivateSourceAndUntrustedHeadersCannotBypass(string peer, string? forwardedFor, string? forwardedProto, bool expected)
    {
        var services = new ServiceCollection(); services.AddLogging();
        services.Configure<ForwardedHeadersOptions>(options =>
        {
            options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
            options.ForwardLimit = 2; options.KnownProxies.Clear(); options.KnownIPNetworks.Clear();
            options.KnownProxies.Add(IPAddress.Parse("192.168.10.2")); options.KnownProxies.Add(IPAddress.Parse("10.0.0.2"));
        });
        await using var provider = services.BuildServiceProvider();
        var app = new ApplicationBuilder(provider); var actual = false;
        var runtime = new McpRuntimeOptions(true, false, "isolated") { TrustedProxyRanges = ["192.168.10.2", "10.0.0.2"] };
        app.UseForwardedHeaders();
        app.Run(http => { actual = McpNetwork.VerifiedPrivateHttpSource(http, runtime, out _); return Task.CompletedTask; });
        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Scheme = "http"; context.Connection.RemoteIpAddress = IPAddress.Parse(peer);
        if (forwardedFor is not null) context.Request.Headers["X-Forwarded-For"] = forwardedFor;
        if (forwardedProto is not null) context.Request.Headers["X-Forwarded-Proto"] = forwardedProto;
        context.Items["McpActualRemoteIp"] = peer;
        context.Items["McpOriginalForwardedFor"] = context.Request.Headers["X-Forwarded-For"].ToArray();
        await app.Build()(context);
        Assert.Equal(expected, actual);
    }
}
