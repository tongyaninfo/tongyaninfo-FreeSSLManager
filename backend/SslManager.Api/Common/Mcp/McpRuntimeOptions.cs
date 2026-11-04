namespace SslManager.Api.Common.Mcp;

/// <summary>只描述启动时实际具备的能力；不自动创建生产密钥或绕过桌面实例边界。</summary>
public sealed record McpRuntimeOptions(bool Supported, bool OAuthReady, string Message, string Issuer = "")
{
    /// <summary>API Key 不依赖 OAuth 签名材料，桌面实例仍不对外提供服务。</summary>
    public bool ApiKeyReady => Supported;
    public string[] TrustedProxyRanges { get; init; } = [];
    /// <summary>OAuth资源独立绑定启动时HTTPS issuer，不能随HTTP主服务基址降级。</summary>
    public string OAuthBaseUrl(string serviceBaseUrl) => !OAuthReady ? "" : McpNetwork.ValidHttpsOrigin(Issuer) ? McpNetwork.NormalizeOrigin(Issuer)
        : McpNetwork.ValidHttpsOrigin(serviceBaseUrl) ? McpNetwork.NormalizeOrigin(serviceBaseUrl) : "";
}
