using System.Net;

namespace SslManager.Api.Common;

/// <summary>部署平台的 HTTPS 管理连接；允许在旧证书失效时继续登录并更新证书。</summary>
public static class DeploymentManagementHttpClient
{
    public static HttpClient Create() => new(new HttpClientHandler
    {
        AllowAutoRedirect = false,
        UseCookies = true,
        CookieContainer = new CookieContainer(),
        // 群晖、雷池管理接口默认忽略自签名、过期和域名不匹配等证书错误。
        // 只作用于调用此工厂的管理客户端，业务端点的 TLS 生效检查仍独立严格校验。
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    });
}
