using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using ModelContextProtocol.AspNetCore;
using ModelContextProtocol.Protocol;
using OpenIddict.Abstractions;
using SslManager.Api.Data;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Api.Common.Mcp;

/// <summary>官方 MCP SDK 和同进程 OAuth 注册入口，未配置材料时不实例化 OAuth 服务器。</summary>
public static class McpIntegration
{
    public const string AuthenticationScheme = "McpBearer";
    public const string Policy = "McpClient";

    public static IServiceCollection AddSslManagerMcp(this IServiceCollection services, IConfiguration configuration, bool desktop)
    {
        // 业务调用使用专用脱敏账本，协议/认证框架不在普通日志输出请求或令牌响应。
        services.AddLogging(logging => logging.AddFilter("OpenIddict", LogLevel.Warning).AddFilter("ModelContextProtocol", LogLevel.Warning));
        var issuer = configuration["Mcp:OAuth:Issuer"]?.TrimEnd('/') ?? "";
        if (McpNetwork.ValidHttpsOrigin(issuer)) issuer = McpNetwork.NormalizeOrigin(issuer);
        var certificatePath = configuration["Mcp:OAuth:CertificatePath"];
        var certificatePemPath = configuration["Mcp:OAuth:CertificatePemPath"];
        var privateKeyPemPath = configuration["Mcp:OAuth:PrivateKeyPemPath"];
        X509Certificate2? certificate = null;
        if (!desktop && McpNetwork.ValidHttpsOrigin(issuer) && (!string.IsNullOrWhiteSpace(certificatePath)
            || !string.IsNullOrWhiteSpace(certificatePemPath) && !string.IsNullOrWhiteSpace(privateKeyPemPath)))
        {
            try
            {
                certificate = !string.IsNullOrWhiteSpace(certificatePemPath) && !string.IsNullOrWhiteSpace(privateKeyPemPath)
                    ? X509Certificate2.CreateFromPemFile(certificatePemPath, privateKeyPemPath)
                    : X509CertificateLoader.LoadPkcs12FromFile(certificatePath!, configuration["Mcp:OAuth:CertificatePassword"], X509KeyStorageFlags.EphemeralKeySet);
                using var privateKey = certificate.GetRSAPrivateKey();
                if (!certificate.HasPrivateKey || privateKey is null || privateKey.KeySize < 2048
                    || certificate.NotAfter.ToUniversalTime() <= DateTime.UtcNow || certificate.NotBefore.ToUniversalTime() > DateTime.UtcNow)
                { certificate.Dispose(); certificate = null; }
            }
            catch (Exception exception) when (exception is IOException or System.Security.Cryptography.CryptographicException or UnauthorizedAccessException or PlatformNotSupportedException or ArgumentException)
            { certificate?.Dispose(); certificate = null; }
        }
        var runtime = new McpRuntimeOptions(!desktop, certificate is not null,
            desktop ? "桌面实例不支持外部 MCP。" : "OAuth 尚未就绪；请通过受控配置引用有效 RSA 证书及 HTTPS issuer，然后重启后端。未自动生成密钥。", issuer)
        {
            TrustedProxyRanges = (configuration.GetSection("Mcp:TrustedProxyAddresses").Get<string[]>() ?? [])
                .Concat(configuration.GetSection("Mcp:TrustedProxyNetworks").Get<string[]>() ?? []).ToArray()
        };
        services.AddSingleton(runtime);
        services.AddScoped<IMcpConfigurationService, McpConfigurationService>();
        services.AddScoped<IMcpClientService, McpClientService>();
        services.AddScoped<IMcpApiKeyService, McpApiKeyService>();
        services.AddScoped<IMcpAuthorizationService, McpAuthorizationService>();
        services.AddScoped<IMcpInvocationLogService, McpInvocationLogService>();
        services.AddHttpContextAccessor();
        services.AddSingleton<McpRequestLimiter>();
        services.AddAuthentication().AddScheme<AuthenticationSchemeOptions, McpBearerHandler>(AuthenticationScheme, _ => { });
        services.AddAuthorization(options => options.AddPolicy(Policy, policy => policy.AddAuthenticationSchemes(AuthenticationScheme).RequireAuthenticatedUser()));
        var oauth = services.AddOpenIddict().AddCore(options =>
        {
            options.UseEntityFrameworkCore().UseDbContext<AppDbContext>()
                .ReplaceDefaultEntities<McpOAuthApplication, McpOAuthAuthorization, McpOAuthScope, McpOAuthToken, string>();
            options.DisableEntityCaching();
        });
        if (certificate is not null)
        {
            oauth.AddServer(options =>
            {
                options.SetIssuer(new Uri(issuer + "/"));
                options.SetAuthorizationEndpointUris("/oauth/mcp/authorize").SetTokenEndpointUris("/oauth/mcp/token")
                    .SetRevocationEndpointUris("/oauth/mcp/revoke");
                options.AllowAuthorizationCodeFlow().AllowRefreshTokenFlow().AllowClientCredentialsFlow();
                options.RequireProofKeyForCodeExchange();
                options.RegisterScopes("mcp.read", "mcp.write", OpenIddictConstants.Scopes.OfflineAccess);
                options.RegisterResources(issuer + "/mcp");
                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(15)).SetRefreshTokenLifetime(TimeSpan.FromDays(7));
                options.SetRefreshTokenReuseLeeway(TimeSpan.Zero);
                options.UseReferenceAccessTokens().UseReferenceRefreshTokens();
                options.AddSigningCertificate(certificate).AddEncryptionCertificate(certificate);
                options.UseDataProtection();
                options.UseAspNetCore().EnableAuthorizationEndpointPassthrough().EnableTokenEndpointPassthrough();
                options.Configure(value =>
                {
                    value.CodeChallengeMethods.Clear();
                    value.CodeChallengeMethods.Add(OpenIddictConstants.CodeChallengeMethods.Sha256);
                });
            }).AddValidation(options =>
            {
                options.UseLocalServer(); options.UseAspNetCore(); options.UseDataProtection();
                options.AddAudiences(issuer + "/mcp");
                options.EnableTokenEntryValidation(); options.EnableAuthorizationEntryValidation();
            });
        }
        services.AddMcpServer(options =>
        {
            options.ServerInfo = new Implementation { Name = "free-ssl-manager", Version = ApplicationVersion.Current };
            options.Capabilities = new ServerCapabilities { Tools = new ToolsCapability { ListChanged = false } };
        }).WithHttpTransport(options =>
        {
            options.SessionMode = HttpServerSessionMode.StatefulForInitializeClients;
            options.ConfigureSessionOptions = async (context, sessionOptions, ct) =>
            {
                var settings = await context.RequestServices.GetRequiredService<AppDbContext>().McpSettings.AsNoTracking()
                    .SingleOrDefaultAsync(ct);
                var instance = McpInstanceIdentity.From(settings);
                sessionOptions.ServerInfo = instance.ServerInfo;
                sessionOptions.ServerInstructions = instance.Instructions;
            };
        }).WithListToolsHandler(McpProtocolHandlers.ListAsync).WithCallToolHandler(McpProtocolHandlers.CallAsync);
        return services;
    }

    /// <summary>放在 UseRouting 后、UseAuthentication 前；仅处理 MCP/OAuth 的运行边界。</summary>
    public static IApplicationBuilder UseSslManagerMcpBoundary(this IApplicationBuilder app) =>
        app.UseMiddleware<McpAuditMiddleware>().UseMiddleware<McpBoundaryMiddleware>();

    public static IEndpointRouteBuilder MapSslManagerMcp(this IEndpointRouteBuilder app)
    {
        app.MapMcp("/mcp").RequireAuthorization(Policy);
        app.MapGet("/.well-known/oauth-protected-resource/mcp", async (AppDbContext db, McpRuntimeOptions runtime, CancellationToken ct) =>
        {
            var settings = await Microsoft.EntityFrameworkCore.EntityFrameworkQueryableExtensions.SingleOrDefaultAsync(db.McpSettings, ct);
            var address = settings is null ? "" : runtime.OAuthBaseUrl(settings.PublicBaseUrl);
            if (address.Length == 0) return Results.NotFound();
            return Results.Json(new { resource = address + "/mcp", authorization_servers = new[] { address + "/" },
                scopes_supported = new[] { "mcp.read", "mcp.write" }, bearer_methods_supported = new[] { "header" } });
        }).AllowAnonymous();
        return app;
    }
}
