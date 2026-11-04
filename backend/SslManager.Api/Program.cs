using System.Security.Claims;
using System.Net;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;
using SslManager.Api.Service.impl.Deployment;
using SslManager.Api.Service.impl.Deployment.Executors;
using SslManager.Api.Service.impl.Deployment.Transports;
using SslManager.Api.Service.impl.Mail;
using SslManager.Api.Service.impl.Mcp;
using SslManager.Api.Common.Mail;
using SslManager.Api.Workers;

DesktopRuntime? desktop;
try { desktop = await DesktopRuntime.InitializeAsync(args); }
catch (Exception exception)
{
    var known = exception as DesktopStartupException;
    Console.Out.WriteLine(JsonSerializer.Serialize(new { type = "error", protocol = 1,
        code = known?.Code ?? "DESKTOP_INITIALIZATION_FAILED", message = known?.Message ?? "桌面后端初始化失败。" }, new JsonSerializerOptions(JsonSerializerDefaults.Web)));
    Environment.ExitCode = 1; return;
}
var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args.Where(value => value != "--desktop").ToArray(),
    ContentRootPath = desktop is null ? null : AppContext.BaseDirectory,
    WebRootPath = desktop?.WebRootDirectory
});
if (desktop is not null)
{
    // 安装目录只读；所有业务数据都使用 Electron 显式传入的独立用户目录。
    builder.Configuration["ConnectionStrings:Default"] = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder { DataSource = desktop.DatabasePath }.ConnectionString;
    builder.Configuration["Storage:KeyDirectory"] = desktop.KeysDirectory;
    builder.Logging.ClearProviders();
    builder.Logging.AddConsole(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
    // 常驻轮询不逐条记录 SQL，防止后台运行时日志无限膨胀；Web 模式日志策略保持原状。
    builder.Logging.AddFilter("Microsoft.EntityFrameworkCore.Database.Command", LogLevel.Warning);
    builder.WebHost.ConfigureKestrel(options =>
    {
        // 不接受外部 Kestrel 端点配置，桌面服务只能由本实例绑定回环动态端口。
        options.Configure(new ConfigurationBuilder().Build(), reloadOnChange: false);
        options.Listen(IPAddress.Loopback, 0);
    });
    builder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = TimeSpan.FromSeconds(20));
    builder.Services.AddSingleton(desktop);
    builder.Services.AddSingleton<IDesktopBackupService, DesktopBackupService>();
    builder.Services.AddHostedService<DesktopControlWorker>();
}
var keyDirectory = Path.GetFullPath(builder.Configuration["Storage:KeyDirectory"] ?? "App_Data/keys", builder.Environment.ContentRootPath);
Directory.CreateDirectory(keyDirectory);
var connectionString = builder.Configuration.GetConnectionString("Default") ?? "Data Source=App_Data/ssl-manager.db";
var sqlite = new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder(connectionString);
if (sqlite.DataSource != ":memory:")
{
    sqlite.DataSource = Path.GetFullPath(sqlite.DataSource, builder.Environment.ContentRootPath);
    Directory.CreateDirectory(Path.GetDirectoryName(sqlite.DataSource)!);
}
builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlite(sqlite.ConnectionString));
builder.Services.AddDataProtection().SetApplicationName("SslManager").PersistKeysToFileSystem(new DirectoryInfo(keyDirectory));
builder.Services.AddSingleton<IIdGenerator, GuidIdGenerator>();
builder.Services.AddScoped<IPasswordHasher<UserAccount>, PasswordHasher<UserAccount>>();
builder.Services.AddScoped<IIdentityService, IdentityService>();
builder.Services.AddScoped<ICloudAccountStore, CloudAccountStore>();
// 邮件采用一套 SMTP 配置，凭据复用现有密钥环，数据库与密钥的桌面备份自动覆盖。
builder.Services.Configure<MailEndpointOptions>(builder.Configuration.GetSection("Mail"));
builder.Services.AddSingleton<MailEndpointGuard>();
builder.Services.AddScoped<IMailTransport, MailKitTransport>();
builder.Services.AddScoped<IMailService, MailService>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<IExpiryReminderTemplateRenderer, ExpiryReminderTemplateRenderer>();
builder.Services.AddScoped<IExpiryReminderService, ExpiryReminderService>();
// 配置迁移仅由管理员主动触发，凭据导入后继续使用本实例密钥环加密保存。
builder.Services.AddScoped<IConfigurationTransferService, ConfigurationTransferService>();
builder.Services.AddScoped<DomainManagementService>();
builder.Services.AddScoped<CertificateManagementService>();
builder.Services.AddScoped<ICertificateScheduleService, CertificateScheduleService>();
builder.Services.AddScoped<CertificateRevocationDnsService>();
builder.Services.AddScoped<TencentCloudService>();
builder.Services.AddScoped<AliyunCloudService>();
builder.Services.AddScoped<CloudflareCloudService>();
builder.Services.AddScoped<AcmeCloudService>();
builder.Services.AddScoped<IAcmeAccountRegistrationService, AcmeAccountRegistrationService>();
builder.Services.AddScoped<ICertificateIssuanceStore, CertificateIssuanceStore>();
builder.Services.AddSingleton<IAcmeDnsPropagationChecker, AcmeDnsPropagationChecker>();
builder.Services.AddScoped<ICloudProviderResolver, CloudProviderResolver>();
// 部署编排、材料、协议和版本执行器分开注册，新增目标不修改 Controller。
builder.Services.AddScoped<ICertificateMaterialService, CertificateMaterialService>();
builder.Services.AddScoped<SafeLineCe9ApiClient>();
builder.Services.AddScoped<SynologyDsmApiClient>();
builder.Services.AddScoped<IRemoteTransport, SshRemoteTransport>();
builder.Services.AddScoped<RemoteDirectoryBrowserService>();
builder.Services.AddScoped<RemoteFileDeploymentService>();
builder.Services.AddScoped<IDeploymentExecutor, SafeLineCe9DeploymentExecutor>();
builder.Services.AddScoped<IDeploymentExecutor, SynologyDsm7DeploymentExecutor>();
builder.Services.AddScoped<IDeploymentExecutor, LinuxSshDeploymentExecutor>();
builder.Services.AddScoped<IDeploymentExecutor, HarborComposeSshDeploymentExecutor>();
builder.Services.AddScoped<IDeploymentExecutor, WindowsSshDeploymentExecutor>();
builder.Services.AddScoped<IDeploymentExecutor, WindowsWinRmDeploymentExecutor>();
builder.Services.AddScoped<IDeploymentExecutorResolver, DeploymentExecutorResolver>();
builder.Services.AddScoped<IDeploymentTargetService, DeploymentTargetService>();
builder.Services.AddScoped<IDeploymentService, DeploymentService>();
builder.Services.AddSingleton<TencentCloudApiClient>();
builder.Services.AddSingleton<AliyunApiClient>();
builder.Services.AddSingleton<CloudflareApiClient>();
builder.Services.AddSingleton<AcmeProtocolClient>();
builder.Services.AddHttpClient("CloudflareApi", c => c.Timeout = TimeSpan.FromSeconds(30))
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false }).RemoveAllLoggers();
builder.Services.AddHttpClient("AcmeProtocol", c => c.Timeout = TimeSpan.FromSeconds(30))
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false }).RemoveAllLoggers();
builder.Services.AddHttpClient("AcmeDns", c => c.Timeout = TimeSpan.FromSeconds(15))
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false }).RemoveAllLoggers();
builder.Services.AddHttpClient("TencentCloudApi", c => c.Timeout = TimeSpan.FromSeconds(30)).RemoveAllLoggers();
builder.Services.AddHttpClient("AliyunApi", c => c.Timeout = TimeSpan.FromSeconds(30)).RemoveAllLoggers();
builder.Services.AddHttpClient("CloudCertificateDownload", c => c.Timeout = TimeSpan.FromSeconds(60))
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false }).RemoveAllLoggers();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(options =>
{
    options.Cookie.Name = desktop is null ? "SslManager.Session" : "SslManager.Desktop.Session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
    options.SlidingExpiration = true;
    options.Events.OnRedirectToLogin = context =>
    { context.Response.StatusCode = 401; return context.Response.WriteAsJsonAsync(ApiResult<object>.Fail("UNAUTHORIZED", "请先登录")); };
    options.Events.OnRedirectToAccessDenied = context =>
    { context.Response.StatusCode = 403; return context.Response.WriteAsJsonAsync(ApiResult<object>.Fail("FORBIDDEN", "当前用户无操作权限")); };
    options.Events.OnValidatePrincipal = async context =>
    {
        var id = context.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
        var identity = context.HttpContext.RequestServices.GetRequiredService<IIdentityService>();
        var user = await identity.GetCurrentUserAsync(id ?? "", context.HttpContext.RequestAborted);
        if (!user.Success || user.Data is null) { context.RejectPrincipal(); await context.HttpContext.SignOutAsync(); return; }
        if (context.Principal?.FindFirstValue(ClaimTypes.Role) != user.Data.Role || context.Principal?.Identity?.Name != user.Data.Username || context.Principal?.FindFirstValue("display_name") != user.Data.Name)
        {
            context.ReplacePrincipal(new ClaimsPrincipal(new ClaimsIdentity(new[] {
                new Claim(ClaimTypes.NameIdentifier, user.Data.Id), new Claim(ClaimTypes.Name, user.Data.Username), new Claim("display_name", user.Data.Name),
                new Claim(ClaimTypes.Role, user.Data.Role) }, CookieAuthenticationDefaults.AuthenticationScheme)));
            context.ShouldRenew = true;
        }
    };
});
builder.Services.AddAuthorization();
builder.Services.AddAntiforgery(options => { options.HeaderName = "X-CSRF-TOKEN"; options.Cookie.SameSite = SameSiteMode.Strict; });
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = 429;
    options.AddPolicy("login", context => RateLimitPartition.GetFixedWindowLimiter(context.Connection.RemoteIpAddress?.ToString() ?? "local",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
    options.OnRejected = async (context, ct) => await context.HttpContext.Response.WriteAsJsonAsync(ApiResult<object>.Fail("RATE_LIMITED", "登录请求过于频繁，请稍后再试"), ct);
});
builder.Services.AddControllers().ConfigureApiBehaviorOptions(options => options.InvalidModelStateResponseFactory = context =>
    new Microsoft.AspNetCore.Mvc.BadRequestObjectResult(ApiResult<object>.Fail("VALIDATION", "请求字段缺失或格式不正确")));
builder.Services.AddHostedService<CertificateWorker>();
builder.Services.AddHostedService<DeploymentWorker>();
builder.Services.AddHostedService<CertificateScheduleWorker>();
builder.Services.AddHostedService<CertificateExpiryReminderWorker>();
// 协议和浏览器管理身份分开注册；未配置生产 OAuth 材料时 MCP 保持关闭，主站仍可启动。
builder.Services.AddSslManagerMcp(builder.Configuration, desktop is not null);
builder.Services.AddScoped<IMcpToolDispatcher, McpToolDispatcher>();
builder.Services.AddScoped<IMcpOperationService, McpOperationService>();
builder.Services.AddScoped<IMcpExecutionGate, McpExecutionGate>();
builder.Services.AddScoped<McpMaintenanceService>();
builder.Services.AddHostedService<McpMaintenanceWorker>();
var mcpProxyAddresses = builder.Configuration.GetSection("Mcp:TrustedProxyAddresses").Get<string[]>() ?? [];
var mcpProxyNetworks = builder.Configuration.GetSection("Mcp:TrustedProxyNetworks").Get<string[]>() ?? [];
var mcpUsesForwarding = mcpProxyAddresses.Length > 0 || mcpProxyNetworks.Length > 0;
if (mcpUsesForwarding)
    builder.Services.Configure<ForwardedHeadersOptions>(options =>
    {
        options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
        options.ForwardLimit = 2; options.KnownProxies.Clear(); options.KnownIPNetworks.Clear();
        foreach (var address in mcpProxyAddresses)
            options.KnownProxies.Add(IPAddress.TryParse(address, out var parsed) ? parsed : throw new InvalidOperationException("MCP 可信代理地址无效。"));
        foreach (var network in mcpProxyNetworks)
            options.KnownIPNetworks.Add(System.Net.IPNetwork.TryParse(network, out var parsed) ? parsed : throw new InvalidOperationException("MCP 可信代理网段无效。"));
    });
var app = builder.Build();
try
{
    await using var scope = app.Services.CreateAsyncScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    if (desktop is null)
    {
        // 新安装可初始化；既有数据库的邮件结构必须通过单独确认的迁移命令升级。
        var applied = (await db.Database.GetAppliedMigrationsAsync()).ToArray();
        var knownMigrations = db.Database.GetMigrations().ToArray();
        if (!applied.SequenceEqual(knownMigrations.Take(applied.Length), StringComparer.Ordinal))
            throw new InvalidOperationException("DATABASE_HISTORY_UNSUPPORTED：数据库包含未知、更高版本或非连续迁移，已停止启动，未修改数据库。");
        if (applied.Length > 0 && (await db.Database.GetPendingMigrationsAsync()).Any(x => x.EndsWith("_AddMailSending", StringComparison.Ordinal)))
            throw new InvalidOperationException("MAIL_DATABASE_UPGRADE_REQUIRED：邮件功能需要单独确认后执行数据库迁移，未自动升级现有数据库。");
        if (applied.Length > 0 && (await db.Database.GetPendingMigrationsAsync()).Any(x => x.EndsWith("_AddMcpServices", StringComparison.Ordinal)))
            throw new InvalidOperationException("MCP_DATABASE_UPGRADE_REQUIRED：MCP 结构需要先备份并按已批准的迁移范围升级，启动不会抢先修改既有数据库。");
        if (applied.Length > 0 && (await db.Database.GetPendingMigrationsAsync()).Any(x => x.EndsWith("_AddCloudflareAcmeIssuance", StringComparison.Ordinal)))
            throw new InvalidOperationException("ISSUANCE_DATABASE_UPGRADE_REQUIRED：Cloudflare/ACME 需要先完成数据库与原密钥成套备份，再按明确目标升级；本次启动未自动升级现有数据库。");
        if (applied.Length > 0 && (await db.Database.GetPendingMigrationsAsync()).Any(x => x.EndsWith("_AddMcpApiKeysAndAudit", StringComparison.Ordinal)))
            throw new InvalidOperationException("MCP_APIKEY_DATABASE_UPGRADE_REQUIRED：API Key 和调用审计结构须先完成数据库与原密钥成套备份，再显式升级；启动不会自动修改现有数据库。");
        await db.Database.MigrateAsync();
        await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");
    }
    else await DesktopDatabase.InitializeAsync(desktop, db, CancellationToken.None);
    if (desktop is not null)
    {
        // 首次安装在 ready 前生成正常首个密钥；既有原密钥缺失已由上面的数据库检查拒绝，绝不生成替代密钥环。
        _ = scope.ServiceProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("SslManager.Desktop.Readiness.v1").Protect("initialized");
    }
    // 仅回填既有配置 JSON；同域名续签可复用目标，不新增表结构或重写凭据密文。
    if (scope.ServiceProvider.GetRequiredService<IDeploymentTargetService>() is DeploymentTargetService targets)
    {
        var updated = await targets.BackfillSourceDomainsAsync(CancellationToken.None);
        if (updated > 0) app.Logger.LogInformation("已将 {Count} 个部署目标的来源配置转换为域名绑定。", updated);
    }
}
catch (Exception exception) when (desktop is not null)
{
    var known = exception as DesktopStartupException;
    desktop.Emit(new { type = "error", protocol = 1, code = known?.Code ?? "DESKTOP_DATABASE_FAILED",
        message = known?.Message ?? "桌面数据初始化失败，请查看本地日志或恢复备份。" });
    desktop.Dispose(); Environment.ExitCode = 1; return;
}
if (desktop is not null)
{
    app.Lifetime.ApplicationStopped.Register(desktop.Dispose);
    app.Lifetime.ApplicationStarted.Register(() =>
    {
        try { desktop.AnnounceReady(app.Services.GetRequiredService<Microsoft.AspNetCore.Hosting.Server.IServer>()); }
        catch (Exception)
        {
            desktop.Emit(new { type = "error", protocol = 1, code = "DESKTOP_BINDING_INVALID", message = "桌面本地服务端点初始化失败。" });
            app.Lifetime.StopApplication();
        }
    });
    app.Use(async (context, next) =>
    {
        if (!desktop.Allows(context))
        {
            context.Response.StatusCode = 403;
            await context.Response.WriteAsJsonAsync(ApiResult<object>.Fail("DESKTOP_ACCESS_DENIED", "此本地服务仅允许当前桌面客户端访问。")); return;
        }
        context.Response.Headers["X-Content-Type-Options"] = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "same-origin";
        context.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'";
        await next();
    });
    app.UseWhen(context => !context.Request.Path.StartsWithSegments("/api"), branch =>
    {
        branch.UseDefaultFiles(); branch.UseStaticFiles();
    });
}
app.Use(async (context, next) =>
{
    try { await next(); }
    catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested) { }
    catch (Exception exception)
    {
        app.Logger.LogError(exception, "系统异常，TraceId={TraceId}", context.TraceIdentifier);
        if (!context.Response.HasStarted)
        {
            context.Response.Clear(); context.Response.StatusCode = 500;
            await context.Response.WriteAsJsonAsync(ApiResult<object>.Fail("SYSTEM_ERROR", "系统发生异常，请使用请求标识联系管理员：" + context.TraceIdentifier));
        }
    }
});
app.UseRouting();
app.Use(async (context, next) =>
{
    // 转发头处理前保存 TCP 对端，审计同时区分真实代理与经过白名单信任的客户端来源。
    if (context.Request.Path.StartsWithSegments("/mcp") || context.Request.Path.StartsWithSegments("/oauth/mcp") ||
        context.Request.Path.StartsWithSegments("/.well-known"))
    {
        context.Items["McpActualRemoteIp"] = context.Connection.RemoteIpAddress?.ToString() ?? "";
        // 仅请求内保留代理处理前的地址链，HTTP内网模式据此拒绝未完整还原的来源，不进入持久审计。
        context.Items["McpOriginalForwardedFor"] = context.Request.Headers["X-Forwarded-For"].ToArray();
    }
    await next();
});
// 未显式配置可信代理时完全不处理转发头，避免空 KnownProxies/Networks 意外信任任意来源。
if (mcpUsesForwarding)
    app.UseWhen(context => context.Request.Path.StartsWithSegments("/mcp") || context.Request.Path.StartsWithSegments("/oauth/mcp") ||
        context.Request.Path.StartsWithSegments("/.well-known"), branch => branch.UseForwardedHeaders());
app.UseSslManagerMcpBoundary();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.Use(async (context, next) =>
{
    if (context.Request.Path.StartsWithSegments("/api") && !HttpMethods.IsGet(context.Request.Method) &&
        !HttpMethods.IsHead(context.Request.Method) && !HttpMethods.IsOptions(context.Request.Method))
    {
        var antiforgery = context.RequestServices.GetRequiredService<IAntiforgery>();
        if (!await antiforgery.IsRequestValidAsync(context))
        {
            context.Response.StatusCode = 400;
            await context.Response.WriteAsJsonAsync(ApiResult<object>.Fail("CSRF_INVALID", "请求验证已失效，请刷新页面重试"));
            return;
        }
    }
    var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "";
    var username = context.User.Identity?.Name ?? "anonymous";
    await next();
    // 仅记录操作摘要，不读取请求正文或云密钥。
    if (context.Request.Path.StartsWithSegments("/api") && (!HttpMethods.IsGet(context.Request.Method) || context.Request.Path.Value?.EndsWith("/download") == true))
    {
        using var auditScope = app.Services.CreateScope();
        var db = auditScope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.AuditLogs.Add(new AuditLog { Id = auditScope.ServiceProvider.GetRequiredService<IIdGenerator>().NewId(), UserId = userId,
            Username = username, Action = context.Request.Method + " " + context.Request.Path, ResourceId = context.Request.Path,
            Success = context.Response.StatusCode < 400, Code = context.Response.StatusCode.ToString(), Message = "操作请求", CreatedAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync();
    }
});
app.MapControllers();
app.MapSslManagerMcp();
app.MapGet("/api/health", () => desktop is null ? ApiResult<object>.Ok(new { status = "Healthy", version = ApplicationVersion.Current })
    : ApiResult<object>.Ok(new { status = "Healthy", version = ApplicationVersion.Current, instanceId = desktop.InstanceId }));
app.MapFallback(async context =>
{
    if (desktop is not null && !context.Request.Path.StartsWithSegments("/api") &&
        (HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method)) && !Path.HasExtension(context.Request.Path))
    {
        context.Response.ContentType = "text/html; charset=utf-8";
        await context.Response.SendFileAsync(Path.Combine(desktop.WebRootDirectory, "index.html")); return;
    }
    context.Response.StatusCode = 404;
    await context.Response.WriteAsJsonAsync(ApiResult<object>.Fail("NOT_FOUND", "接口不存在"));
});
app.Run();

public partial class Program;
