using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using SslManager.Api.Data;
using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Api.Common.Mcp;

/// <summary>调用前检查实时总开关、可信公开地址、Origin/来源及有界请求，不改原有 REST 身份流程。</summary>
public sealed class McpBoundaryMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, AppDbContext db, McpRuntimeOptions runtime, McpRequestLimiter limiter)
    {
        var path = context.Request.Path;
        var mcp = path.StartsWithSegments("/mcp");
        var oauth = path.StartsWithSegments("/oauth/mcp") || path.StartsWithSegments("/.well-known");
        if (!mcp && !oauth) { await next(context); return; }
        context.Response.Headers.CacheControl = "no-store";
        if (!context.Request.IsHttps) { await Reject(context, 400, "HTTPS_REQUIRED"); return; }
        if (!runtime.Supported || oauth && !runtime.OAuthReady)
        { await Reject(context, 503, "MCP_NOT_READY"); return; }
        var settings = await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(context.RequestAborted);
        if (settings is null || !settings.Enabled)
        { await Reject(context, 503, "MCP_DISABLED"); return; }
        if (!Uri.TryCreate(settings.PublicBaseUrl, UriKind.Absolute, out var address) || runtime.OAuthReady && settings.PublicBaseUrl != runtime.Issuer
            || !string.Equals(context.Request.Host.Host, address.Host, StringComparison.OrdinalIgnoreCase)
            || (context.Request.Host.Port ?? 443) != address.Port)
        { await Reject(context, 400, "INVALID_HOST"); return; }
        if (context.Request.Query.Keys.Any(key => key.Equals("access_token", StringComparison.OrdinalIgnoreCase)
            || key.Equals("api_key", StringComparison.OrdinalIgnoreCase) || key.Equals("apikey", StringComparison.OrdinalIgnoreCase)
            || key.Equals("api-key", StringComparison.OrdinalIgnoreCase) || key.Equals("x-api-key", StringComparison.OrdinalIgnoreCase)
            || key.Equals("authorization", StringComparison.OrdinalIgnoreCase) || key.Equals("key", StringComparison.OrdinalIgnoreCase)
            || key.Equals("token", StringComparison.OrdinalIgnoreCase)))
        { await Reject(context, 400, "TOKEN_IN_QUERY_FORBIDDEN"); return; }
        var origin = context.Request.Headers.Origin.ToString();
        if (origin.Length > 0 && !McpConfigurationService.Strings(settings.AllowedOriginsJson).Contains(origin.TrimEnd('/')))
        { await Reject(context, 403, "ORIGIN_FORBIDDEN"); return; }
        var ip = context.Connection.RemoteIpAddress?.ToString() ?? "";
        if (!McpNetwork.Contains(McpConfigurationService.Strings(settings.AllowedCidrsJson), ip))
        { await Reject(context, 403, "SOURCE_FORBIDDEN"); return; }
        if (context.Request.ContentLength > 256 * 1024) { await Reject(context, 413, "REQUEST_TOO_LARGE"); return; }
        var size = context.Features.Get<IHttpMaxRequestBodySizeFeature>();
        if (size is { IsReadOnly: false }) size.MaxRequestBodySize = 256 * 1024;
        // 认证中间件尚未建立 OpenIddict 验证事务，此处只做来源防滥用；客户端限流在 Bearer 认证后执行。
        using var lease = limiter.TryEnter("ip:" + ip, Math.Min(6000, settings.RateLimitPerMinute * 10), Math.Max(32, settings.MaxConcurrentCalls));
        if (lease is null)
        {
            context.Response.Headers.RetryAfter = "60";
            await Reject(context, 429, "RATE_LIMITED"); return;
        }
        if (mcp && !await McpRequestShape.CheckAsync(context)) return;
        await next(context);
        if (context.Response.StatusCode >= 400) await RecordDeniedAsync(context, context.Response.StatusCode, "PROTOCOL_OR_AUTH_REJECTED");
    }
    private static async Task Reject(HttpContext context, int status, string code)
    {
        context.Response.StatusCode = status;
        await RecordDeniedAsync(context, status, code);
        await context.Response.WriteAsJsonAsync(ApiResult<object>.Fail(code, "MCP 请求未通过接入检查。"));
    }

    /// <summary>未鉴权和畸形请求按错误码/分钟聚合，任意来源不能线性撑满 SQLite。</summary>
    internal static async Task RecordDeniedAsync(HttpContext context, int status, string code)
    {
        if (McpAuditCapture.HasInvocation(context)) return;
        // 已认证但在工具处理器前拒绝的协议请求由外层逐次审计，保留其 Key/客户端关联。
        if (context.User.Identity?.IsAuthenticated == true && context.User.HasClaim(claim => claim.Type == "mcp_client")) return;
        if (context.Items.ContainsKey("McpDeniedLogged")) return;
        context.Items["McpDeniedLogged"] = true;
        try
        {
            var db = context.RequestServices.GetRequiredService<AppDbContext>();
            var now = DateTime.UtcNow;
            var minute = new DateTime(now.Ticks - now.Ticks % TimeSpan.TicksPerMinute, DateTimeKind.Utc);
            var row = await db.McpInvocationLogs.SingleOrDefaultAsync(x => x.ClientId == "" && x.Method == ""
                && x.Status == "Denied" && x.Code == code && x.StartedAtUtc == minute);
            var ip = context.Connection.RemoteIpAddress?.ToString() ?? "";
            var peer = context.Items.TryGetValue("McpActualRemoteIp", out var actual) ? actual?.ToString() ?? "" : ip;
            if (row is null)
            {
                row = new() { Id = context.RequestServices.GetRequiredService<IIdGenerator>().NewId(), Status = "Denied", Code = code,
                    AuthenticationType = "None",
                    HttpStatus = status, StartedAtUtc = minute, FinishedAtUtc = now, SourceIp = ip, RemoteIp = peer,
                    Message = "本分钟接入拒绝计数；来源不同时不保留单一来源地址。" };
                db.McpInvocationLogs.Add(row);
            }
            else
            {
                row.OccurrenceCount = (int)Math.Min(int.MaxValue, (long)row.OccurrenceCount + 1);
                if (row.SourceIp != ip) { row.SourceIp = ""; row.RemoteIp = ""; }
                else if (row.RemoteIp != peer) row.RemoteIp = "";
                row.FinishedAtUtc = now;
            }
            await db.SaveChangesAsync();
            McpAuditCapture.MarkPersisted(context, row.Id);
        }
        catch (Exception exception) when (exception is Microsoft.Data.Sqlite.SqliteException or DbUpdateException)
        { /* 数据库不可写时仍拒绝接入，绝不因此转为允许。 */ }
    }
}
