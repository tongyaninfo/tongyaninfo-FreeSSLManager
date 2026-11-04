using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SslManager.Api.Common;
using SslManager.Api.Service;

namespace SslManager.Api.Controllers;

/// <summary>独立字面量路由优先于日志ID；API Key不能读取管理员审计。</summary>
[ApiController, Authorize(AuthenticationSchemes = "Cookies", Roles = "admin"), Route("api/mcp/call-logs/statistics")]
public sealed class McpAuditController(IMcpInvocationLogService logs) : BusinessController
{
    [HttpGet]
    public async Task<IActionResult> Statistics(DateTime? fromUtc = null, DateTime? toUtc = null, CancellationToken ct = default)
    {
        Response.Headers.CacheControl = "no-store";
        return Reply(await logs.StatisticsAsync(fromUtc, toUtc, ct));
    }
}
