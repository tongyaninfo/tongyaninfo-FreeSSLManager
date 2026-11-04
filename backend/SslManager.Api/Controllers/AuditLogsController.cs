using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;

namespace SslManager.Api.Controllers;

[ApiController, Authorize(Roles = "admin"), Route("api/audit-logs")]
public sealed class AuditLogsController(AppDbContext db) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20,
        [FromQuery] string? username = null, [FromQuery] string? action = null, [FromQuery] string? resourceId = null,
        [FromQuery] bool? success = null, CancellationToken ct = default)
    {
        page = Math.Max(1, page); pageSize = Math.Clamp(pageSize, 1, 200);
        var query = db.AuditLogs.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(username)) query = query.Where(x => x.Username.Contains(username));
        if (!string.IsNullOrWhiteSpace(action)) query = query.Where(x => x.Action.Contains(action));
        if (!string.IsNullOrWhiteSpace(resourceId)) query = query.Where(x => x.ResourceId.Contains(resourceId));
        if (success.HasValue) query = query.Where(x => x.Success == success.Value);
        var total = await query.CountAsync(ct);
        var items = await query.OrderByDescending(x => x.CreatedAtUtc).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return Ok(ApiResult<object>.Ok(new { items, total, page, pageSize }));
    }
}
