using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Data;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Mcp;

/// <summary>工具调用先建立持久Started记录，最终只保存业务元数据及有界白名单快照。</summary>
public sealed class McpInvocationLogService(AppDbContext db, IIdGenerator ids, IHttpContextAccessor? accessor = null) : IMcpInvocationLogService
{
    public async Task<string> StartAsync(McpCallerContext caller, string method, string toolName, string requestId, string version, CancellationToken ct)
    {
        var http = accessor?.HttpContext;
        if (http is not null)
        {
            McpAuditCapture.ReadRequest(http);
            var state = McpAuditCapture.State(http); state.Method = method; state.ToolName = toolName;
            var settings = await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(ct);
            state.Context = state.Context with { SystemName = settings?.SystemName, InstanceId = settings?.InstanceId };
        }
        var row = new McpInvocationLog { Id = ids.NewId(), ClientId = caller.ClientId, UserId = caller.EffectiveUserId,
            AuthorizationId = caller.AuthorizationId, SourceIp = caller.SourceIp, RemoteIp = caller.RemoteIp.Length == 0 ? caller.SourceIp : caller.RemoteIp, TraceId = Clean(caller.TraceId, 100),
            Method = Clean(method, 100), ToolName = Clean(toolName, 150), ProtocolVersion = Clean(version, 30),
            // 请求 ID 是任意调用方输入，只保留摘要，防止它夹带秘密或控制字符。
            RequestId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(requestId))), StartedAtUtc = DateTime.UtcNow,
            AuthenticationType = caller.AuthenticationType, ApiKeyId = caller.ApiKeyId,
            ContextJson = http is null ? "{}" : McpAuditCapture.Snapshot(http) };
        if (caller.ApiKeyId.Length > 0)
        {
            var key = await db.McpApiKeys.AsNoTracking().Where(x => x.Id == caller.ApiKeyId).Select(x => new { x.Name, x.Prefix }).SingleOrDefaultAsync(ct);
            row.ApiKeyName = key?.Name ?? ""; row.ApiKeyPrefix = key?.Prefix ?? "";
        }
        db.McpInvocationLogs.Add(row); await db.SaveChangesAsync(ct);
        if (http is not null) McpAuditCapture.MarkInvocation(http, row.Id);
        return row.Id;
    }
    public async Task CompleteAsync(string id, bool success, string code, bool unknown, CancellationToken ct)
    {
        var row = await db.McpInvocationLogs.SingleAsync(x => x.Id == id, ct);
        ApplyResult(row, success, code, unknown);
        if (accessor?.HttpContext is { } http)
        {
            McpAuditCapture.SetResult(http, success, code, unknown);
            row.ContextJson = McpAuditCapture.Snapshot(http);
        }
        await db.SaveChangesAsync(ct);
    }

    public async Task FinalizeHttpAsync(string id, McpHttpAuditCompletion result, CancellationToken ct)
    {
        var row = await db.McpInvocationLogs.SingleAsync(x => x.Id == id, ct);
        // HTTP 200中的业务失败保留失败码，不能由传输成功覆盖。
        var alreadyFailed = row.Status is not ("Started" or "Succeeded");
        if (!alreadyFailed || !result.Success) ApplyResult(row, result.Success, result.Code, result.Unknown);
        row.HttpStatus = result.HttpStatus; row.StartedAtUtc = result.StartedAtUtc;
        row.FinishedAtUtc = DateTime.UtcNow; row.DurationMilliseconds = Math.Max(0, result.DurationMilliseconds);
        row.ContextJson = McpAuditPayloads.Normalize(result.ContextJson);
        await db.SaveChangesAsync(ct);
    }
    public async Task<ApiResult<PageResult<McpInvocationLog>>> ListAsync(McpInvocationQuery input, CancellationToken ct)
    {
        if (input.Page < 1 || input.PageSize is < 1 or > 100) return ApiResult<PageResult<McpInvocationLog>>.Fail("VALIDATION", "分页参数无效。");
        if (!Window(input.FromUtc, input.ToUtc, out var from, out var to)) return ApiResult<PageResult<McpInvocationLog>>.Fail("VALIDATION", "查询时间范围须为有效UTC时间且不超过90天。");
        if ((long)(input.Page - 1) * input.PageSize > int.MaxValue || input.HttpStatus is < 100 or > 599)
            return ApiResult<PageResult<McpInvocationLog>>.Fail("VALIDATION", "分页或HTTP状态参数无效。");
        var query = db.McpInvocationLogs.AsNoTracking().Where(x => x.StartedAtUtc >= from && x.StartedAtUtc <= to);
        if (!string.IsNullOrEmpty(input.ClientId)) query = query.Where(x => x.ClientId == input.ClientId);
        if (!string.IsNullOrEmpty(input.ToolName)) query = query.Where(x => x.ToolName == input.ToolName);
        if (!string.IsNullOrEmpty(input.Status)) query = query.Where(x => x.Status == input.Status);
        if (!string.IsNullOrEmpty(input.Code)) query = query.Where(x => x.Code == input.Code);
        if (!string.IsNullOrEmpty(input.SourceIp)) query = query.Where(x => x.SourceIp == input.SourceIp);
        if (!string.IsNullOrEmpty(input.ApiKeyId)) query = query.Where(x => x.ApiKeyId == input.ApiKeyId);
        if (!string.IsNullOrEmpty(input.Method)) query = query.Where(x => x.Method == input.Method);
        if (!string.IsNullOrEmpty(input.TraceId)) query = query.Where(x => x.TraceId == input.TraceId);
        if (!string.IsNullOrEmpty(input.AuthenticationType)) query = query.Where(x => x.AuthenticationType == input.AuthenticationType);
        if (input.HttpStatus.HasValue) query = query.Where(x => x.HttpStatus == input.HttpStatus.Value);
        var count = await query.CountAsync(ct);
        var rows = await query.OrderByDescending(x => x.StartedAtUtc).ThenByDescending(x => x.Id).Skip((input.Page - 1) * input.PageSize).Take(input.PageSize).ToListAsync(ct);
        foreach (var row in rows) row.ContextJson = McpAuditPayloads.Normalize(row.ContextJson);
        return ApiResult<PageResult<McpInvocationLog>>.Ok(new(rows, count, input.Page, input.PageSize));
    }
    public async Task<ApiResult<McpInvocationLog>> GetAsync(string id, CancellationToken ct)
    {
        var row = await db.McpInvocationLogs.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is not null) row.ContextJson = McpAuditPayloads.Normalize(row.ContextJson);
        return row is null ? ApiResult<McpInvocationLog>.Fail("NOT_FOUND", "调用日志不存在。") : ApiResult<McpInvocationLog>.Ok(row);
    }

    public async Task<ApiResult<McpAuditStatistics>> StatisticsAsync(DateTime? fromUtc, DateTime? toUtc, CancellationToken ct)
    {
        if (!Window(fromUtc, toUtc, out var from, out var to)) return ApiResult<McpAuditStatistics>.Fail("VALIDATION", "统计时间范围须为有效UTC时间且不超过90天。");
        var query = db.McpInvocationLogs.AsNoTracking().Where(x => x.StartedAtUtc >= from && x.StartedAtUtc <= to);
        var hourly = (to - from).TotalDays <= 14;
        // 在数据库聚合，不下载整窗日志；聚合拒绝行按OccurrenceCount计算请求数。
        var buckets = await query.GroupBy(x => new { x.StartedAtUtc.Year, x.StartedAtUtc.Month, x.StartedAtUtc.Day, Hour = hourly ? x.StartedAtUtc.Hour : 0 })
            .Select(g => new
            {
                g.Key.Year, g.Key.Month, g.Key.Day, g.Key.Hour,
                Requests = g.Sum(x => (long)x.OccurrenceCount),
                ToolCalls = g.Sum(x => x.Method == "tools/call" ? (long)x.OccurrenceCount : 0),
                Succeeded = g.Sum(x => x.Status == "Succeeded" ? (long)x.OccurrenceCount : 0),
                Failed = g.Sum(x => x.Status == "Failed" || x.Status == "TimedOut" || x.Status == "Cancelled" ? (long)x.OccurrenceCount : 0),
                Denied = g.Sum(x => x.Status == "Denied" ? (long)x.OccurrenceCount : 0),
                Unknown = g.Sum(x => x.Status == "Unknown" || x.Status == "Started" ? (long)x.OccurrenceCount : 0)
            }).ToListAsync(ct);
        var average = await query.Where(x => x.Method == "tools/call" && x.FinishedAtUtc != null && x.OccurrenceCount == 1)
            .Select(x => (double?)x.DurationMilliseconds).AverageAsync(ct);
        var trend = buckets.Select(x => new McpAuditTrendPoint(new(x.Year, x.Month, x.Day, x.Hour, 0, 0, DateTimeKind.Utc), x.Requests, x.ToolCalls, x.Failed, x.Denied))
            .OrderBy(x => x.BucketUtc).ToArray();
        return ApiResult<McpAuditStatistics>.Ok(new(from, to, buckets.Sum(x => x.Requests), buckets.Sum(x => x.ToolCalls), buckets.Sum(x => x.Succeeded),
            buckets.Sum(x => x.Failed), buckets.Sum(x => x.Denied), buckets.Sum(x => x.Unknown), average, trend));
    }

    private static void ApplyResult(McpInvocationLog row, bool success, string code, bool unknown)
    {
        row.FinishedAtUtc = DateTime.UtcNow; row.DurationMilliseconds = (long)(row.FinishedAtUtc.Value - row.StartedAtUtc).TotalMilliseconds;
        row.Status = unknown ? "Unknown" : success ? "Succeeded" : code == "CANCELLED" ? "Cancelled" : code == "TIMEOUT" ? "TimedOut"
            : code is "FORBIDDEN" or "UNAUTHORIZED" or "INSUFFICIENT_SCOPE" or "API_KEY_REVOKED" or "AUTHORIZATION_REVOKED" or "MCP_DISABLED" or "READ_ONLY" ? "Denied" : "Failed";
        row.Code = Clean(code, 80); row.Message = success ? "调用完成。" : unknown ? "调用中断，业务结果请按关联操作核对。" : "调用未成功，请按业务码处理。";
    }
    private static bool Window(DateTime? requestedFrom, DateTime? requestedTo, out DateTime from, out DateTime to)
    {
        to = Utc(requestedTo ?? DateTime.UtcNow);
        if (requestedFrom is null && to.Ticks < TimeSpan.FromDays(7).Ticks) { from = to; return false; }
        from = Utc(requestedFrom ?? to.AddDays(-7));
        return from <= to && (to - from).TotalDays <= 90;
    }
    private static DateTime Utc(DateTime value) => value.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(value, DateTimeKind.Utc) : value.ToUniversalTime();
    private static string Clean(string value, int limit) => new(value.Where(c => !char.IsControl(c)).Take(limit).ToArray());
}
