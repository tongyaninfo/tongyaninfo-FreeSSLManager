using Microsoft.EntityFrameworkCore;
using SslManager.Api.Data;

namespace SslManager.Api.Service.impl.Mcp;

/// <summary>仅整理 MCP 调用账本；不触碰 OAuth 授权、未知操作、部署材料或任何文件。</summary>
public sealed class McpMaintenanceService(AppDbContext db, TimeProvider time)
{
    public async Task<int> SweepAsync(CancellationToken ct)
    {
        var now = time.GetUtcNow().UtcDateTime;
        var interrupted = now.AddMinutes(-30);
        var count = await db.McpInvocationLogs.Where(row => row.Status == "Started" && row.StartedAtUtc < interrupted)
            .ExecuteUpdateAsync(update => update.SetProperty(row => row.Status, "Unknown")
                .SetProperty(row => row.Code, "CALL_INTERRUPTED")
                .SetProperty(row => row.Message, "调用未保留最终回执，请核对关联业务任务。")
                .SetProperty(row => row.FinishedAtUtc, (DateTime?)now), ct);
        var settings = await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(ct);
        if (settings is null || settings.LogRetentionDays is < 1 or > 365) return count;
        var cutoff = now.AddDays(-settings.LogRetentionDays);
        // 只有管理员明确保存过保留策略的单例配置才清理；初始无配置不会自动删除账本。
        return count + await db.McpInvocationLogs.Where(row => row.Status != "Started" && row.StartedAtUtc < cutoff)
            .ExecuteDeleteAsync(ct);
    }
}
