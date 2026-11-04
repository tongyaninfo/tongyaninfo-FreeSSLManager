using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Models;
using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Api.Service.impl;

public sealed partial class CertificateScheduleService
{
    private async Task AttachMcpScheduleOriginAsync(CertificateScheduleRun run, CancellationToken ct)
    {
        var sourceId = await McpScheduleOrigin.FindForScheduleAsync(db, run.ScheduleId, ct);
        if (sourceId is not null) run.ConfigSnapshotJson = McpScheduleOrigin.WriteOperationId(run.ConfigSnapshotJson, sourceId);
    }

    private async Task<ApiResult<bool>> CheckMcpScheduleOriginAsync(CertificateScheduleRun run, CancellationToken ct)
    {
        var sourceId = McpScheduleOrigin.ReadOperationId(run.ConfigSnapshotJson);
        if (sourceId.Length == 0) return ApiResult<bool>.Ok(true);
        if (mcpGate is null) return ApiResult<bool>.Fail("MCP_GATE_UNAVAILABLE", "计划缺少原 MCP 来源校验能力。");
        var source = await db.McpOperations.AsNoTracking().SingleOrDefaultAsync(x => x.Id == sourceId, ct);
        if (source is null) return ApiResult<bool>.Fail("MCP_OPERATION_MISSING", "计划的原 MCP 操作不存在。");
        try
        {
            var input = JsonSerializer.Deserialize<CertificateScheduleRunSnapshot>(run.ConfigSnapshotJson, Json);
            var snapshot = JsonSerializer.Deserialize<McpOperationResourceSnapshot>(source.ResourceJson, Json);
            if (input is null || snapshot?.Resources is null || input.TargetIds.Length == 0 || input.TargetIds.Any(target => !snapshot.Resources.Any(resource =>
                resource.AccountId == input.AccountId && resource.Domain == input.Domain && resource.TargetId == target && resource.ScheduleId == run.ScheduleId)))
                return ApiResult<bool>.Fail("MCP_RESOURCE_CHANGED", "计划轮次超出了原批准资源范围。");
            if (!string.IsNullOrEmpty(input.DnsZoneId))
            {
                var zone = await db.Domains.AsNoTracking().SingleOrDefaultAsync(x => x.Id == input.DnsZoneId, ct);
                if (zone is null || !snapshot.Resources.Any(resource => resource.AccountId == zone.AccountId && resource.Domain == input.Domain))
                    return ApiResult<bool>.Fail("MCP_RESOURCE_CHANGED", "计划 DNS 区域不再匹配原授权。");
            }
            if (source.ToolName is "ssl_schedules_create" or "ssl_schedules_update" or "ssl_schedules_status")
            {
                using var document = JsonDocument.Parse(snapshot.SummaryJson);
                var revision = ReadSourceRevision(document.RootElement);
                if (revision is null || revision != input.ConfigRevision)
                    return ApiResult<bool>.Fail("MCP_POLICY_CHANGED", "计划配置修订变化后需要重新授权。");
            }
        }
        catch (JsonException) { return ApiResult<bool>.Fail("MCP_SNAPSHOT_INVALID", "计划来源快照无法核对。"); }
        return await mcpGate.CheckOperationAsync(sourceId, ct);
    }

    private static int? ReadSourceRevision(JsonElement input, int depth = 0)
    {
        if (depth > 4 || input.ValueKind != JsonValueKind.Object) return null;
        if (input.TryGetProperty("sourceConfigRevision", out var revision) && revision.ValueKind == JsonValueKind.Number && revision.TryGetInt32(out var value)) return value;
        if (input.TryGetProperty("result", out var result) && result.ValueKind == JsonValueKind.Object
            && result.TryGetProperty("configRevision", out var config) && config.ValueKind == JsonValueKind.Number && config.TryGetInt32(out var resultValue)) return resultValue;
        return input.TryGetProperty("request", out var request) ? ReadSourceRevision(request, depth + 1) : null;
    }
}
