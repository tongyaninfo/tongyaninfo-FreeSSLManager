using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Data;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Common.Mcp;

/// <summary>计划及轮次来源保存在既有 JSON 中，不新增列；未来执行始终沿用原操作和 Key。</summary>
public static class McpScheduleOrigin
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public static string ReadOperationId(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object) return "mcp-invalid-snapshot";
            if (!document.RootElement.TryGetProperty("mcpOperationId", out var id)) return "";
            return id.ValueKind == JsonValueKind.String ? id.GetString() ?? "" : "mcp-invalid-snapshot";
        }
        catch (JsonException) { return "mcp-invalid-snapshot"; }
    }
    public static string WriteOperationId(string json, string operationId)
    {
        var node = JsonNode.Parse(json) as JsonObject ?? throw new JsonException("计划快照必须为对象。");
        node["mcpOperationId"] = operationId; return node.ToJsonString(Json);
    }
    public static async Task<string?> FindForScheduleAsync(AppDbContext db, string id, CancellationToken ct)
    {
        var candidates = await db.McpOperations.AsNoTracking().Where(x => x.ConsumedAtUtc != null
            && (x.ToolName == "ssl_schedules_create" || x.ToolName == "ssl_schedules_update" || x.ToolName == "ssl_schedules_status")
            && x.ResourceJson.Contains(id)).OrderByDescending(x => x.ConsumedAtUtc).ThenByDescending(x => x.Id).ToArrayAsync(ct);
        foreach (var candidate in candidates)
        {
            try
            {
                var snapshot = JsonSerializer.Deserialize<SslManager.Api.Service.impl.Mcp.McpOperationResourceSnapshot>(candidate.ResourceJson, Json);
                if (snapshot?.Resources is null) return "mcp-invalid-snapshot";
                if (snapshot.Resources.Any(x => x.ScheduleId == id)) return candidate.Id;
            }
            catch (JsonException) { return "mcp-invalid-snapshot"; }
        }
        return null;
    }
    public static async Task<string?> FindForCertificateAsync(AppDbContext db, string id, CancellationToken ct)
    {
        var snapshot = await db.CertificateScheduleRuns.AsNoTracking().Where(x => x.CertificateId == id)
            .OrderByDescending(x => x.CreatedAtUtc).Select(x => x.ConfigSnapshotJson).FirstOrDefaultAsync(ct);
        if (snapshot is not null) { var source = ReadOperationId(snapshot); if (source.Length > 0) return source; }
        return null;
    }
    public static async Task<string?> FindForBatchAsync(AppDbContext db, string id, CancellationToken ct)
    {
        var candidates = await db.CertificateScheduleRuns.AsNoTracking().Where(x => x.TargetsJson.Contains(id))
            .OrderByDescending(x => x.CreatedAtUtc).Select(x => new { x.ConfigSnapshotJson, x.TargetsJson }).ToArrayAsync(ct);
        foreach (var candidate in candidates)
        {
            try
            {
                using var document = JsonDocument.Parse(candidate.TargetsJson);
                if (document.RootElement.ValueKind != JsonValueKind.Array) return "mcp-invalid-snapshot";
                if (!document.RootElement.EnumerateArray().Any(target => target.ValueKind == JsonValueKind.Object
                    && target.TryGetProperty("batchId", out var batch) && batch.ValueKind == JsonValueKind.String && batch.GetString() == id)) continue;
                var source = ReadOperationId(candidate.ConfigSnapshotJson); if (source.Length > 0) return source;
            }
            catch (JsonException) { return "mcp-invalid-snapshot"; }
        }
        return null;
    }
}
