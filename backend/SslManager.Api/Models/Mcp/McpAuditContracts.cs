using System.Text.Json;

namespace SslManager.Api.Models.Mcp;

/// <summary>仅保存固定字段投影；空值与尚未采集通过独立标记区分，历史记录不回填。</summary>
public sealed record McpAuditContext(string? ClientName = null, string? ClientVersion = null,
    JsonElement? Input = null, JsonElement? Output = null, bool InputCaptured = false,
    bool OutputCaptured = false, bool InputTruncated = false, bool OutputTruncated = false, bool Truncated = false,
    string? SystemName = null, string? InstanceId = null, string? UserAgent = null, string? TransportScheme = null);

public sealed record McpAuditTrendPoint(DateTime BucketUtc, long Requests, long ToolCalls, long Failed, long Denied);

/// <summary>接入拒绝聚合按 OccurrenceCount 计数；工具调用只统计 tools/call，目录和握手单独计请求。</summary>
public sealed record McpAuditStatistics(DateTime FromUtc, DateTime ToUtc, long TotalRequests, long ToolCalls,
    long Succeeded, long Failed, long Denied, long Unknown, double? AverageDurationMilliseconds,
    IReadOnlyList<McpAuditTrendPoint> Trend);

public sealed record McpHttpAuditCompletion(int HttpStatus, DateTime StartedAtUtc, long DurationMilliseconds,
    string ContextJson, bool Success, string Code, bool Unknown = false);
