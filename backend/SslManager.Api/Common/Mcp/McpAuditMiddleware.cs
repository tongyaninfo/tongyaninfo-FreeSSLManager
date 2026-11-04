using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Data;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service;

namespace SslManager.Api.Common.Mcp;

/// <summary>覆盖握手、通知和协议错误的HTTP账本；工具处理器先写Started，本层只补最终HTTP结果，避免重复计数。</summary>
public sealed class McpAuditMiddleware(RequestDelegate next, ILogger<McpAuditMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context, IMcpInvocationLogService logs, AppDbContext db)
    {
        if (!context.Request.Path.StartsWithSegments("/mcp", StringComparison.OrdinalIgnoreCase)) { await next(context); return; }
        var startedAt = DateTime.UtcNow; var timer = Stopwatch.GetTimestamp();
        var originalBody = context.Response.Body;
        using var capture = new ResponseCapture(originalBody, McpAuditPayloads.MaxOutputBytes);
        context.Response.Body = capture;
        var interrupted = false;
        try { await next(context); }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        { interrupted = true; McpAuditCapture.SetResult(context, false, "CANCELLED"); throw; }
        catch
        {
            interrupted = true;
            var known = McpAuditCapture.State(context);
            if (known.Success is not false || known.Code is null) McpAuditCapture.SetResult(context, false, "SYSTEM_ERROR", true);
            throw;
        }
        finally
        {
            context.Response.Body = originalBody;
            var state = McpAuditCapture.State(context);
            if (!state.PersistedDenial)
            {
                try
                {
                    McpAuditCapture.ReadRequest(context);
                    McpAuditCapture.ReadResponse(context, capture.Captured, capture.Truncated);
                    if (context.RequestAborted.IsCancellationRequested) McpAuditCapture.SetResult(context, false, "CANCELLED", state.Unknown);
                    var httpStatus = context.RequestAborted.IsCancellationRequested ? 499 : interrupted && !context.Response.HasStarted ? 500 : context.Response.StatusCode;
                    var caller = McpBearerHandler.Caller(context);
                    if (caller.ClientId.Length == 0)
                    {
                        // 未认证错误仍由原有有界分钟聚合承担，不能让攻击者每请求创建独立行。
                        if (httpStatus >= 400) await McpBoundaryMiddleware.RecordDeniedAsync(context, httpStatus, state.Code ?? "PROTOCOL_OR_AUTH_REJECTED");
                    }
                    else
                    {
                        var settings = await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(CancellationToken.None);
                        state.Context = state.Context with { SystemName = state.Context.SystemName ?? settings?.SystemName,
                            InstanceId = state.Context.InstanceId ?? settings?.InstanceId };
                        var id = state.InvocationId ?? await logs.StartAsync(caller, state.Method, state.ToolName, state.RequestId, state.ProtocolVersion, CancellationToken.None);
                        var success = httpStatus < 400 && state.Success is not false;
                        var code = state.Code;
                        if (httpStatus >= 400 && (code is null or "OK")) code = "HTTP_" + httpStatus;
                        await logs.FinalizeHttpAsync(id, new(httpStatus, startedAt, (long)Stopwatch.GetElapsedTime(timer).TotalMilliseconds,
                            McpAuditCapture.Snapshot(context), success, code ?? (success ? "OK" : "HTTP_" + httpStatus), state.Unknown), CancellationToken.None);
                    }
                }
                catch (Exception exception) when (exception is not OutOfMemoryException)
                {
                    // 处理器开始前的可靠审计失败会阻止业务；响应完成后的补记失败只能明确记录故障，不能再发送第二份响应。
                    logger.LogWarning("MCP最终HTTP审计补记失败，异常类型：{ExceptionType}", exception.GetType().Name);
                }
            }
        }
    }

    /// <summary>仅内存保存有界前缀用于解析固定协议字段，不持久化原文，不拥有底层响应流。</summary>
    private sealed class ResponseCapture(Stream inner, int maximum) : Stream
    {
        private readonly MemoryStream buffer = new();
        public ReadOnlyMemory<byte> Captured => buffer.TryGetBuffer(out var bytes) ? bytes.AsMemory() : ReadOnlyMemory<byte>.Empty;
        public bool Truncated { get; private set; }
        private void Capture(ReadOnlySpan<byte> bytes)
        {
            var available = Math.Max(0, maximum - (int)buffer.Length);
            if (bytes.Length > available) Truncated = true;
            if (available > 0) buffer.Write(bytes[..Math.Min(bytes.Length, available)]);
        }
        public override void Write(byte[] bytes, int offset, int count) { Capture(bytes.AsSpan(offset, count)); inner.Write(bytes, offset, count); }
        public override void Write(ReadOnlySpan<byte> bytes) { Capture(bytes); inner.Write(bytes); }
        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> bytes, CancellationToken ct = default)
        { Capture(bytes.Span); await inner.WriteAsync(bytes, ct); }
        public override Task WriteAsync(byte[] bytes, int offset, int count, CancellationToken ct) => WriteAsync(bytes.AsMemory(offset, count), ct).AsTask();
        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken ct) => inner.FlushAsync(ct);
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] bytes, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        protected override void Dispose(bool disposing) { if (disposing) buffer.Dispose(); base.Dispose(disposing); }
    }
}
