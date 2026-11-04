namespace SslManager.Api.Common.Mcp;

/// <summary>把已持久化的原调用门禁传递到实际云写入边界；按异步执行流隔离，嵌套作用域共同生效。</summary>
public static class McpCloudMutationGuard
{
    private static readonly AsyncLocal<Frame?> Current = new();
    private sealed record Frame(Func<CancellationToken, Task> BeforeWrite, Frame? Parent, string? OperationId);
    public static string? CurrentOperationId
    {
        get { for (var frame = Current.Value; frame is not null; frame = frame.Parent) if (!string.IsNullOrEmpty(frame.OperationId)) return frame.OperationId; return null; }
    }
    public static IDisposable Enter(Func<CancellationToken, Task> beforeWrite, string? operationId = null)
    {
        var previous = Current.Value;
        var frame = new Frame(beforeWrite, previous, operationId); Current.Value = frame;
        return new Scope(frame, previous);
    }
    public static async Task CheckBeforeMutationAsync(CancellationToken ct)
    {
        for (var frame = Current.Value; frame is not null; frame = frame.Parent) await frame.BeforeWrite(ct);
    }
    private sealed class Scope(Frame frame, Frame? previous) : IDisposable
    {
        private bool disposed;
        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            if (ReferenceEquals(Current.Value, frame)) Current.Value = previous;
        }
    }
}
