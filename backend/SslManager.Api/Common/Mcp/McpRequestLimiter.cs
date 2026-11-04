namespace SslManager.Api.Common.Mcp;

/// <summary>当前单实例限流与并发边界；不将进程内计数宣称为多实例全局限流。</summary>
public sealed class McpRequestLimiter(TimeProvider? timeProvider = null)
{
    private readonly Dictionary<string, Bucket> buckets = new(StringComparer.Ordinal);
    private readonly object gate = new();
    private readonly TimeProvider clock = timeProvider ?? TimeProvider.System;
    private long lastPrunedMinute = -1;
    public IDisposable? TryEnter(string key, int perMinute, int concurrent)
    {
        lock (gate)
        {
            var minute = clock.GetUtcNow().Ticks / TimeSpan.TicksPerMinute;
            if (minute != lastPrunedMinute)
            {
                // 有活动调用的桶永不移除；取桶及回收共用锁，避免旧桶和新桶同时放行。
                foreach (var item in buckets.ToArray())
                    lock (item.Value)
                        if (item.Value.Active == 0 && item.Value.Minute < minute - 2) buckets.Remove(item.Key);
                lastPrunedMinute = minute;
            }
            if (!buckets.TryGetValue(key, out var bucket))
            {
                if (buckets.Count >= 10000) return null;
                buckets[key] = bucket = new();
            }
            lock (bucket)
            {
                if (minute != bucket.Minute) { bucket.Minute = minute; bucket.Requests = 0; }
                if (bucket.Requests >= perMinute || bucket.Active >= concurrent) return null;
                bucket.Requests++; bucket.Active++; return new Release(bucket);
            }
        }
    }
    private sealed class Bucket { public long Minute; public int Requests; public int Active; }
    private sealed class Release(Bucket bucket) : IDisposable
    {
        private int disposed;
        public void Dispose() { if (Interlocked.Exchange(ref disposed, 1) == 0) lock (bucket) bucket.Active--; }
    }
}
