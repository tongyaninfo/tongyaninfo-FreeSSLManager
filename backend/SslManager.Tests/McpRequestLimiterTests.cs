using SslManager.Api.Common.Mcp;

namespace SslManager.Tests;

/// <summary>限流、并发和有界来源桶回收；不通过真实等待验证分钟边界。</summary>
public sealed class McpRequestLimiterTests
{
    [Fact]
    public void RateAndConcurrencyAreIndependentAndReleaseIsIdempotent()
    {
        var clock = new Clock(); var limiter = new McpRequestLimiter(clock);
        var first = limiter.TryEnter("client:a", 2, 1); Assert.NotNull(first);
        Assert.Null(limiter.TryEnter("client:a", 2, 1));
        first.Dispose(); first.Dispose();
        using var second = limiter.TryEnter("client:a", 2, 1); Assert.NotNull(second);
        second.Dispose();
        Assert.Null(limiter.TryEnter("client:a", 2, 1));
        using var independent = limiter.TryEnter("client:b", 2, 1); Assert.NotNull(independent);
        clock.Advance(TimeSpan.FromMinutes(1));
        using var nextMinute = limiter.TryEnter("client:a", 2, 1); Assert.NotNull(nextMinute);
    }

    [Fact]
    public void InactiveSourcesAreReclaimedWithoutResettingActiveConcurrency()
    {
        var clock = new Clock(); var limiter = new McpRequestLimiter(clock);
        using var active = limiter.TryEnter("active", 20, 1); Assert.NotNull(active);
        for (var i = 0; i < 9999; i++) { using var lease = limiter.TryEnter("source:" + i, 20, 1); Assert.NotNull(lease); }
        Assert.Null(limiter.TryEnter("new-client", 20, 1));
        clock.Advance(TimeSpan.FromMinutes(3));
        using var newClient = limiter.TryEnter("new-client", 20, 1); Assert.NotNull(newClient);
        Assert.Null(limiter.TryEnter("active", 20, 1));
        active.Dispose();
        using var resumed = limiter.TryEnter("active", 20, 1); Assert.NotNull(resumed);
    }

    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset now = new(2026, 11, 2, 12, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan interval) => now += interval;
    }
}
