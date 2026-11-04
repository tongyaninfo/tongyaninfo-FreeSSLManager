using SslManager.Api.Common;

namespace SslManager.Tests;

/// <summary>使用固定时钟验证日历锚点、月底恢复和停机后只跳到未来一个执行点。</summary>
public sealed class CertificateScheduleTimingTests
{
    [Theory]
    [InlineData("2027-01-30T18:00:00Z", 1, "month", "2027-02-01T00:00:00Z", "2027-02-27T18:00:00Z")]
    [InlineData("2027-01-30T18:00:00Z", 1, "month", "2027-02-27T18:00:00Z", "2027-03-30T18:00:00Z")]
    [InlineData("2028-01-30T18:00:00Z", 1, "month", "2028-02-01T00:00:00Z", "2028-02-28T18:00:00Z")]
    [InlineData("2027-01-30T18:00:00Z", 2, "month", "2027-04-15T00:00:00Z", "2027-05-30T18:00:00Z")]
    [InlineData("2027-01-01T18:00:00Z", 3, "day", "2027-01-10T19:00:00Z", "2027-01-13T18:00:00Z")]
    [InlineData("2027-01-01T18:15:00Z", 4, "hour", "2027-01-02T06:15:00Z", "2027-01-02T10:15:00Z")]
    [InlineData("2027-01-01T18:15:00Z", 1, "hour", "2026-11-01T00:00:00Z", "2027-01-01T18:15:00Z")]
    public void NextRunUsesTheOriginalShanghaiAnchor(string first, int interval, string unit, string now, string expected)
    {
        var result = CertificateScheduleTiming.NextAfter(DateTime.Parse(first).ToUniversalTime(), interval, unit, DateTime.Parse(now).ToUniversalTime());
        Assert.Equal(DateTime.Parse(expected).ToUniversalTime(), result);
        Assert.Equal(DateTimeKind.Utc, result.Kind);
    }

    [Theory]
    [InlineData(0, "hour")]
    [InlineData(1201, "month")]
    [InlineData(1, "minute")]
    public void UnsupportedIntervalsCannotStartAPlan(int interval, string unit) =>
        Assert.Throws<ArgumentException>(() => CertificateScheduleTiming.NextAfter(DateTime.UtcNow, interval, unit, DateTime.UtcNow));
}
