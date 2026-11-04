namespace SslManager.Api.Common;

/// <summary>以首次执行点为日历锚点；月底缩短后下月恢复原日期，不从完成时间递推。</summary>
public static class CertificateScheduleTiming
{
    private static readonly TimeZoneInfo China = TimeZoneInfo.FindSystemTimeZoneById("Asia/Shanghai");

    public static DateTime EnsureUtc(DateTime value) => value.Kind == DateTimeKind.Local
        ? value.ToUniversalTime() : DateTime.SpecifyKind(value, DateTimeKind.Utc);

    public static DateTime NextAfter(DateTime firstRunAtUtc, int intervalValue, string intervalUnit, DateTime utcNow)
    {
        if (intervalValue is < 1 or > 1200 || intervalUnit is not ("hour" or "day" or "month"))
            throw new ArgumentException("计划周期必须为 1 至 1200 小时、天或月。");
        var first = EnsureUtc(firstRunAtUtc);
        var now = EnsureUtc(utcNow);
        if (first > now) return first;
        if (intervalUnit == "hour")
        {
            var step = TimeSpan.FromHours(intervalValue).Ticks;
            return first.AddTicks(checked(((now.Ticks - first.Ticks) / step + 1) * step));
        }
        var localFirst = TimeZoneInfo.ConvertTimeFromUtc(first, China);
        var localNow = TimeZoneInfo.ConvertTimeFromUtc(now, China);
        var index = intervalUnit == "day"
            ? (long)Math.Floor((localNow - localFirst).TotalDays / intervalValue)
            : ((localNow.Year - localFirst.Year) * 12L + localNow.Month - localFirst.Month) / intervalValue;
        index = Math.Max(index, 0);
        DateTime candidate;
        do
        {
            candidate = intervalUnit == "day" ? localFirst.AddDays(checked(index * intervalValue))
                : localFirst.AddMonths(checked((int)(index * intervalValue)));
            index++;
        } while (candidate <= localNow);
        return TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(candidate, DateTimeKind.Unspecified), China);
    }
}
