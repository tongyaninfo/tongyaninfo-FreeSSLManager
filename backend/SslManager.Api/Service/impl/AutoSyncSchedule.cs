using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

public static class AutoSyncSchedule
{
    private static readonly TimeZoneInfo ChinaTimeZone = ResolveChinaTimeZone();

    public static DateTime NextRun(CloudAccount account, DateTime utcNow)
    {
        var localNow = TimeZoneInfo.ConvertTimeFromUtc(DateTime.SpecifyKind(utcNow, DateTimeKind.Utc), ChinaTimeZone);
        var time = TimeOnly.TryParseExact(account.AutoSyncAtLocalTime, "HH:mm", out var parsed) ? parsed : new TimeOnly(2, 0);
        DateTime local = account.AutoSyncIntervalUnit switch
        {
            "minute" => localNow.AddMinutes(account.AutoSyncIntervalValue),
            "hour" => localNow.AddHours(account.AutoSyncIntervalValue),
            "month" => localNow.AddMonths(account.AutoSyncIntervalValue).Date.Add(time.ToTimeSpan()),
            _ => localNow.Date.AddDays(account.AutoSyncIntervalValue).Add(time.ToTimeSpan())
        };
        return TimeZoneInfo.ConvertTimeToUtc(DateTime.SpecifyKind(local, DateTimeKind.Unspecified), ChinaTimeZone);
    }

    private static TimeZoneInfo ResolveChinaTimeZone()
    {
        try { return TimeZoneInfo.FindSystemTimeZoneById("Asia/Shanghai"); }
        catch (TimeZoneNotFoundException) { return TimeZoneInfo.Utc; }
        catch (InvalidTimeZoneException) { return TimeZoneInfo.Utc; }
    }
}
