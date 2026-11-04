using SslManager.Api.Service;

namespace SslManager.Api.Workers;

/// <summary>每分钟核对本地证书和持久预警状态，不调用云端同步；停机后沿原请求键继续核对。</summary>
public sealed class CertificateExpiryReminderWorker(IServiceScopeFactory scopes, TimeProvider timeProvider,
    ILogger<CertificateExpiryReminderWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopes.CreateScope();
                await scope.ServiceProvider.GetRequiredService<IExpiryReminderService>().ProcessAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            { logger.LogWarning("证书到期提醒检查未完成，异常类型={ExceptionType}，下一轮继续核对。", exception.GetType().Name); }
            try { await Task.Delay(TimeSpan.FromMinutes(1), timeProvider, stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
