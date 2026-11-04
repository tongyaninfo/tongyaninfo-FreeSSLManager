using SslManager.Api.Service;

namespace SslManager.Api.Workers;

/// <summary>每一步使用新作用域；本轮进度和租约在数据库中，浏览器关闭或服务重启不丢失。</summary>
public sealed class CertificateScheduleWorker(IServiceScopeFactory scopes, ILogger<CertificateScheduleWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopes.CreateScope();
                if (await scope.ServiceProvider.GetRequiredService<ICertificateScheduleService>().ProcessNextAsync(stoppingToken))
                    continue;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                // 不输出可能回显云凭据或材料的异常正文。
                logger.LogError("周期证书任务轮询失败，异常类型={ExceptionType}", exception.GetType().Name);
            }
            try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
