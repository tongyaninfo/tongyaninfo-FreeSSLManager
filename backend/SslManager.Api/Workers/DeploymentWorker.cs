using SslManager.Api.Service;
namespace SslManager.Api.Workers;

/// <summary>部署独立轮询，不占用证书签发 Worker 或证书操作全局锁。</summary>
public sealed class DeploymentWorker(IServiceScopeFactory scopes, ILogger<DeploymentWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopes.CreateScope();
                var service = scope.ServiceProvider.GetRequiredService<IDeploymentService>();
                if (await service.ProcessNextAsync(stoppingToken)) continue;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            {
                // 不记录远端原始异常正文，避免设备回显凭据或材料。
                logger.LogError("部署任务轮询失败，异常类型={ExceptionType}", exception.GetType().Name);
            }
            try { await Task.Delay(TimeSpan.FromSeconds(3), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
