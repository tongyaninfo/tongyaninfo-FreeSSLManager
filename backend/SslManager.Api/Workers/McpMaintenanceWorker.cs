using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Api.Workers;

/// <summary>MCP 调用日志定期核对和保留策略；所有业务任务仍由原 Worker 执行。</summary>
public sealed class McpMaintenanceWorker(IServiceScopeFactory scopes, ILogger<McpMaintenanceWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopes.CreateScope();
                await scope.ServiceProvider.GetRequiredService<McpMaintenanceService>().SweepAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception)
            { logger.LogWarning("MCP 日志维护未完成，异常类型={ExceptionType}", exception.GetType().Name); }
            try { await Task.Delay(TimeSpan.FromMinutes(10), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
