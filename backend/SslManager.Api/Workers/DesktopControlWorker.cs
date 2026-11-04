using System.Text.Json;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service;

namespace SslManager.Api.Workers;

/// <summary>父进程私有控制管道；EOF 表示 Electron 已退出，自动优雅停止以免残留后台进程。</summary>
public sealed class DesktopControlWorker(DesktopRuntime runtime, IDesktopBackupService backups,
    IHostApplicationLifetime lifetime, ILogger<DesktopControlWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var line = await Console.In.ReadLineAsync(stoppingToken);
                if (line is null) { lifetime.StopApplication(); return; }
                DesktopControlRequest? command = null;
                try { if (line.Length <= 16384) command = JsonSerializer.Deserialize<DesktopControlRequest>(line, DesktopRuntime.Json); }
                catch (JsonException) { }
                if (command is null || command.RequestId.Length is 0 or > 80 || command.RequestId.Any(value => !char.IsAsciiLetterOrDigit(value) && value is not ('-' or '_')))
                { runtime.Emit(new { type = "response", requestId = "", success = false, code = "INVALID_COMMAND", message = "桌面控制命令格式不正确。" }); continue; }
                if (command.Type == "shutdown")
                {
                    runtime.Emit(new { type = "response", requestId = command.RequestId, success = true, code = "OK", message = "正在保存状态并停止本地服务。" });
                    lifetime.StopApplication(); return;
                }
                if (command.Type == "backup")
                {
                    var result = await backups.CreateAsync(command.Destination, stoppingToken);
                    runtime.Emit(new { type = "response", requestId = command.RequestId, result.Success, result.Code, result.Message, result.Data });
                    continue;
                }
                runtime.Emit(new { type = "response", requestId = command.RequestId, success = false, code = "UNKNOWN_COMMAND", message = "不支持此桌面控制命令。" });
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        catch (Exception exception)
        {
            logger.LogError("桌面控制管道异常，异常类型={ExceptionType}", exception.GetType().Name);
            lifetime.StopApplication();
        }
    }
}
