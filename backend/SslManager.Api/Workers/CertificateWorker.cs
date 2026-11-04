using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service.impl;

namespace SslManager.Api.Workers;

/// <summary>单实例持久任务轮询，停机取消正常结束，系统故障保留任务待恢复。</summary>
public sealed class CertificateWorker(IServiceScopeFactory scopes, IConfiguration configuration, ILogger<CertificateWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var seconds = Math.Clamp(configuration.GetValue("Worker:PollSeconds", 15), 5, 300);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopes.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var service = scope.ServiceProvider.GetRequiredService<CertificateManagementService>();
                var domains = scope.ServiceProvider.GetRequiredService<DomainManagementService>();
                var ids = scope.ServiceProvider.GetRequiredService<IIdGenerator>();
                var now = DateTime.UtcNow;
                var jobs = await db.CertificateJobs.AsNoTracking().Where(x => (x.Status == "Waiting" || x.Status == "Submitting" || x.Status == "McpQueued") &&
                    x.NextRunAtUtc <= now && (x.LeaseUntilUtc == null || x.LeaseUntilUtc < now)).OrderBy(x => x.NextRunAtUtc).Select(x => x.Id).Take(10).ToListAsync(stoppingToken);
                foreach (var id in jobs) await service.ProcessJobAsync(id, stoppingToken);
                var autoAccounts = await db.CloudAccounts.Where(x => x.Enabled && x.AutoSyncEnabled &&
                    (x.AutoSyncNextRunAtUtc == null || x.AutoSyncNextRunAtUtc <= now)).ToListAsync(stoppingToken);
                foreach (var account in autoAccounts)
                {
                    var failures = new List<string>();
                    var completed = new List<string>();
                    if (account.UseForDns)
                    {
                        var result = await domains.SyncAsync(account.Id, stoppingToken);
                        (result.Success ? completed : failures).Add("域名：" + result.Message);
                    }
                    if (account.UseForCertificates)
                    {
                        var result = await service.SyncAsync(account.Id, stoppingToken);
                        (result.Success ? completed : failures).Add("证书：" + result.Message);
                    }
                    account.LastAutoSyncAtUtc = now;
                    account.AutoSyncNextRunAtUtc = AutoSyncSchedule.NextRun(account, now);
                    var success = failures.Count == 0;
                    db.AuditLogs.Add(new AuditLog
                    {
                        Id = ids.NewId(), UserId = "system", Username = "system", Action = "AutoSync", ResourceId = account.Id,
                        Success = success, Code = success ? "OK" : "AUTO_SYNC_PARTIAL_FAILED",
                        Message = string.Join("；", completed.Concat(failures)), CreatedAtUtc = now
                    });
                }
                if (autoAccounts.Count > 0) await db.SaveChangesAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception exception) { logger.LogError(exception, "证书任务发生系统异常，将在下一轮恢复"); }
            try { await Task.Delay(TimeSpan.FromSeconds(seconds), stoppingToken); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
