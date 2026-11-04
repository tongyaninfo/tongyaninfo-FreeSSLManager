using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

public sealed partial class CertificateScheduleService
{
    // 仅重新推进已保存的原轮次；权限、身份冲突和人工结束不能被自动重试绕过。
    private static readonly string[] AutomaticRecoveryCodes =
    [
        "SCHEDULE_STEP_INTERRUPTED", "DEPLOYMENT_NEEDS_ATTENTION", "CLEANUP_NEEDS_ATTENTION",
        "NETWORK_ERROR", "CONNECTION_FAILED", "REMOTE_READ_FAILED", "TIMEOUT", "REQUEST_TIMEOUT",
        "RATE_LIMITED", "SERVICE_UNAVAILABLE", "MATERIAL_UNAVAILABLE", "PLAN_STALE",
        "APPLICATION_DNS_RETRY", "REVOCATION_DNS_DELETE_FAILED", "SUBMISSION_RECHECK",
        "REVOCATION_CHALLENGE_UNAVAILABLE", "DEPLOYMENT_BINDING_RECHECK"
    ];

    private static bool RetryableFailure(string code) => AutomaticRecoveryCodes.Contains(code) ||
        code.Contains("Throttl", StringComparison.OrdinalIgnoreCase) ||
        code.Contains("Timeout", StringComparison.OrdinalIgnoreCase) ||
        code.Contains("RateLimit", StringComparison.OrdinalIgnoreCase) ||
        code.Contains("CONNECTION", StringComparison.OrdinalIgnoreCase) ||
        code.Contains("NETWORK", StringComparison.OrdinalIgnoreCase) ||
        code.Contains("ServiceUnavailable", StringComparison.OrdinalIgnoreCase) ||
        code is "REMOTE_RESULT_UNKNOWN" or "DNS_QUERY_FAILED" or "DNS_READ_FAILED" or "REMOTE_READ_FAILED" or
            "REMOTE_WRITE_FAILED" or "FILE_VERIFICATION_FAILED" or "TARGET_BUSY" or "CONFLICT" ||
        DefinitelyRejectedRetryable(code);

    // 这些响应明确表示请求未受理；网络/超时/未知结果不能据此重新提交副作用。
    private static bool DefinitelyRejectedRetryable(string code) =>
        code == "RATE_LIMITED" ||
        code.StartsWith("RequestLimitExceeded", StringComparison.OrdinalIgnoreCase) ||
        code.StartsWith("Throttling", StringComparison.OrdinalIgnoreCase) ||
        code.StartsWith("LimitExceeded.Frequency", StringComparison.OrdinalIgnoreCase);

    private static string RecoveryStage(CertificateScheduleRun run)
    {
        if (string.IsNullOrEmpty(run.CertificateId)) return "Applying";
        var progress = Read<List<ScheduleTargetProgress>>(run.TargetsJson) ?? [];
        if (progress.Count > 0 && progress.All(TargetSucceeded)) return "CleaningOldCertificates";
        return progress.Any(item => item.BatchId.Length > 0 || item.Status != "Pending") ? "Deploying" : "WaitingForIssuance";
    }

    /// <summary>保持当前业务阶段并持久化退避时间；重启不丢失重试进度，也不会回到新申请入口。</summary>
    private async Task RetryRunAsync(CertificateScheduleRun run, string token, string code, string message, CancellationToken ct)
    {
        if (run.Status == "NeedsAttention") run.Status = RecoveryStage(run);
        var snapshot = Read<CertificateScheduleRunSnapshot>(run.ConfigSnapshotJson) ?? throw new InvalidOperationException("运行快照缺失。");
        snapshot.RecoveryAttempts = Math.Min(snapshot.RecoveryAttempts + 1, 1000);
        run.ConfigSnapshotJson = JsonSerializer.Serialize(snapshot, Json);
        run.Code = SafeCode(code); run.Message = message;
        var delay = Math.Min(300, 15 * (1 << Math.Min(snapshot.RecoveryAttempts, 5)));
        await SaveRunAsync(run, token, ct, delay);
    }

    private async Task FailureOrRetryAsync(CertificateScheduleRun run, string token, string code, string message, CancellationToken ct)
    {
        if (RetryableFailure(code)) await RetryRunAsync(run, token, code, message + " 后台将自动继续核对原操作。", ct);
        else await AttentionAsync(run, token, code, message, ct);
    }

    /// <summary>历史成功记录可能在绑定保存前停机；只补缺失绑定，不覆盖后续部署产生的现有绑定。</summary>
    private async Task<bool> RecoverMissingBindingsAsync(CertificateScheduleRun run, string token, CancellationToken ct)
    {
        var certificate = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(item => item.Id == run.CertificateId, ct);
        if (certificate is null || certificate.Status != "Issued" || certificate.NotAfterUtc is null ||
            certificate.NotAfterUtc <= DateTime.UtcNow || certificate.NotBeforeUtc > DateTime.UtcNow) return false;
        var waiting = false;
        var progress = Read<List<ScheduleTargetProgress>>(run.TargetsJson) ?? [];
        foreach (var target in progress.Where(item => TargetSucceeded(item) && item.BatchId.Length > 0))
        {
            var missing = await db.DeploymentTasks.AsNoTracking().Where(task => task.BatchId == target.BatchId &&
                    (task.Status == "Succeeded" || task.Status == "Skipped") &&
                    !db.DeploymentBindings.Any(binding => binding.TargetId == task.TargetId && binding.ResourceKey == task.ResourceKey))
                .ToListAsync(ct);
            foreach (var task in missing)
            {
                if (task.Code != "OK" || task.FinishedAtUtc is null || task.VerificationLevel is not ("FilesChecked" or "PlatformReadback" or "TlsObserved") ||
                    await db.DeploymentTasks.AnyAsync(other => other.Id != task.Id && other.ResourceKey == task.ResourceKey &&
                        other.CreatedAtUtc >= task.CreatedAtUtc && other.Status != "Draft" && other.Status != "Cancelled", ct)) return false;
            }
            if (missing.Count == 0) continue;
            var recovered = await deployments.RecoverForScheduleAsync(target.BatchId, run.Id, token, ct);
            if (!recovered.Success && !RetryableFailure(recovered.Code)) return false;
            // 成功接口返回不代表远端核对已取得证明；暂时缺绑定继续退避，不能永久停在待处理。
            foreach (var task in missing)
                waiting |= !await db.DeploymentBindings.AnyAsync(binding => binding.TargetId == task.TargetId && binding.ResourceKey == task.ResourceKey, ct);
        }
        return waiting;
    }
}
