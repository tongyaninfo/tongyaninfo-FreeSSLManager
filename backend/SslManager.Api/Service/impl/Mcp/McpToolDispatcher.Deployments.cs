using System.Linq.Expressions;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Mcp;

public sealed partial class McpToolDispatcher
{
    private async Task<string[]> AllowedTargetIdsAsync(McpAllowRuleInput rule, CancellationToken ct)
    {
        var candidates = await db.DeploymentTargets.AsNoTracking()
            .Where(McpQueryFilters.Build<DeploymentTarget>([rule], target: x => x.Id))
            .Select(x => new { x.Id, x.ConfigurationJson }).ToArrayAsync(ct);
        var ids = new List<string>();
        foreach (var candidate in candidates)
        {
            try
            {
                using var document = JsonDocument.Parse(candidate.ConfigurationJson);
                var domain = document.RootElement.TryGetProperty("sourceDomain", out var value) && value.ValueKind == JsonValueKind.String
                    ? value.GetString() ?? "" : "";
                // 通用平台目标没有固定域名时，只返回显式授权的目标摘要；实际部署另按证书校验域名。
                if (domain.Length == 0 || McpQueryFilters.DomainMatches(domain, rule)) ids.Add(candidate.Id);
            }
            catch (JsonException) { /* 无法识别目标配置时拒绝推断范围。 */ }
        }
        return ids.ToArray();
    }

    private async Task<ApiResult<object>> TargetsAsync(McpEffectivePermission permission, JsonElement input, CancellationToken ct)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        var domain = Text(input, "domain");
        foreach (var rule in permission.Rules)
        {
            if (domain.Length > 0 && !McpQueryFilters.DomainMatches(domain, rule)) continue;
            foreach (var id in await AllowedTargetIdsAsync(rule, ct)) ids.Add(id);
        }
        var allowed = ids.ToArray();
        var query = db.DeploymentTargets.AsNoTracking().Where(x => allowed.Contains(x.Id));
        return await PageAsync(query.OrderBy(x => x.Name).ThenBy(x => x.Id).Select(x => new
        { x.Id, x.Name, x.ExecutorKey, x.Enabled, x.ConfigRevision, x.ProductVersion, x.LastTestAtUtc,
            x.LastTestSuccess, x.LastDeploymentAtUtc, x.LastDeploymentStatus }), input, ct);
    }

    private async Task<IQueryable<DeploymentBatch>> AllowedBatchesAsync(McpEffectivePermission permission, CancellationToken ct)
    {
        Expression<Func<DeploymentBatch, bool>> visible = _ => false;
        foreach (var rule in permission.Rules)
        {
            var certificates = db.Certificates.AsNoTracking()
                .Where(McpQueryFilters.Build<ManagedCertificate>([rule], x => x.AccountId, x => x.Domain));
            var targets = await AllowedTargetIdsAsync(rule, ct);
            // 一条完整规则必须同时覆盖证书和该批次所有目标，禁止跨规则拼接权限或泄露其他目标。
            Expression<Func<DeploymentBatch, bool>> match = batch => certificates.Any(certificate => certificate.Id == batch.CertificateId) &&
                !db.DeploymentTasks.Any(task => task.BatchId == batch.Id && !targets.Contains(task.TargetId));
            visible = McpQueryFilters.Or(visible, match);
        }
        return db.DeploymentBatches.AsNoTracking().Where(visible);
    }

    private async Task<ApiResult<object>> BatchesAsync(McpEffectivePermission permission, JsonElement input, CancellationToken ct)
    {
        var query = await AllowedBatchesAsync(permission, ct);
        var certificate = Text(input, "certificateId"); var target = Text(input, "targetId"); var status = Text(input, "status");
        if (certificate.Length > 0) query = query.Where(x => x.CertificateId == certificate);
        if (target.Length > 0) query = query.Where(x => db.DeploymentTasks.Any(task => task.BatchId == x.Id && task.TargetId == target));
        if (status.Length > 0) query = query.Where(x => x.Status == status);
        return await PageAsync(query.OrderByDescending(x => x.CreatedAtUtc).ThenBy(x => x.Id).Select(x => new
        { x.Id, x.CertificateId, x.CertificateDomain, x.Status, x.OperationType, x.CreatedAtUtc, x.SubmittedAtUtc }), input, ct);
    }

    private async Task<ApiResult<object>> BatchAsync(McpEffectivePermission permission, string id, CancellationToken ct)
    {
        var query = await AllowedBatchesAsync(permission, ct);
        var batch = await query.Where(x => x.Id == id).Select(x => new
        { x.Id, x.CertificateId, x.CertificateDomain, x.Status, x.OperationType, x.Fingerprint,
            x.PlanRevision, x.CreatedAtUtc, x.ExpiresAtUtc, x.SubmittedAtUtc }).SingleOrDefaultAsync(ct);
        if (batch is null) return Missing();
        var tasks = await db.DeploymentTasks.AsNoTracking().Where(x => x.BatchId == id).OrderBy(x => x.CreatedAtUtc)
            .Select(x => new { x.Id, x.TargetId, x.TargetName, x.ExecutorKey, x.Status, x.Phase, x.Code,
                x.VerificationLevel, x.CreatedAtUtc, x.StartedAtUtc, x.FinishedAtUtc }).ToArrayAsync(ct);
        return ApiResult<object>.Ok(new { batch, tasks });
    }

    private async Task<ApiResult<object>> TaskAsync(McpEffectivePermission permission, string id, CancellationToken ct)
    {
        var batches = await AllowedBatchesAsync(permission, ct);
        var task = await db.DeploymentTasks.AsNoTracking().Where(x => x.Id == id && batches.Any(batch => batch.Id == x.BatchId))
            .Select(x => new { x.Id, x.BatchId, x.TargetId, x.TargetName, x.ExecutorKey, x.Status, x.Phase, x.Code,
                x.VerificationLevel, x.Fingerprint, x.CreatedAtUtc, x.StartedAtUtc, x.FinishedAtUtc }).SingleOrDefaultAsync(ct);
        if (task is null) return Missing();
        var steps = await db.DeploymentTaskSteps.AsNoTracking().Where(x => x.TaskId == id).OrderBy(x => x.CreatedAtUtc)
            .Take(200).Select(x => new { x.Id, x.Phase, x.Status, x.CreatedAtUtc }).ToArrayAsync(ct);
        return ApiResult<object>.Ok(new { task, steps });
    }
}
