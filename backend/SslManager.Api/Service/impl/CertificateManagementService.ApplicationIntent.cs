using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl;

/// <summary>Web 与 MCP 共用参数校验、意图和唯一一次云派发；MCP 仅把首次派发移至现有 Worker。</summary>
public sealed partial class CertificateManagementService
{
    private sealed record PreparedCertificateApplication(CertificateApplyRequest Request, string Domain, CertificateContext Context);

    private async Task<ApiResult<PreparedCertificateApplication>> PrepareApplicationInternalAsync(CertificateApplyRequest request, CancellationToken ct)
    {
        var domain = request.Domain?.Trim().ToLowerInvariant().TrimEnd('.') ?? "";
        if (!IsValidDomain(domain)) return ApiResult<PreparedCertificateApplication>.Fail("INVALID_DOMAIN", "请输入有效的单个域名，免费证书不支持 IP、泛域名或 URL");
        if (!new[] { "NativeAutoDns", "ManagedDns", "ManualDns", "File" }.Contains(request.ValidationMode))
            return ApiResult<PreparedCertificateApplication>.Fail("INVALID_VALIDATION_MODE", "不支持的验证方式");
        var context = await ResolveAccountAsync(request.AccountId, ct);
        if (!context.Success || context.Data is null) return ApiResult<PreparedCertificateApplication>.Fail(context.Code, context.Message);
        if (context.Data.Account.Provider == "Acme" && request.ValidationMode is not ("ManagedDns" or "ManualDns"))
            return ApiResult<PreparedCertificateApplication>.Fail("UNSUPPORTED_MODE", "ACME 当前支持系统自动 DNS 或手动 DNS-01 验证。");
        if (request.ValidationMode == "NativeAutoDns")
        {
            if (context.Data.Account.Provider is not ("TencentCloud" or "Aliyun")) return ApiResult<PreparedCertificateApplication>.Fail("UNSUPPORTED_MODE", "此平台请使用系统自动 DNS 或手动验证");
            var hosted = await db.Domains.AnyAsync(x => x.AccountId == request.AccountId && x.Status != "NotPresent" &&
                (x.Name == domain || domain.EndsWith("." + x.Name)), ct);
            if (!hosted) return ApiResult<PreparedCertificateApplication>.Fail("DNS_ACCOUNT_MISMATCH", "请先同步同一证书账号的 DNS 托管域，或改用手动验证");
            // 腾讯云由原生接口负责 DNS 记录；阿里云 CAS 没有对应的自动删除参数，复用本平台托管域编排，
            // 但保留 NativeAutoDns 语义以便详情页准确显示用户选择的验证方式。
        }
        if (request.ValidationMode == "ManagedDns" ||
            (request.ValidationMode == "NativeAutoDns" && context.Data.Account.Provider == "Aliyun"))
        {
            // DNS 托管域由证书申请账号自动确定。保留旧请求中的 DnsZoneId 兼容已有调用方，
            // 新申请不再要求用户选择；无值时按同一账号下覆盖申请域名的最长域名后缀匹配。
            var dnsZoneId = request.DnsZoneId;
            if (string.IsNullOrWhiteSpace(dnsZoneId))
            {
                if (!context.Data.Account.UseForDns)
                    return ApiResult<PreparedCertificateApplication>.Fail("DNS_DISABLED", "当前证书申请账号未启用 DNS 管理，无法使用本平台托管 DNS 验证");
                var candidates = await db.Domains.AsNoTracking()
                    .Where(x => x.AccountId == request.AccountId && x.Status != "NotPresent")
                    .ToListAsync(ct);
                dnsZoneId = candidates
                    .Where(x => BelongsTo(domain, x.Name))
                    .OrderByDescending(x => x.Name.Length)
                    .Select(x => x.Id)
                    .FirstOrDefault();
                if (string.IsNullOrWhiteSpace(dnsZoneId))
                    return ApiResult<PreparedCertificateApplication>.Fail("DNS_ZONE_NOT_FOUND", "请先同步当前证书申请账号的 DNS 托管域，系统会自动匹配覆盖申请域名的区域");
            }
            var dns = await domains.ResolveAsync(dnsZoneId, ct);
            if (!dns.Success || dns.Data is null) return ApiResult<PreparedCertificateApplication>.Fail(dns.Code, dns.Message);
            if (!BelongsTo(domain, dns.Data.Domain.Name)) return ApiResult<PreparedCertificateApplication>.Fail("DNS_ZONE_MISMATCH", "申请域名不属于所选 DNS 托管域");
            request = request with { DnsZoneId = dnsZoneId };
        }


        request = request with { Domain = domain };
        return ApiResult<PreparedCertificateApplication>.Ok(new(request, domain, context.Data));
    }

    private (ManagedCertificate Certificate, CertificateJob Job) CreateApplicationIntent(CertificateApplyRequest request,
        string domain, string provider, string jobStatus, bool isStaging = false)
    {
            var entity = new ManagedCertificate
            {
                Id = ids.NewId(), AccountId = request.AccountId, Provider = provider, Domain = domain,
                Alias = request.Alias, ValidationMode = request.ValidationMode, AutoCleanup = request.AutoCleanup,
                HasPrivateKey = provider != "Acme",
                IsStaging = isStaging,
                DnsZoneId = request.DnsZoneId, ApiVersion = request.ApiVersion, InstanceId = request.InstanceId ?? "",
                Status = "Submitting", CleanupStatus = request.AutoCleanup && request.ValidationMode is ("NativeAutoDns" or "ManagedDns") ? "Pending" : "NotRequested",
                SyncedAtUtc = DateTime.UtcNow
            };
            var job = new CertificateJob { Id = ids.NewId(), CertificateId = entity.Id, Status = jobStatus, CreatedAtUtc = DateTime.UtcNow, NextRunAtUtc = DateTime.UtcNow };
            db.Certificates.Add(entity); db.CertificateJobs.Add(job);

        return (entity, job);
    }

    private async Task<ApiResult<ManagedCertificate>> DispatchApplicationInternalAsync(ManagedCertificate entity,
        CertificateJob job, CertificateApplyRequest request, CertificateContext context, CancellationToken ct)
    {
            ApiResult<CloudCertificateDetail> response;
            try
            {
                response = await context.Provider.ApplyAsync(context.Account,
                    new(entity.Domain, request.ValidationMode, request.AutoCleanup, request.InstanceId, request.ApiVersion, request.Alias,
                        entity.Id), ct);
            }
            catch (Exception) when (!ct.IsCancellationRequested)
            {
                entity.Status = "SubmissionUnknown"; job.Status = "SubmissionUnknown";
                job.Message = "提交发生系统故障，结果未知；请核对云端订单，系统不会重复申请";
                await db.SaveChangesAsync(ct);
                throw; // 基础设施异常交由系统异常边界记录。
            }
            if (!response.Success || response.Data is null)
            {
                if (context.Account.Provider == "Acme")
                {
                    var issuance = await db.CertificateIssuanceStates.AsNoTracking().SingleOrDefaultAsync(x => x.Id == entity.Id &&
                        x.AccountId == entity.AccountId && x.Provider == "Acme", ct);
                    if (issuance is { OrderUrl.Length: > 0 })
                    {
                        // CA 已受理且订单引用已落库；后续查询失败仍由原任务核对，不丢失引用或重新下单。
                        entity.OrderId = issuance.OrderUrl; entity.CertificateId = issuance.RemoteCertificateId;
                        entity.ApiVersion = "AcmeV2"; entity.Status = "Processing";
                        job.Status = "Waiting"; job.Message = "原 ACME 订单已保存，等待继续核对验证与签发状态。";
                        await db.SaveChangesAsync(ct);
                        return ApiResult<ManagedCertificate>.Ok(entity, job.Message);
                    }
                }
                var uncertain = IsUncertain(response.Code);
                entity.Status = uncertain ? "SubmissionUnknown" : "Failed";
                job.Status = entity.Status; job.Message = response.Message;
                await db.SaveChangesAsync(ct);
                return ApiResult<ManagedCertificate>.Fail(response.Code, response.Message);
            }
            Copy(response.Data.Certificate, entity);
            job.Status = "Waiting"; job.Message = "申请已提交，等待验证与签发"; job.RequestId = response.Data.Certificate.RequestId;
            await SaveChallengesAsync(entity, response.Data.Challenges, ct);
            await db.SaveChangesAsync(ct);
            return ApiResult<ManagedCertificate>.Ok(entity, "申请已提交");

    }

    /// <summary>由 MCP Submit 的同一事务调用；此处只记账，不调用任何云端写接口。</summary>
    internal async Task<ApiResult<ManagedCertificate>> QueueForMcpAsync(CertificateApplyRequest request, McpOperation operation, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is null) throw new InvalidOperationException("MCP 申请意图必须与 operation 在同一事务内保存。");
        var prepared = await PrepareApplicationInternalAsync(request, ct);
        if (!prepared.Success || prepared.Data is null) return ApiResult<ManagedCertificate>.Fail(prepared.Code, prepared.Message);
        request = prepared.Data.Request;
        if (await db.Certificates.AnyAsync(row => row.AccountId == request.AccountId && row.Domain == prepared.Data.Domain &&
            (row.Status == "Submitting" || row.Status == "SubmissionUnknown" || row.Status == "PendingValidation" || row.Status == "Processing"), ct))
            return ApiResult<ManagedCertificate>.Fail("APPLICATION_IN_PROGRESS", "该账号下此域名已有进行中或结果未知的申请。");
        var (certificate, job) = CreateApplicationIntent(request, prepared.Data.Domain, prepared.Data.Context.Account.Provider, "McpQueued",
            prepared.Data.Context.Account.Provider == "Acme" && prepared.Data.Context.Account.AcmeDirectoryUrl == AcmeProtocolClient.StagingDirectory);
        operation.CertificateId = certificate.Id; operation.CertificateJobId = job.Id; operation.Status = "Queued";
        operation.Message = "申请意图已受理，等待现有证书 Worker 首次派发。"; operation.Code = "QUEUED";
        await db.SaveChangesAsync(ct);
        return ApiResult<ManagedCertificate>.Ok(certificate, operation.Message);
    }
}
