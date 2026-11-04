using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;

namespace SslManager.Api.Controllers;

[ApiController, Authorize, Route("api/certificates")]
public sealed class CertificatesController(AppDbContext db, CertificateManagementService service,
    ICertificateMaterialService materials) : BusinessController
{
    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20,
        [FromQuery] string? accountId = null, [FromQuery] string? search = null, [FromQuery] string? status = null,
        [FromQuery] bool freeOnly = false, [FromQuery] string? provider = null, CancellationToken ct = default)
    {
        page = Math.Max(1, page); pageSize = Math.Clamp(pageSize, 1, 200);
        var query = db.Certificates.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(accountId)) query = query.Where(x => x.AccountId == accountId);
        if (!string.IsNullOrWhiteSpace(provider)) query = query.Where(x => x.Provider == provider);
        if (!string.IsNullOrWhiteSpace(search)) query = query.Where(x => x.Domain.Contains(search) || x.Alias.Contains(search));
        if (!string.IsNullOrWhiteSpace(status)) query = query.Where(x => x.Status == status);
        if (freeOnly) query = query.Where(x => x.IsFree == true);
        var total = await query.CountAsync(ct);
        // 有到期日的证书优先按到期日倒序；没有到期日的记录统一置后，再按最近快照时间倒序。
        // 当前实体没有独立创建时间，SyncedAtUtc 作为无到期日记录的稳定次级排序。
        // 先关联账号再排序和分页，确保数据库最终返回顺序与页面看到的顺序一致。
        var rows = await query
            .Join(db.CloudAccounts, c => c.AccountId, a => a.Id, (c, a) => new
            { c.Id, c.AccountId, AccountName = a.Name, c.Provider, c.CertificateId, c.OrderId, c.InstanceId, c.ApiVersion,
                c.Domain, c.Alias, c.ProductCode, c.IsFree, c.Status, c.RawStatus, c.NotBeforeUtc, c.NotAfterUtc,
                c.ValidationMode, c.AutoCleanup, c.DnsZoneId, c.CleanupStatus, c.SyncedAtUtc })
            .OrderByDescending(x => x.NotAfterUtc.HasValue)
            .ThenByDescending(x => x.NotAfterUtc)
            .ThenByDescending(x => x.SyncedAtUtc)
            .Skip((page - 1) * pageSize).Take(pageSize)
            .ToListAsync(ct);
        var items = rows.Select(x => new
        {
            x.Id, x.AccountId, x.AccountName, x.Provider, x.CertificateId, x.OrderId, x.InstanceId, x.ApiVersion,
            Domain = CertificateManagementService.PrimaryDomain(x.Domain), x.Alias, x.ProductCode, x.IsFree, x.Status,
            x.RawStatus, x.NotBeforeUtc, x.NotAfterUtc, x.ValidationMode, x.AutoCleanup, x.DnsZoneId, x.CleanupStatus, x.SyncedAtUtc
        }).ToArray();
        return Ok(ApiResult<object>.Ok(new { items, total, page, pageSize }));
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> Detail(string id, CancellationToken ct)
    {
        var certificate = await db.Certificates.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct);
        if (certificate is null) return NotFound(ApiResult<object>.Fail("NOT_FOUND", "证书不存在"));
        certificate.Domain = CertificateManagementService.PrimaryDomain(certificate.Domain);
        var validations = await db.ValidationRecords.AsNoTracking().Where(x => x.CertificateId == id).ToListAsync(ct);
        var tasks = await db.CertificateJobs.AsNoTracking().Where(x => x.CertificateId == id).OrderByDescending(x => x.CreatedAtUtc).ToListAsync(ct);
        return Ok(ApiResult<object>.Ok(new { certificate, validations, tasks }));
    }
    [HttpPost("sync"), Authorize(Roles = "admin")]
    public async Task<IActionResult> Sync(SyncRequest request, CancellationToken ct) => Reply(await service.SyncAsync(request.AccountId, ct));
    [HttpPost("apply"), Authorize(Roles = "admin")]
    public async Task<IActionResult> Apply(CertificateApplyRequest request, CancellationToken ct) => Reply(await service.ApplyAsync(request, ct));
    [HttpPost("{id}/revoke"), Authorize(Roles = "admin")]
    public async Task<IActionResult> Revoke(string id, RevokeRequest request, CancellationToken ct) => Reply(await service.RevokeAsync(id, request.Reason, ct));
    [HttpPost("{id}/cancel"), Authorize(Roles = "admin")]
    public async Task<IActionResult> Cancel(string id, CancellationToken ct) => Reply(await service.CancelAsync(id, ct));
    [HttpDelete("{id}"), Authorize(Roles = "admin")]
    public async Task<IActionResult> Delete(string id, CancellationToken ct) => Reply(await service.DeleteAsync(id, ct));
    [HttpDelete, Authorize(Roles = "admin")]
    public async Task<IActionResult> DeleteBatch(BatchDeleteRequest request, CancellationToken ct)
        => Reply(await service.DeleteBatchAsync(request.Ids ?? [], ct));
    [HttpPost("{id}/cleanup-retry"), Authorize(Roles = "admin")]
    public async Task<IActionResult> Cleanup(string id, CancellationToken ct) => Reply(await service.RetryCleanupAsync(id, ct));
    [HttpGet("{id}/download"), Authorize(Roles = "admin")]
    public async Task<IActionResult> Download(string id, [FromQuery] string format = "nginx", CancellationToken ct = default)
    {
        var result = await service.DownloadAsync(id, format, ct);
        Response.Headers.CacheControl = "no-store";
        if (!result.Success || result.Data is null) return Reply(result);
        return File(result.Data.Content, result.Data.ContentType, result.Data.FileName);
    }

    [HttpGet("{id}/deployment-files"), Authorize(Roles = "admin")]
    public async Task<IActionResult> DeploymentFiles(string id, [FromQuery] string format = "nginx", CancellationToken ct = default)
    {
        Response.Headers.CacheControl = "no-store";
        var material = await materials.GetAsync(id, ct);
        if (!material.Success || material.Data is null) return Reply(material);
        var source = await materials.GetSourceAsync(id, format, material.Data.Metadata, ct);
        if (!source.Success || source.Data is null) return Reply(source);
        var files = source.Data.Files.Select(file => new CertificateSourceFileMetadata(file.Name, file.Role,
            file.Content.LongLength, file.Sha256, file.ContainsSecrets)).ToArray();
        return Reply(ApiResult<CertificateSourceListing>.Ok(new(id, material.Data.Metadata.Domain, source.Data.Format, files)));
    }
}
