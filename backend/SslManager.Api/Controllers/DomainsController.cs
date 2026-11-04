using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service.impl;

namespace SslManager.Api.Controllers;

[ApiController, Authorize, Route("api/domains")]
public sealed class DomainsController(AppDbContext db, DomainManagementService service) : BusinessController
{
    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20,
        [FromQuery] string? accountId = null, [FromQuery] string? search = null, [FromQuery] string? provider = null, CancellationToken ct = default)
    {
        page = Math.Max(1, page); pageSize = Math.Clamp(pageSize, 1, 200);
        var query = db.Domains.AsNoTracking().Where(x => x.Status != "NotPresent");
        if (!string.IsNullOrWhiteSpace(accountId)) query = query.Where(x => x.AccountId == accountId);
        if (!string.IsNullOrWhiteSpace(provider)) query = query.Where(x => x.Provider == provider);
        if (!string.IsNullOrWhiteSpace(search)) query = query.Where(x => x.Name.Contains(search));
        var total = await query.CountAsync(ct);
        var items = await query.OrderBy(x => x.Name).Skip((page - 1) * pageSize).Take(pageSize)
            .Join(db.CloudAccounts, d => d.AccountId, a => a.Id, (d, a) => new
            { d.Id, d.AccountId, AccountName = a.Name, d.Provider, d.ZoneId, d.Name, d.Status, d.SyncedAtUtc }).ToListAsync(ct);
        return Ok(ApiResult<object>.Ok(new { items, total, page, pageSize }));
    }

    [HttpPost("sync"), Authorize(Roles = "admin")]
    public async Task<IActionResult> Sync(SyncRequest request, CancellationToken ct) => Reply(await service.SyncAsync(request.AccountId, ct));

    [HttpGet("{id}/records")]
    public async Task<IActionResult> Records(string id, CancellationToken ct)
    {
        var result = await service.ListRecordsAsync(id, ct);
        return result.Success && result.Data is not null
            ? Ok(ApiResult<object>.Ok(result.Data.Select(x => new { x.Id, x.Zone, x.Name, x.Type, x.Value, x.Ttl,
                Status = x.Status.Equals("ENABLE", StringComparison.OrdinalIgnoreCase) || x.Status.Equals("Enabled", StringComparison.OrdinalIgnoreCase) ? "Enabled" : "Disabled", x.Line, x.Mx })))
            : Reply(result);
    }

    [HttpPost("{id}/records"), Authorize(Roles = "admin")]
    public async Task<IActionResult> Create(string id, DnsRecordRequest request, CancellationToken ct) => Reply(await service.SaveRecordAsync(id, null, request, ct));
    [HttpPut("{id}/records/{recordId}"), Authorize(Roles = "admin")]
    public async Task<IActionResult> Update(string id, string recordId, DnsRecordRequest request, CancellationToken ct) => Reply(await service.SaveRecordAsync(id, recordId, request, ct));
    [HttpPut("{id}/records/{recordId}/status"), Authorize(Roles = "admin")]
    public async Task<IActionResult> Status(string id, string recordId, RecordStatusRequest request, CancellationToken ct) => Reply(await service.ChangeRecordAsync(id, recordId, request.Enabled, ct));
    [HttpDelete("{id}/records/{recordId}"), Authorize(Roles = "admin")]
    public async Task<IActionResult> Remove(string id, string recordId, CancellationToken ct) => Reply(await service.ChangeRecordAsync(id, recordId, null, ct));
}
