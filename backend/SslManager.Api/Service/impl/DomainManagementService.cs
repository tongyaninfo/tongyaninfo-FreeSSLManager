using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

public sealed partial class DomainManagementService(AppDbContext db, ICloudAccountStore accounts,
    ICloudProviderResolver providers, IIdGenerator ids)
{
    public async Task<ApiResult<int>> SyncAsync(string accountId, CancellationToken ct)
        => await SyncCoreAsync(accountId, null, ct);

    private async Task<ApiResult<int>> SyncCoreAsync(string accountId, Func<CancellationToken, Task<ApiResult<bool>>>? beforeWrite, CancellationToken ct)
    {
        var credentials = await accounts.GetCredentialsAsync(accountId, ct);
        if (!credentials.Success || credentials.Data is null) return ApiResult<int>.Fail(credentials.Code, credentials.Message);
        if (!credentials.Data.UseForDns) return ApiResult<int>.Fail("DNS_DISABLED", "该账号未启用 DNS 用途");
        var provider = providers.ResolveDns(credentials.Data.Provider);
        if (!provider.Success || provider.Data is null) return ApiResult<int>.Fail(provider.Code, provider.Message);
        var result = await provider.Data.ListZonesAsync(credentials.Data, ct);
        if (!result.Success || result.Data is null) return ApiResult<int>.Fail(result.Code, result.Message);
        if (beforeWrite is not null)
        {
            var allowed = await beforeWrite(ct);
            if (!allowed.Success) return ApiResult<int>.Fail(allowed.Code, allowed.Message);
        }
        // 云端完整分页成功后才更新快照，失败时保留上次可信结果。
        var existing = await db.Domains.Where(x => x.AccountId == accountId).ToListAsync(ct);
        var now = DateTime.UtcNow;
        foreach (var zone in result.Data)
        {
            var entity = existing.Find(x => x.ZoneId == zone.Id);
            if (entity is null)
            {
                entity = new ManagedDomain { Id = ids.NewId(), AccountId = accountId, ZoneId = zone.Id };
                db.Domains.Add(entity);
            }
            entity.Provider = credentials.Data.Provider;
            entity.Name = zone.Name.ToLowerInvariant().TrimEnd('.');
            entity.Status = zone.Status;
            entity.SyncedAtUtc = now;
        }
        var currentIds = result.Data.Select(x => x.Id).ToHashSet();
        foreach (var stale in existing.Where(x => !currentIds.Contains(x.ZoneId))) stale.Status = "NotPresent";
        await db.SaveChangesAsync(ct);
        return ApiResult<int>.Ok(result.Data.Count, "域名同步完成");
    }

    public async Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(string domainId, CancellationToken ct)
    {
        var context = await ResolveAsync(domainId, ct);
        if (!context.Success || context.Data is null) return ApiResult<IReadOnlyList<DnsRecord>>.Fail(context.Code, context.Message);
        return await context.Data.Provider.ListRecordsAsync(context.Data.Account, context.Data.Domain.Name, ct);
    }

    public async Task<ApiResult<DnsRecord>> SaveRecordAsync(string domainId, string? recordId, DnsRecordRequest request, CancellationToken ct)
        => await SaveRecordCoreAsync(domainId, recordId, request, null, ct);

    private async Task<ApiResult<DnsRecord>> SaveRecordCoreAsync(string domainId, string? recordId, DnsRecordRequest request,
        Func<DnsContext, DnsRecord?, CancellationToken, Task<ApiResult<bool>>>? beforeWrite, CancellationToken ct)
    {
        var validation = Validate(request);
        if (!validation.Success) return ApiResult<DnsRecord>.Fail(validation.Code, validation.Message);
        var context = await ResolveAsync(domainId, ct);
        if (!context.Success || context.Data is null) return ApiResult<DnsRecord>.Fail(context.Code, context.Message);
        DnsRecord? original = null;
        if (recordId is not null)
        {
            var records = await context.Data.Provider.ListRecordsAsync(context.Data.Account, context.Data.Domain.Name, ct);
            if (!records.Success || records.Data is null) return ApiResult<DnsRecord>.Fail(records.Code, records.Message);
            original = records.Data.SingleOrDefault(x => x.Id == recordId);
            if (original is null) return ApiResult<DnsRecord>.Fail("NOT_FOUND", "该解析记录不属于当前托管域");
        }
        if (beforeWrite is not null)
        {
            var allowed = await beforeWrite(context.Data, original, ct);
            if (!allowed.Success) return ApiResult<DnsRecord>.Fail(allowed.Code, allowed.Message);
        }
        return recordId is null
            ? await context.Data.Provider.CreateRecordAsync(context.Data.Account, context.Data.Domain.Name, request, ct)
            : await context.Data.Provider.UpdateRecordAsync(context.Data.Account, context.Data.Domain.Name, recordId, request, ct);
    }

    public async Task<ApiResult<CloudOperation>> ChangeRecordAsync(string domainId, string recordId, bool? enabled, CancellationToken ct)
        => await ChangeRecordCoreAsync(domainId, recordId, enabled, null, ct);

    private async Task<ApiResult<CloudOperation>> ChangeRecordCoreAsync(string domainId, string recordId, bool? enabled,
        Func<DnsContext, DnsRecord?, CancellationToken, Task<ApiResult<bool>>>? beforeWrite, CancellationToken ct)
    {
        var context = await ResolveAsync(domainId, ct);
        if (!context.Success || context.Data is null) return ApiResult<CloudOperation>.Fail(context.Code, context.Message);
        var records = await context.Data.Provider.ListRecordsAsync(context.Data.Account, context.Data.Domain.Name, ct);
        if (!records.Success || records.Data is null) return ApiResult<CloudOperation>.Fail(records.Code, records.Message);
        var original = records.Data.SingleOrDefault(x => x.Id == recordId);
        if (original is null) return ApiResult<CloudOperation>.Fail("NOT_FOUND", "该解析记录不属于当前托管域");
        if (beforeWrite is not null)
        {
            var allowed = await beforeWrite(context.Data, original, ct);
            if (!allowed.Success) return ApiResult<CloudOperation>.Fail(allowed.Code, allowed.Message);
        }
        return enabled.HasValue
            ? await context.Data.Provider.SetRecordStatusAsync(context.Data.Account, context.Data.Domain.Name, recordId, enabled.Value, ct)
            : await context.Data.Provider.DeleteRecordAsync(context.Data.Account, context.Data.Domain.Name, recordId, ct);
    }

    public async Task<ApiResult<DnsContext>> ResolveAsync(string domainId, CancellationToken ct)
    {
        var domain = await db.Domains.FindAsync([domainId], ct);
        if (domain is null || domain.Status == "NotPresent") return ApiResult<DnsContext>.Fail("NOT_FOUND", "DNS 托管域不存在，请重新同步");
        var account = await accounts.GetCredentialsAsync(domain.AccountId, ct);
        if (!account.Success || account.Data is null) return ApiResult<DnsContext>.Fail(account.Code, account.Message);
        if (!account.Data.UseForDns) return ApiResult<DnsContext>.Fail("DNS_DISABLED", "该账号未启用 DNS 用途");
        var provider = providers.ResolveDns(account.Data.Provider);
        return provider.Success && provider.Data is not null
            ? ApiResult<DnsContext>.Ok(new(domain, account.Data, provider.Data))
            : ApiResult<DnsContext>.Fail(provider.Code, provider.Message);
    }

    private static async Task<ApiResult<bool>> CheckRecordAsync(DnsContext context, string recordId, CancellationToken ct)
    {
        var records = await context.Provider.ListRecordsAsync(context.Account, context.Domain.Name, ct);
        if (!records.Success || records.Data is null) return ApiResult<bool>.Fail(records.Code, records.Message);
        return records.Data.Any(x => x.Id == recordId) ? ApiResult<bool>.Ok(true)
            : ApiResult<bool>.Fail("NOT_FOUND", "该解析记录不属于当前托管域");
    }

    public static ApiResult<bool> Validate(DnsRecordRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Name) || string.IsNullOrWhiteSpace(request.Value))
            return ApiResult<bool>.Fail("INVALID_RECORD", "主机记录和记录值不能为空");
        if (!new[] { "A", "AAAA", "CNAME", "TXT", "MX", "NS", "CAA", "SRV" }.Contains(request.Type))
            return ApiResult<bool>.Fail("INVALID_RECORD_TYPE", "不支持的解析记录类型");
        if (request.Ttl < 60 || request.Ttl > 604800) return ApiResult<bool>.Fail("INVALID_TTL", "TTL 必须在 60 到 604800 秒之间");
        if (request.Type is "A" or "AAAA")
        {
            if (!System.Net.IPAddress.TryParse(request.Value, out var address) ||
                (request.Type == "A" && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) ||
                (request.Type == "AAAA" && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6))
                return ApiResult<bool>.Fail("INVALID_IP", "记录值不是对应类型的 IP 地址");
        }
        return ApiResult<bool>.Ok(true);
    }

    public sealed record DnsContext(ManagedDomain Domain, CloudAccountCredentials Account, IDnsProvider Provider);
}
