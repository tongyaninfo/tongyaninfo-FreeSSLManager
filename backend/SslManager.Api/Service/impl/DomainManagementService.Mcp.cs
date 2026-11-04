using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

public sealed partial class DomainManagementService
{
    internal Task<ApiResult<int>> SyncForMcpAsync(string accountId, Func<CancellationToken, Task<ApiResult<bool>>> beforeWrite, CancellationToken ct)
        => SyncCoreAsync(accountId, beforeWrite, ct);
    /// <summary>复用原验证和账号解析，在最后一次读取精确记录后、真正写云端前复核审批快照和原调用授权。</summary>
    internal Task<ApiResult<DnsRecord>> SaveRecordForMcpAsync(string domainId, string? recordId, DnsRecordRequest request,
        Func<DnsContext, DnsRecord?, CancellationToken, Task<ApiResult<bool>>> beforeWrite, CancellationToken ct)
        => SaveRecordCoreAsync(domainId, recordId, request, beforeWrite, ct);

    internal Task<ApiResult<CloudOperation>> ChangeRecordForMcpAsync(string domainId, string recordId, bool? enabled,
        Func<DnsContext, DnsRecord?, CancellationToken, Task<ApiResult<bool>>> beforeWrite, CancellationToken ct)
        => ChangeRecordCoreAsync(domainId, recordId, enabled, beforeWrite, ct);
}
