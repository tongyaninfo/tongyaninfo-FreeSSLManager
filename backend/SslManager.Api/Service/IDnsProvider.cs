using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service;

/// <summary>DNS 写操作以精确记录 ID 为边界；连通性测试只查询域名。</summary>
public interface IDnsProvider
{
    string Provider { get; }
    Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default);
    Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default);
    Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default);
    Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default);
    Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string recordId, DnsRecordRequest request, CancellationToken ct = default);
    Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string recordId, bool enabled, CancellationToken ct = default);
    Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string recordId, CancellationToken ct = default);
}
