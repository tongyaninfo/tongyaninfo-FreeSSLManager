using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service;

/// <summary>本地生成证书的长期加密材料仓库；解密失败不能用替代私钥继续。</summary>
public interface ICertificateIssuanceStore
{
    Task<ApiResult<CertificateIssuancePayload>> GetOrCreateAsync(string localId, string provider, string domain, string accountId, CancellationToken ct = default);
    Task<ApiResult<CertificateIssuancePayload>> GetAsync(string localId, CancellationToken ct = default);
    Task<ApiResult<bool>> SetStageAsync(string localId, string stage, CancellationToken ct = default);
    Task<ApiResult<bool>> StoreIssuedAsync(string localId, string certificatePem, string chainPem, string remoteCertificateId, CancellationToken ct = default);
}
