using SslManager.Api.Common;
using SslManager.Api.Models;
namespace SslManager.Api.Service;
/// <summary>统一证书材料读取和校验，材料仅在内存或加密快照中存在。</summary>
public interface ICertificateMaterialService
{
    Task<ApiResult<CertificateMaterial>> GetAsync(string certificateId, CancellationToken ct);

    /// <summary>按源格式读取真实证书包，并核对它属于本次固定的证书材料。</summary>
    Task<ApiResult<CertificateSourcePackage>> GetSourceAsync(string certificateId, string format,
        CertificateMaterialMetadata expected, CancellationToken ct) =>
        Task.FromResult(ApiResult<CertificateSourcePackage>.Fail("SOURCE_FORMAT_UNSUPPORTED", "当前材料服务不支持源格式包。"));
}
