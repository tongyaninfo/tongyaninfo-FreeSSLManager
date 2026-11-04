using SslManager.Api.Common;

namespace SslManager.Api.Service;

public interface ICloudProviderResolver
{
    ApiResult<ICloudCertificateService> ResolveCertificate(string provider);
    ApiResult<IDnsProvider> ResolveDns(string provider);
}
