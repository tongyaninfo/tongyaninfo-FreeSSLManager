using SslManager.Api.Common;

namespace SslManager.Api.Service.impl;

/// <summary>云适配器复用同一实例，未知厂商返回业务结果。</summary>
public sealed class CloudProviderResolver(TencentCloudService tencent, AliyunCloudService aliyun,
    CloudflareCloudService? cloudflare = null, AcmeCloudService? acme = null) : ICloudProviderResolver
{
    public ApiResult<ICloudCertificateService> ResolveCertificate(string provider) => provider switch
    {
        "TencentCloud" => ApiResult<ICloudCertificateService>.Ok(tencent),
        "Aliyun" => ApiResult<ICloudCertificateService>.Ok(aliyun),
        "Acme" when acme is not null => ApiResult<ICloudCertificateService>.Ok(acme),
        _ => ApiResult<ICloudCertificateService>.Fail("UnsupportedProvider", "不支持的云平台。")
    };
    public ApiResult<IDnsProvider> ResolveDns(string provider) => provider switch
    {
        "TencentCloud" => ApiResult<IDnsProvider>.Ok(tencent),
        "Aliyun" => ApiResult<IDnsProvider>.Ok(aliyun),
        "Cloudflare" when cloudflare is not null => ApiResult<IDnsProvider>.Ok(cloudflare),
        _ => ApiResult<IDnsProvider>.Fail("UnsupportedProvider", "不支持的 DNS 平台。")
    };
}
