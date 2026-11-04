using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service;

/// <summary>免费证书云适配接口；所有预期业务错误通过统一结果返回。</summary>
public interface ICloudCertificateService
{
    string Provider { get; }
    Task<ApiResult<CloudConnectionTest>> TestAsync(CloudAccountCredentials account, CancellationToken ct = default);
    /// <summary>读取云平台证书申请联系人；不支持的平台返回业务失败。</summary>
    Task<ApiResult<IReadOnlyList<AliyunContact>>> ListContactsAsync(CloudAccountCredentials account, CancellationToken ct = default)
        => Task.FromResult(ApiResult<IReadOnlyList<AliyunContact>>.Fail("CONTACTS_UNSUPPORTED", "当前云平台不支持证书联系人同步。"));
    /// <summary>读取可用于阿里云 V2 申请的免费测试实例；不支持的平台返回业务失败。</summary>
    Task<ApiResult<IReadOnlyList<AliyunCertificateInstanceOption>>> ListAliyunInstancesAsync(CloudAccountCredentials account, CancellationToken ct = default)
        => Task.FromResult(ApiResult<IReadOnlyList<AliyunCertificateInstanceOption>>.Fail("INSTANCES_UNSUPPORTED", "当前云平台不支持测试证书实例选择。"));
    Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListAsync(CloudAccountCredentials account, CancellationToken ct = default);
    Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default);
    Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default);
    /// <summary>仅由申请任务在写入验证记录后推进；查询接口不能隐式接受 ACME 挑战或提交 CSR。</summary>
    Task<ApiResult<CloudCertificateDetail>> ContinueApplicationAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
        => GetAsync(account, reference, ct);
    Task<ApiResult<CloudOperation>> RevokeAsync(CloudAccountCredentials account, CloudCertificateReference reference, string reason, CancellationToken ct = default);
    /// <summary>取消待验证或审核中的证书申请，不等同于已签发证书吊销。</summary>
    Task<ApiResult<CloudOperation>> CancelAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
        => Task.FromResult(ApiResult<CloudOperation>.Fail("CANCEL_UNSUPPORTED", "当前云平台不支持取消审核中的证书申请。"));
    /// <summary>删除云端证书。编排层必须先核验本地状态，仅允许已过期、已吊销或已取消证书调用。</summary>
    Task<ApiResult<CloudOperation>> DeleteAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
        => Task.FromResult(ApiResult<CloudOperation>.Fail("DELETE_UNSUPPORTED", "当前云平台不支持通过接口删除证书。"));
    Task<ApiResult<CertificateDownload>> DownloadAsync(CloudAccountCredentials account, CloudCertificateReference reference, string format, CancellationToken ct = default);
}
