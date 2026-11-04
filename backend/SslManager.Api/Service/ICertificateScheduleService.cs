using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service;

/// <summary>持久化周期申请与自动部署；后台执行复用原有证书和部署队列。</summary>
public interface ICertificateScheduleService
{
    Task<ApiResult<PageResult<CertificateScheduleView>>> ListAsync(int page, int pageSize, string? search, CancellationToken ct);
    Task<ApiResult<CertificateScheduleView>> GetAsync(string id, CancellationToken ct);
    Task<ApiResult<CertificateScheduleView>> SaveAsync(string? id, CertificateScheduleInput input, string userId, CancellationToken ct);
    Task<ApiResult<CertificateScheduleView>> SetEnabledAsync(string id, bool enabled, CancellationToken ct);
    Task<ApiResult<CertificateScheduleRunView>> RunNowAsync(string id, CancellationToken ct);
    Task<ApiResult<PageResult<CertificateScheduleRunView>>> ListRunsAsync(string id, int page, int pageSize, CancellationToken ct);
    Task<ApiResult<CertificateScheduleRunView>> ResumeRunAsync(string runId, CancellationToken ct);
    Task<ApiResult<CertificateScheduleRunView>> ResolveRunAsync(string runId, string note, CancellationToken ct);
    Task<bool> ProcessNextAsync(CancellationToken ct);
}
