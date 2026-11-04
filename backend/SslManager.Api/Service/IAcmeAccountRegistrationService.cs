using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service;

/// <summary>与证书申请分离的显式自动注册入口；默认 Existing 模式不能调用。</summary>
public interface IAcmeAccountRegistrationService
{
    Task<ApiResult<AcmeAccountRegistrationView>> RegisterAsync(string accountId, bool agreeTerms, CancellationToken ct = default);
}
