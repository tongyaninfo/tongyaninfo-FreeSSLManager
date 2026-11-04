using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service;

public interface ICloudAccountStore
{
    Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, CancellationToken ct);
    Task<ApiResult<CloudAccountPage>> ListAsync(int page, int pageSize, string? search, string? provider, bool? enabled, CancellationToken ct);
    Task<ApiResult<IReadOnlyList<CloudAccountOption>>> ListOptionsAsync(CancellationToken ct);
    Task<ApiResult<CloudAccountSummary>> CreateAsync(CloudAccountInput input, CancellationToken ct);
    Task<ApiResult<CloudAccountSummary>> UpdateAsync(string id, CloudAccountInput input, CancellationToken ct);
    /// <summary>仅供管理员主动查看配置使用；调用方负责审计和禁止响应缓存。</summary>
    Task<ApiResult<CloudAccountSecrets>> RevealSecretsAsync(string accountId, CancellationToken ct);
    /// <summary>解密结果只能在服务端内部使用；已禁用账号返回业务失败。</summary>
    Task<ApiResult<CloudAccountCredentials>> GetCredentialsAsync(string accountId, CancellationToken ct);
    /// <summary>联系人同步允许读取已保存密钥，即使配置暂时停用；仅供管理员主动触发的只读查询。</summary>
    Task<ApiResult<CloudAccountCredentials>> GetCredentialsForContactSyncAsync(string accountId, CancellationToken ct)
        => GetCredentialsAsync(accountId, ct);
    Task<ApiResult<bool>> RecordTestAsync(string accountId, bool success, string code, string message, CancellationToken ct);
}
