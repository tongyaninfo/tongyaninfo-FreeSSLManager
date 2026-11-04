using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service;

/// <summary>仅迁移配置；所有网络操作、后台任务和原环境密钥均不属于导入范围。</summary>
public interface IConfigurationTransferService
{
    Task<ApiResult<ConfigurationPackage>> ExportAsync(CancellationToken ct);
    Task<ApiResult<ConfigurationImportPreview>> PreviewAsync(ConfigurationImportRequest request, string userId, CancellationToken ct);
    Task<ApiResult<ConfigurationImportResult>> ImportAsync(ConfigurationImportRequest request, string userId, CancellationToken ct);
}
