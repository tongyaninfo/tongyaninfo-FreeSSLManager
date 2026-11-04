using SslManager.Api.Common;
using SslManager.Api.Models;
namespace SslManager.Api.Service;
public interface IDeploymentTargetService
{
    Task<ApiResult<PageResult<DeploymentTargetView>>> ListAsync(int page, int pageSize, string? search, CancellationToken ct);
    Task<ApiResult<DeploymentTargetView>> GetAsync(string id, CancellationToken ct);
    Task<ApiResult<DeploymentTargetView>> SaveAsync(string? id, DeploymentTargetInput input, CancellationToken ct);
    Task<ApiResult<DeploymentTargetView>> SetStatusAsync(string id, bool enabled, CancellationToken ct);
    Task<ApiResult<DeploymentTargetContext>> GetContextAsync(string id, CancellationToken ct);
    Task<ApiResult<DeploymentTargetContext>> GetBrowseContextAsync(RemoteBrowseRequest request, CancellationToken ct);
    Task<ApiResult<DeploymentConnectionTest>> TestAsync(string id, CancellationToken ct);
    Task<ApiResult<DeploymentDiscovery>> DiscoverAsync(string id, CancellationToken ct);
}
