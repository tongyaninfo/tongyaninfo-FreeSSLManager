using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service;

public interface IIdentityService
{
    Task<bool> IsSetupRequiredAsync(CancellationToken ct);
    Task<ApiResult<CurrentUser>> SetupAsync(SetupInput input, CancellationToken ct);
    Task<ApiResult<CurrentUser>> LoginAsync(LoginInput input, CancellationToken ct);
    Task<ApiResult<CurrentUser>> ChangePasswordAsync(string userId, ChangePasswordInput input, CancellationToken ct);
    Task<ApiResult<CurrentUser>> GetCurrentUserAsync(string userId, CancellationToken ct);
    Task<ApiResult<IReadOnlyList<ManagedUser>>> ListUsersAsync(CancellationToken ct);
    Task<ApiResult<ManagedUser>> CreateUserAsync(UserInput input, CancellationToken ct);
    Task<ApiResult<ManagedUser>> UpdateUserAsync(string id, UserInput input, CancellationToken ct);
}
