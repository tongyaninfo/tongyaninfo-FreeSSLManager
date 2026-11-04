using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SslManager.Api.Common;
using SslManager.Api.Service;
using SslManager.Api.Models;

namespace SslManager.Api.Controllers;

[ApiController, Authorize(Roles = "admin"), Route("api/users")]
public sealed class UsersController(IIdentityService identity) : BusinessController
{
    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20,
        [FromQuery] string? search = null, [FromQuery] string? role = null, [FromQuery] bool? enabled = null,
        CancellationToken ct = default)
    {
        if (page < 1 || pageSize is < 1 or > 100 || (!string.IsNullOrWhiteSpace(role) && role is not ("admin" or "viewer")))
            return BadRequest(ApiResult<PageResult<ManagedUser>>.Fail("VALIDATION", "分页或角色筛选条件无效。"));
        var response = await identity.ListUsersAsync(ct);
        if (!response.Success || response.Data is null) return Reply(response);
        IEnumerable<ManagedUser> query = response.Data;
        if (!string.IsNullOrWhiteSpace(search))
        {
            var keyword = search.Trim();
            query = query.Where(x => x.Username.Contains(keyword, StringComparison.OrdinalIgnoreCase) ||
                x.DisplayName.Contains(keyword, StringComparison.OrdinalIgnoreCase));
        }
        if (!string.IsNullOrWhiteSpace(role)) query = query.Where(x => x.Role == role);
        if (enabled.HasValue) query = query.Where(x => x.Enabled == enabled.Value);
        var filtered = query.ToList();
        var offset = (long)(page - 1) * pageSize;
        IReadOnlyList<ManagedUser> items = offset >= filtered.Count ? [] : filtered.Skip((int)offset).Take(pageSize).ToArray();
        return Ok(ApiResult<PageResult<ManagedUser>>.Ok(new(items, filtered.Count, page, pageSize)));
    }

    [HttpPost]
    public async Task<IActionResult> Create(UserInput input, CancellationToken ct) => Reply(await identity.CreateUserAsync(input, ct));

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(string id, UserInput input, CancellationToken ct) => Reply(await identity.UpdateUserAsync(id, input, ct));
}
