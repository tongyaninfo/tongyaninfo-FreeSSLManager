using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Deployment;
namespace SslManager.Api.Controllers;

[ApiController, Authorize(Roles = "admin"), Route("api/deployment-targets")]
public sealed class DeploymentTargetsController(IDeploymentTargetService targets, IDeploymentExecutorResolver executors,
    RemoteDirectoryBrowserService browser) : BusinessController
{
    [HttpGet("/api/deployment-executors")]
    public IActionResult Executors() => Ok(ApiResult<IReadOnlyList<DeploymentExecutorDescriptor>>.Ok(executors.List()));
    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, [FromQuery] string? search = null, CancellationToken ct = default)
        => Reply(await targets.ListAsync(page, pageSize, search, ct));
    [HttpGet("{id}")]
    public async Task<IActionResult> Get(string id, CancellationToken ct) => Reply(await targets.GetAsync(id, ct));
    [HttpPost]
    public async Task<IActionResult> Create(DeploymentTargetInput input, CancellationToken ct) => Reply(await targets.SaveAsync(null, input, ct));
    [HttpPut("{id}")]
    public async Task<IActionResult> Update(string id, DeploymentTargetInput input, CancellationToken ct) => Reply(await targets.SaveAsync(id, input, ct));
    [HttpPost("{id}/status")]
    public async Task<IActionResult> Status(string id, DeploymentStatusRequest input, CancellationToken ct) => Reply(await targets.SetStatusAsync(id, input.Enabled, ct));
    [HttpPost("{id}/test")]
    public async Task<IActionResult> Test(string id, CancellationToken ct) => Reply(await targets.TestAsync(id, ct));
    [HttpPost("{id}/discover")]
    public async Task<IActionResult> Discover(string id, CancellationToken ct) => Reply(await targets.DiscoverAsync(id, ct));
    [HttpPost("browse")]
    public async Task<IActionResult> Browse(RemoteBrowseRequest input, CancellationToken ct)
    {
        var context = await targets.GetBrowseContextAsync(input, ct);
        if (!context.Success || context.Data is null)
            return Reply(ApiResult<RemoteDirectoryListing>.Fail(context.Code, context.Message));
        return Reply(await browser.BrowseAsync(context.Data, input.Path, ct));
    }
}
