using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service;

namespace SslManager.Api.Controllers;

/// <summary>计划操作复用管理员权限、统一业务结果、CSRF 和操作审计。</summary>
[ApiController, Authorize(Roles = "admin"), Route("api/certificate-schedules")]
public sealed class CertificateSchedulesController(ICertificateScheduleService schedules) : BusinessController
{
    private string UserId => User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "";

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20,
        [FromQuery] string? search = null, CancellationToken ct = default)
        => Reply(await schedules.ListAsync(page, pageSize, search, ct));

    [HttpGet("{id}")]
    public async Task<IActionResult> Get(string id, CancellationToken ct)
        => Reply(await schedules.GetAsync(id, ct));

    [HttpPost]
    public async Task<IActionResult> Create(CertificateScheduleInput request, CancellationToken ct)
        => Reply(await schedules.SaveAsync(null, request, UserId, ct));

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(string id, CertificateScheduleInput request, CancellationToken ct)
        => Reply(await schedules.SaveAsync(id, request, UserId, ct));

    [HttpPost("{id}/status")]
    public async Task<IActionResult> Status(string id, DeploymentStatusRequest request, CancellationToken ct)
        => Reply(await schedules.SetEnabledAsync(id, request.Enabled, ct));

    [HttpPost("{id}/run")]
    public async Task<IActionResult> Run(string id, CancellationToken ct)
        => Reply(await schedules.RunNowAsync(id, ct));

    [HttpGet("{id}/runs")]
    public async Task<IActionResult> Runs(string id, [FromQuery] int page = 1,
        [FromQuery] int pageSize = 20, CancellationToken ct = default)
        => Reply(await schedules.ListRunsAsync(id, page, pageSize, ct));

    [HttpPost("runs/{runId}/resume")]
    public async Task<IActionResult> Resume(string runId, CancellationToken ct)
        => Reply(await schedules.ResumeRunAsync(runId, ct));

    [HttpPost("runs/{runId}/resolve")]
    public async Task<IActionResult> Resolve(string runId, DeploymentResolveRequest request, CancellationToken ct)
        => Reply(await schedules.ResolveRunAsync(runId, request.Note, ct));
}
