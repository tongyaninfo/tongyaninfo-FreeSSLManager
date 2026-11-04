using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
namespace SslManager.Api.Controllers;

[ApiController, Authorize(Roles = "admin"), Route("api/deployments")]
public sealed class DeploymentsController(IDeploymentService deployments, AppDbContext db) : BusinessController
{
    private string UserId => User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "";
    [HttpPost("/api/certificates/{id}/deployments/plan")]
    public async Task<IActionResult> Plan(string id, DeploymentPlanRequest request, CancellationToken ct)
        => Reply(await deployments.PlanAsync(id, request, UserId, ct));
    [HttpPost("{batchId}/submit")]
    public async Task<IActionResult> Submit(string batchId, DeploymentSubmitRequest request, CancellationToken ct)
        => Reply(await deployments.SubmitAsync(batchId, request, UserId, ct));
    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20, [FromQuery] string? search = null, CancellationToken ct = default)
        => Reply(await deployments.ListAsync(page, pageSize, search, ct));
    [HttpGet("{batchId}")]
    public async Task<IActionResult> Get(string batchId, CancellationToken ct) => Reply(await deployments.GetAsync(batchId, ct));
    [HttpGet("/api/deployment-tasks/{id}")]
    public async Task<IActionResult> Task(string id, CancellationToken ct) => Reply(await deployments.GetTaskAsync(id, ct));
    [HttpGet("/api/deployment-tasks/{id}/steps")]
    public async Task<IActionResult> Steps(string id, CancellationToken ct)
    {
        var result = await deployments.GetTaskAsync(id, ct);
        return result.Success ? Ok(ApiResult<IReadOnlyList<DeploymentStepView>>.Ok(result.Data!.Steps ?? [])) : Reply(result);
    }
    [HttpPost("/api/deployment-tasks/{id}/cancel")]
    public async Task<IActionResult> Cancel(string id, CancellationToken ct) => Reply(await deployments.CancelAsync(id, ct));
    [HttpPost("/api/deployment-tasks/{id}/inspect")]
    public async Task<IActionResult> Inspect(string id, CancellationToken ct) => Reply(await deployments.InspectAsync(id, ct));
    [HttpPost("/api/deployment-tasks/{id}/resolve")]
    public async Task<IActionResult> Resolve(string id, DeploymentResolveRequest request, CancellationToken ct)
        => Reply(await deployments.ResolveAsync(id, request.Note, UserId, User.Identity?.Name ?? "", ct));
    [HttpPost("/api/deployment-tasks/{id}/retry-plan")]
    public async Task<IActionResult> RetryPlan(string id, CancellationToken ct)
    {
        var task = await db.DeploymentTasks.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        if (task is null) return NotFound(ApiResult<object>.Fail("NOT_FOUND", "部署任务不存在。"));
        if (task.Status is "Queued" or "Running" or "Succeeded" or "Skipped") return Reply(ApiResult<object>.Fail("CONFLICT", "此任务无需重试或正在执行。"));
        var batch = await db.DeploymentBatches.AsNoTracking().SingleAsync(x => x.Id == task.BatchId, ct);
        var plan = JsonSerializer.Deserialize<DeploymentTargetPlan>(task.PlanJson, new JsonSerializerOptions(JsonSerializerDefaults.Web))!;
        return Reply(await deployments.PlanAsync(batch.CertificateId, new([new(task.TargetId, plan.RemoteResourceId, plan.SiteIds)]), UserId, ct));
    }
    [HttpPost("/api/deployment-tasks/{id}/rollback-plan")]
    public async Task<IActionResult> RollbackPlan(string id, CancellationToken ct) => Reply(await deployments.RollbackPlanAsync(id, UserId, ct));
}
