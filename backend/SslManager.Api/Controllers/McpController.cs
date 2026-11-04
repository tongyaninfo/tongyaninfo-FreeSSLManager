using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service;

namespace SslManager.Api.Controllers;

/// <summary>仅管理员管理 MCP；机器调用不能通过 Bearer 进入管理接口，浏览器写入沿用 CSRF。</summary>
[ApiController, Authorize(AuthenticationSchemes = "Cookies", Roles = "admin"), Route("api/mcp")]
public sealed class McpController(IMcpConfigurationService settings, IMcpClientService clients,
    IMcpInvocationLogService logs, IMcpOperationService operations, IMcpApiKeyService apiKeys) : BusinessController
{
    [HttpGet("settings")] public async Task<IActionResult> Settings(CancellationToken ct) => Reply(await settings.GetAsync(ct));
    [HttpPut("settings")] public async Task<IActionResult> Save(McpSettingsInput input, CancellationToken ct) => Reply(await settings.SaveAsync(input, ct));
    [HttpGet("status")] public async Task<IActionResult> Status(CancellationToken ct) => Reply(await settings.StatusAsync(ct));
    [HttpGet("tools")] public IActionResult Tools() => Reply(ApiResult<IReadOnlyList<McpToolDescriptor>>.Ok(McpToolCatalog.All));
    [HttpGet("clients")] public async Task<IActionResult> Clients(int page = 1, int pageSize = 20, string? search = null, CancellationToken ct = default) => Reply(await clients.ListAsync(page, pageSize, ct, search));
    [HttpPost("clients")] public async Task<IActionResult> Create(McpClientInput input, CancellationToken ct)
    { Response.Headers.CacheControl = "no-store"; return Reply(await clients.CreateAsync(input, ct)); }
    [HttpPut("clients/{id}")] public async Task<IActionResult> Update(string id, McpClientInput input, CancellationToken ct) => Reply(await clients.UpdateAsync(id, input, ct));
    [HttpPost("clients/{id}/status")] public async Task<IActionResult> ClientStatus(string id, McpStatusInput input, CancellationToken ct) => Reply(await clients.SetStatusAsync(id, input, ct));
    [HttpPost("clients/{id}/rotate-secret")] public async Task<IActionResult> Rotate(string id, CancellationToken ct)
    { Response.Headers.CacheControl = "no-store"; return Reply(await clients.RotateSecretAsync(id, ct)); }
    [HttpPost("clients/{id}/revoke")] public async Task<IActionResult> Revoke(string id, CancellationToken ct) => Reply(await clients.RevokeAsync(id, ct));
    [HttpGet("clients/{id}/allow-rules")] public async Task<IActionResult> Rules(string id, CancellationToken ct) => Reply(await clients.GetRulesAsync(id, ct));
    [HttpPut("clients/{id}/allow-rules")] public async Task<IActionResult> SaveRules(string id, McpAllowRulesInput input, CancellationToken ct) => Reply(await clients.SaveRulesAsync(id, input, ct));
    [HttpGet("clients/{id}/connection-profile")] public async Task<IActionResult> Profile(string id, CancellationToken ct) => Reply(await clients.ProfileAsync(id, ct));
    [HttpGet("clients/{id}/api-keys")] public async Task<IActionResult> ApiKeys(string id, CancellationToken ct) => Reply(await apiKeys.ListAsync(id, ct));
    [HttpPost("clients/{id}/api-keys")] public async Task<IActionResult> CreateApiKey(string id, McpApiKeyInput input, CancellationToken ct)
    { Response.Headers.CacheControl = "no-store"; return Reply(await apiKeys.CreateAsync(id, input, ct)); }
    [HttpPost("api-keys/{id}/status")] public async Task<IActionResult> ApiKeyStatus(string id, McpStatusInput input, CancellationToken ct) => Reply(await apiKeys.SetStatusAsync(id, input, ct));
    [HttpPost("api-keys/{id}/rotate")] public async Task<IActionResult> RotateApiKey(string id, McpApiKeyRevisionInput input, CancellationToken ct)
    { Response.Headers.CacheControl = "no-store"; return Reply(await apiKeys.RotateAsync(id, ct, input.ConfigRevision)); }
    [HttpPost("api-keys/{id}/revoke")] public async Task<IActionResult> RevokeApiKey(string id, McpApiKeyRevisionInput input, CancellationToken ct) => Reply(await apiKeys.RevokeAsync(id, ct, input.ConfigRevision));
    [HttpGet("call-logs")] public async Task<IActionResult> Logs([FromQuery] McpInvocationQuery input, CancellationToken ct) => Reply(await logs.ListAsync(input, ct));
    [HttpGet("call-logs/{id}")] public async Task<IActionResult> Log(string id, CancellationToken ct) => Reply(await logs.GetAsync(id, ct));
    [HttpGet("operations")] public async Task<IActionResult> Operations(int page = 1, int pageSize = 20, string? status = null, CancellationToken ct = default) => Reply(await operations.ListForAdminAsync(page, pageSize, status, ct));
    [HttpGet("operations/{id}")] public async Task<IActionResult> Operation(string id, CancellationToken ct) => Reply(await operations.GetForAdminAsync(id, ct));
    [HttpPost("operations/{id}/approve")] public async Task<IActionResult> Approve(string id, McpApprovalInput input, CancellationToken ct) =>
        Reply(await operations.ApproveAsync(id, User.FindFirstValue(ClaimTypes.NameIdentifier)!, true, input.Version, ct));
    [HttpPost("operations/{id}/reject")] public async Task<IActionResult> Reject(string id, McpApprovalInput input, CancellationToken ct) =>
        Reply(await operations.ApproveAsync(id, User.FindFirstValue(ClaimTypes.NameIdentifier)!, false, input.Version, ct));
}
