using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service;

namespace SslManager.Api.Controllers;

/// <summary>管理员主动迁移配置；复用登录、CSRF、统一响应与操作审计，响应禁止缓存。</summary>
[ApiController, Authorize(Roles = "admin"), Route("api/configuration-transfer")]
public sealed class ConfigurationTransferController(IConfigurationTransferService configurations) : BusinessController
{
    // JSON 文件最多 5 MiB，为请求包装和预览凭证保留额外空间。
    private const long ImportRequestLimit = 6 * 1024 * 1024;

    [HttpPost("export")]
    public async Task<IActionResult> Export(CancellationToken ct)
    {
        DisableCaching();
        return Reply(await configurations.ExportAsync(ct));
    }

    [HttpPost("preview"), RequestSizeLimit(ImportRequestLimit)]
    public async Task<IActionResult> Preview(ConfigurationImportRequest request, CancellationToken ct)
    {
        DisableCaching();
        return Reply(await configurations.PreviewAsync(request, User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "", ct));
    }

    [HttpPost("import"), RequestSizeLimit(ImportRequestLimit)]
    public async Task<IActionResult> Import(ConfigurationImportRequest request, CancellationToken ct)
    {
        DisableCaching();
        return Reply(await configurations.ImportAsync(request, User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "", ct));
    }

    private void DisableCaching()
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
    }
}
