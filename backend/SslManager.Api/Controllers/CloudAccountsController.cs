using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;

namespace SslManager.Api.Controllers;

[ApiController, Authorize, Route("api/cloud-accounts")]
public sealed class CloudAccountsController(ICloudAccountStore accounts, AppDbContext db, IIdGenerator ids,
    ICloudProviderResolver? providers = null, IAcmeAccountRegistrationService? acmeRegistration = null) : BusinessController
{
    [Authorize(Roles = "admin"), HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 20,
        [FromQuery] string? search = null, [FromQuery] string? provider = null, [FromQuery] bool? enabled = null,
        CancellationToken ct = default) => Reply(await accounts.ListAsync(page, pageSize, search, provider, enabled, ct));

    [HttpGet("options")]
    public async Task<IActionResult> Options(CancellationToken ct) => Reply(await accounts.ListOptionsAsync(ct));

    [Authorize(Roles = "admin"), HttpGet("{id}/secrets")]
    public async Task<IActionResult> RevealSecrets(string id, CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store";
        Response.Headers.Pragma = "no-cache";
        var result = await accounts.RevealSecretsAsync(id, ct);
        if (!result.Success) return Reply(result);
        // 查看成功必须先完成审计；审计记录只包含资源和操作者，不包含任何密钥。
        db.AuditLogs.Add(new AuditLog { Id = ids.NewId(), UserId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "",
            Username = User.FindFirstValue(ClaimTypes.Name) ?? "", Action = "RevealCloudSecrets", ResourceId = id,
            Success = true, Code = "OK", Message = "管理员主动查看云账号密钥。", CreatedAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync(ct);
        return Ok(result);
    }

    [Authorize(Roles = "admin"), HttpPost]
    public async Task<IActionResult> Create(CloudAccountInput input, CancellationToken ct) => Reply(await accounts.CreateAsync(input, ct));

    [Authorize(Roles = "admin"), HttpPut("{id}")]
    public async Task<IActionResult> Update(string id, CloudAccountInput input, CancellationToken ct) => Reply(await accounts.UpdateAsync(id, input, ct));

    [Authorize(Roles = "admin"), HttpPost("{id}/acme-registration")]
    public async Task<IActionResult> RegisterAcmeAccount(string id, AcmeAccountRegistrationRequest input, CancellationToken ct)
    {
        Response.Headers.CacheControl = "no-store";
        if (acmeRegistration is null) return Reply(ApiResult<bool>.Fail("SERVICE_UNAVAILABLE", "ACME 注册服务不可用。"));
        var result = await acmeRegistration.RegisterAsync(id, input.AgreeTerms, ct);
        // 不记录账号私钥、请求体或原始 CA 响应；账号 URL 通过脱敏元数据视图单独提供。
        db.AuditLogs.Add(new() { Id = ids.NewId(), UserId = User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "",
            Username = User.FindFirstValue(ClaimTypes.Name) ?? "", Action = "RegisterAcmeAccount", ResourceId = id,
            Success = result.Success, Code = result.Code, Message = "管理员显式提交 ACME 账号注册或恢复核对。", CreatedAtUtc = DateTime.UtcNow });
        await db.SaveChangesAsync(ct);
        return Reply(result);
    }

    /// <summary>使用编辑表单中的临时密钥读取阿里云联系人，不保存或返回密钥。</summary>
    [Authorize(Roles = "admin"), HttpPost("aliyun-contacts")]
    public async Task<IActionResult> AliyunContacts(CloudContactSyncInput input, CancellationToken ct)
    {
        if (!string.Equals(input.Provider, "Aliyun", StringComparison.OrdinalIgnoreCase))
            return Reply(ApiResult<IReadOnlyList<AliyunContact>>.Fail("VALIDATION", "联系人同步仅支持阿里云。"));
        var accessKeyId = input.AccessKeyId?.Trim() ?? "";
        var accessKeySecret = input.AccessKeySecret?.Trim() ?? "";
        if (input.AccountId is { Length: > 0 })
        {
            var saved = await accounts.GetCredentialsForContactSyncAsync(input.AccountId, ct);
            if (!saved.Success || saved.Data is null) return Reply(saved);
            if (!string.Equals(saved.Data.Provider, "Aliyun", StringComparison.OrdinalIgnoreCase))
                return Reply(ApiResult<IReadOnlyList<AliyunContact>>.Fail("VALIDATION", "指定云账号不是阿里云配置。"));
            // 编辑时两项都留空才复用已保存密钥；只要表单填写了密钥，就以本次输入为准。
            if (accessKeyId.Length == 0 && accessKeySecret.Length == 0)
            {
                accessKeyId = saved.Data.AccessKeyId;
                accessKeySecret = saved.Data.AccessKeySecret;
            }
        }
        if (accessKeyId.Length == 0 || accessKeySecret.Length == 0)
            return Reply(ApiResult<IReadOnlyList<AliyunContact>>.Fail("CONFIGURATION_MISSING", "请先填写完整的阿里云 AccessKey ID 和 AccessKey Secret。"));
        var account = new CloudAccountCredentials(input.AccountId ?? "temporary", "临时配置", "Aliyun", accessKeyId, accessKeySecret,
            true, true, true, "", "", "");
        if (providers is null) return Reply(ApiResult<IReadOnlyList<AliyunContact>>.Fail("SYSTEM_ERROR", "云平台服务未初始化。"));
        var provider = providers.ResolveCertificate("Aliyun");
        if (!provider.Success || provider.Data is null) return Reply(ApiResult<IReadOnlyList<AliyunContact>>.Fail(provider.Code, provider.Message));
        return Reply(await provider.Data.ListContactsAsync(account, ct));
    }

    /// <summary>读取当前阿里云配置下尚未使用的基础免费 V2 测试实例，供证书申请下拉选择。</summary>
    [Authorize(Roles = "admin"), HttpGet("{id}/aliyun-instances")]
    public async Task<IActionResult> AliyunInstances(string id, CancellationToken ct)
    {
        var credentials = await accounts.GetCredentialsAsync(id, ct);
        if (!credentials.Success || credentials.Data is null) return Reply(credentials);
        if (!string.Equals(credentials.Data.Provider, "Aliyun", StringComparison.OrdinalIgnoreCase))
            return Reply(ApiResult<IReadOnlyList<AliyunCertificateInstanceOption>>.Fail("VALIDATION", "指定云账号不是阿里云配置。"));
        if (providers is null) return Reply(ApiResult<IReadOnlyList<AliyunCertificateInstanceOption>>.Fail("SYSTEM_ERROR", "云平台服务未初始化。"));
        var provider = providers.ResolveCertificate("Aliyun");
        if (!provider.Success || provider.Data is null)
            return Reply(ApiResult<IReadOnlyList<AliyunCertificateInstanceOption>>.Fail(provider.Code, provider.Message));
        return Reply(await provider.Data.ListAliyunInstancesAsync(credentials.Data, ct));
    }
}
