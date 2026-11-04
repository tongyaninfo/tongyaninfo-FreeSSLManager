using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service;

namespace SslManager.Api.Controllers;

[ApiController, Authorize(Roles = "admin"), Route("api/cloud-accounts")]
public sealed class CloudTestsController(ICloudAccountStore accounts, ICloudProviderResolver providers) : BusinessController
{
    [HttpPost("{id}/test")]
    public async Task<IActionResult> Test(string id, CancellationToken ct)
    {
        var account = await accounts.GetCredentialsAsync(id, ct);
        if (!account.Success || account.Data is null)
        {
            await accounts.RecordTestAsync(id, false, account.Code, account.Message, ct);
            return Reply(account);
        }
        ApiResult<CloudConnectionTest>? sslResult = null, dnsResult = null;
        if (account.Data.UseForCertificates)
        {
            var provider = providers.ResolveCertificate(account.Data.Provider);
            sslResult = provider.Success && provider.Data is not null ? await provider.Data.TestAsync(account.Data, ct)
                : ApiResult<CloudConnectionTest>.Fail(provider.Code, provider.Message);
        }
        if (account.Data.UseForDns)
        {
            var provider = providers.ResolveDns(account.Data.Provider);
            dnsResult = provider.Success && provider.Data is not null ? await provider.Data.TestDnsAsync(account.Data, ct)
                : ApiResult<CloudConnectionTest>.Fail(provider.Code, provider.Message);
        }
        var failed = new[] { sslResult, dnsResult }.FirstOrDefault(x => x is { Success: false });
        await accounts.RecordTestAsync(id, failed is null, failed?.Code ?? "OK", failed?.Message ?? "读取权限验证通过；写入权限未执行验证。", ct);
        return Ok(ApiResult<object>.Ok(new { ssl = sslResult, dns = dnsResult, writePermissions = "Unknown", message = "仅验证读取能力，写入权限未执行验证" }));
    }
}
