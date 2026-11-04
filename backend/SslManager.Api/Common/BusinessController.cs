using Microsoft.AspNetCore.Mvc;

namespace SslManager.Api.Common;

public abstract class BusinessController : ControllerBase
{
    /// <summary>HTTP 状态与统一业务结果同时保留，预期错误不抛异常。</summary>
    protected IActionResult Reply<T>(ApiResult<T> result)
    {
        if (result.Success) return Ok(result);
        var status = result.Code switch
        {
            "NOT_FOUND" or "ACCOUNT_NOT_FOUND" or "CERTIFICATE_NOT_FOUND" => 404,
            "UNAUTHORIZED" => 401,
            "FORBIDDEN" => 403,
            "CONFLICT" or "APPLICATION_IN_PROGRESS" => 409,
            _ => 400
        };
        return StatusCode(status, result);
    }
}
