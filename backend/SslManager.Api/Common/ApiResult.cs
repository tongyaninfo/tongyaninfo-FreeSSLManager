namespace SslManager.Api.Common;

/// <summary>预期业务错误通过结果返回，异常只用于系统故障。</summary>
public sealed record ApiResult<T>(bool Success, string Code, string Message, T? Data = default)
{
    public static ApiResult<T> Ok(T data, string message = "操作成功") => new(true, "OK", message, data);
    public static ApiResult<T> Fail(string code, string message) => new(false, code, message);
}

public sealed record PageResult<T>(IReadOnlyList<T> Items, int Total, int Page, int PageSize);

/// <summary>统一业务 ID 入口，云端资源 ID 原样另存。</summary>
public interface IIdGenerator { string NewId(); }
public sealed class GuidIdGenerator : IIdGenerator
{
    public string NewId() => Guid.CreateVersion7().ToString("N");
}
