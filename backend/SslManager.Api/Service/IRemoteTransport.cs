using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service;

/// <summary>远程连接只消费已保存的目标快照，不访问云账号或浏览器配置。</summary>
public interface IRemoteTransport
{
    Task<ApiResult<IRemoteSession>> ConnectAsync(DeploymentTargetContext target, CancellationToken ct);

    /// <summary>浏览器需要结构化主机指纹；默认适配保持现有传输和测试实现兼容。</summary>
    async Task<ApiResult<RemoteConnectionAttempt>> ConnectWithIdentityAsync(DeploymentTargetContext target, CancellationToken ct)
    {
        var result = await ConnectAsync(target, ct);
        return result.Success && result.Data is not null
            ? ApiResult<RemoteConnectionAttempt>.Ok(new(result.Data))
            : ApiResult<RemoteConnectionAttempt>.Fail(result.Code, result.Message);
    }
}

/// <summary>仅限服务端连接过程使用；失败时只有指纹，不持有已关闭的会话。</summary>
public sealed record RemoteConnectionAttempt(IRemoteSession? Session = null, string ObservedFingerprint = "");

/// <summary>文件部署共用的可测试会话边界；移动操作不覆盖已有目标，不提供任意删除接口。</summary>
public interface IRemoteSession : IAsyncDisposable
{
    /// <summary>仅提供真实远端互斥和持久结果协议的会话声明支持；旧实现保持保守兼容。</summary>
    bool SupportsCommandRecovery => false;
    /// <summary>只读探测远端执行协议依赖；误声明支持但未实现的会话不能回退到无锁命令。</summary>
    Task<ApiResult<bool>> CheckCommandRecoverySupportAsync(bool windows, CancellationToken ct) =>
        Task.FromResult(ApiResult<bool>.Fail("COMMAND_RECOVERY_UNSUPPORTED", "此会话未实现远端命令锁和持久回执能力探测。"));
    Task<RemoteFileInfo> StatAsync(string path, CancellationToken ct);
    Task<RemoteDirectoryListing> ListDirectoryAsync(string path, int limit, CancellationToken ct) =>
        Task.FromException<RemoteDirectoryListing>(new NotSupportedException("此远程会话不支持目录浏览。"));
    Task<byte[]> ReadAsync(string path, int byteLimit, CancellationToken ct);
    Task WriteNewAsync(string path, byte[] content, short? permissions, CancellationToken ct);
    Task CreateDirectoryAsync(string path, short? permissions, CancellationToken ct);
    Task MoveAsync(string source, string destination, CancellationToken ct);
    Task<RemoteCommandResult> ExecuteAsync(string command, int timeoutSeconds, CancellationToken ct);
    Task<RemoteCommandResult> ExecuteTrackedAsync(RemoteCommandIdentity identity, string command, int timeoutSeconds, CancellationToken ct) =>
        Task.FromResult(new RemoteCommandResult(125, true, "SSLRECOVERY|Unsupported"));
    Task<RemoteCommandEvidence> InspectCommandAsync(RemoteCommandIdentity identity, int timeoutSeconds, CancellationToken ct) =>
        Task.FromResult(new RemoteCommandEvidence("Unsupported"));
}
