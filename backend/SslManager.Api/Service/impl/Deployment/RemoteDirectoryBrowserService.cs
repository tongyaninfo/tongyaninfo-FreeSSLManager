using System.Net.Sockets;
using Renci.SshNet.Common;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl.Deployment;

/// <summary>只读 SFTP 目录浏览；不读取文件正文、不写文件、不执行远端命令。</summary>
public sealed class RemoteDirectoryBrowserService(IRemoteTransport transport)
{
    private const int EntryLimit = 1000;

    public async Task<ApiResult<RemoteDirectoryListing>> BrowseAsync(DeploymentTargetContext target, string path, CancellationToken ct)
    {
        if (target.ExecutorKey != "linux.files.ssh.v1")
            return ApiResult<RemoteDirectoryListing>.Fail("BROWSE_UNSUPPORTED", "当前仅支持 Linux SSH 目录浏览。");
        var validated = RemotePathHelper.ValidateAbsolute(path, false);
        if (!validated.Success || validated.Data is null)
            return ApiResult<RemoteDirectoryListing>.Fail(validated.Code, validated.Message);
        var directory = validated.Data == "/" ? "/" : validated.Data.TrimEnd('/');
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(target.Configuration.ConnectionTimeoutSeconds +
            target.Configuration.OperationTimeoutSeconds, 5, 120)));
        try
        {
            var connected = await transport.ConnectWithIdentityAsync(target, timeout.Token);
            if (!connected.Success || connected.Data?.Session is null)
            {
                var observed = connected.Data?.ObservedFingerprint ?? "";
                return new(false, connected.Code, DeploymentSafeText.Redact(connected.Message, target.Credentials),
                    string.IsNullOrEmpty(observed) ? null : new(directory, RemotePathHelper.Parent(directory), [], ObservedFingerprint: observed));
            }
            await using var session = connected.Data.Session;
            // 逐级检查，禁止通过父目录中的符号链接绕过实际部署的路径限制。
            var current = directory;
            for (var depth = 0; ; depth++)
            {
                if (depth >= 64)
                    return ApiResult<RemoteDirectoryListing>.Fail("DIRECTORY_DEPTH_LIMIT", "目录层级过深，请选择层级少于 64 的目录。");
                var info = await session.StatAsync(current, timeout.Token);
                if (!info.Exists)
                    return ApiResult<RemoteDirectoryListing>.Fail("DIRECTORY_NOT_FOUND", "目录不存在，请选择已有目录。");
                if (info.IsSymbolicLink)
                    return ApiResult<RemoteDirectoryListing>.Fail("SYMBOLIC_LINK_UNSUPPORTED", "目录或其父目录是符号链接，请使用真实目录路径。");
                if (!info.IsDirectory)
                    return ApiResult<RemoteDirectoryListing>.Fail("PATH_NOT_DIRECTORY", "所选路径不是目录。");
                if (current == "/") break;
                current = RemotePathHelper.Parent(current);
            }
            var listing = await session.ListDirectoryAsync(directory, EntryLimit, timeout.Token);
            return ApiResult<RemoteDirectoryListing>.Ok(listing with { ObservedFingerprint = connected.Data.ObservedFingerprint });
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { return ApiResult<RemoteDirectoryListing>.Fail("REMOTE_TIMEOUT", "目录浏览超时，请稍后重试。"); }
        catch (SftpPermissionDeniedException)
        { return ApiResult<RemoteDirectoryListing>.Fail("PERMISSION_DENIED", "SSH 账号没有读取此目录的权限。"); }
        catch (SftpPathNotFoundException)
        { return ApiResult<RemoteDirectoryListing>.Fail("DIRECTORY_NOT_FOUND", "目录不存在或已被移动，请刷新后重试。"); }
        catch (Exception exception) when (exception is IOException or SshException or SocketException or InvalidOperationException or NotSupportedException)
        { return ApiResult<RemoteDirectoryListing>.Fail("REMOTE_READ_FAILED", "远端目录读取失败，请核对连接、路径和访问权限。"); }
    }
}
