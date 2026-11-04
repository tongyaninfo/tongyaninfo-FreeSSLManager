using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Renci.SshNet;
using Renci.SshNet.Common;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl.Deployment.Transports;

/// <summary>SSH.NET 会话；握手先核验固定主机密钥，不自动信任新指纹。</summary>
public sealed class SshRemoteTransport(ILogger<SshRemoteTransport>? logger = null) : IRemoteTransport
{
    public async Task<ApiResult<IRemoteSession>> ConnectAsync(DeploymentTargetContext target, CancellationToken ct)
    {
        var connected = await ConnectWithIdentityAsync(target, ct);
        return connected.Success && connected.Data?.Session is not null
            ? ApiResult<IRemoteSession>.Ok(connected.Data.Session)
            : ApiResult<IRemoteSession>.Fail(connected.Code, connected.Message);
    }

    public async Task<ApiResult<RemoteConnectionAttempt>> ConnectWithIdentityAsync(DeploymentTargetContext target, CancellationToken ct)
    {
        var endpoint = ParseEndpoint(target);
        if (!endpoint.Success) return ApiResult<RemoteConnectionAttempt>.Fail(endpoint.Code, endpoint.Message);
        if (string.IsNullOrWhiteSpace(target.Username)) return ApiResult<RemoteConnectionAttempt>.Fail("CONFIGURATION_INVALID", "请输入 SSH 用户名。");
        if (target.AuthenticationMode is not ("Password" or "PrivateKey"))
            return ApiResult<RemoteConnectionAttempt>.Fail("AUTHENTICATION_UNSUPPORTED", "SSH 支持密码或私钥认证。");
        var keys = new List<PrivateKeyFile>();
        var session = new SshRemoteSession(target, endpoint.Data.Host, endpoint.Data.Port, keys);
        try
        {
            await session.ConnectAsync(ct);
            return ApiResult<RemoteConnectionAttempt>.Ok(new(session, session.ObservedFingerprint));
        }
        catch (Exception exception) when (exception is SshException or SocketException or IOException or
            ArgumentException or InvalidOperationException or OperationCanceledException or CryptographicException)
        {
            await session.DisposeAsync();
            if (ct.IsCancellationRequested) throw;
            if (!session.HostTrusted && !string.IsNullOrEmpty(session.ObservedFingerprint))
                return new(false, string.IsNullOrWhiteSpace(target.Configuration.HostKeyFingerprint)
                    ? "HOST_IDENTITY_REQUIRED" : "HOST_IDENTITY_CHANGED",
                    "SSH 主机身份尚未信任或已变化；请通过可信渠道核对指纹：" + session.ObservedFingerprint,
                    new(ObservedFingerprint: session.ObservedFingerprint));
            // 仅记录脱敏原因，不把原始异常或连接凭据写入日志；区分网络、握手和 SFTP 初始化。
            var reason = DeploymentSafeText.Redact(exception.Message, target.Credentials);
            var stage = session.HostTrusted ? "SSH 认证或 SFTP 初始化" : "SSH 握手";
            logger?.LogWarning("SSH 连接失败，阶段：{Stage}；异常类型：{ExceptionType}；原因：{Reason}",
                stage, exception.GetType().Name, reason);
            if (exception is SshAuthenticationException)
                return ApiResult<RemoteConnectionAttempt>.Fail("AUTHENTICATION_FAILED", "SSH 身份认证失败，请核对账号和凭据。");
            if (exception is ArgumentException or CryptographicException)
                return ApiResult<RemoteConnectionAttempt>.Fail("CONFIGURATION_INVALID", "SSH 私钥、地址或连接参数不正确。");
            if (exception is SocketException socket)
                return ApiResult<RemoteConnectionAttempt>.Fail("REMOTE_CONNECTION_FAILED",
                    $"应用后端无法连接 SSH 服务器（{socket.SocketErrorCode}）：{reason}。请检查后端进程的网络访问权限和路由。");
            if (exception is SshOperationTimeoutException or OperationCanceledException)
                return ApiResult<RemoteConnectionAttempt>.Fail("REMOTE_TIMEOUT", $"{stage}超时，请核对服务器响应和超时设置。");
            return ApiResult<RemoteConnectionAttempt>.Fail("REMOTE_CONNECTION_FAILED", $"{stage}失败：{reason}");
        }
    }

    public static ApiResult<(string Host, int Port)> ParseEndpoint(DeploymentTargetContext target)
    {
        var value = target.Endpoint.Trim();
        if (value.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != "ssh" ||
                !string.IsNullOrEmpty(uri.UserInfo) || uri.AbsolutePath != "/" || !string.IsNullOrEmpty(uri.Query) ||
                !string.IsNullOrEmpty(uri.Fragment))
                return ApiResult<(string, int)>.Fail("CONFIGURATION_INVALID", "SSH 地址仅允许主机/IP 或 ssh://主机:端口，不含账号或路径。");
            var port = target.Port > 0 ? target.Port : uri.IsDefaultPort ? 22 : uri.Port;
            return port is > 0 and <= 65535
                ? ApiResult<(string, int)>.Ok((uri.Host, port))
                : ApiResult<(string, int)>.Fail("CONFIGURATION_INVALID", "SSH 端口不正确。");
        }
        if (value.Length == 0 || value.Length > 253 || value.Any(character => char.IsWhiteSpace(character) ||
                character is '/' or '\\' or '@' or '?' or '#'))
            return ApiResult<(string, int)>.Fail("CONFIGURATION_INVALID", "请输入有效的 SSH 主机或 IP。");
        var actualPort = target.Port == 0 ? 22 : target.Port;
        return actualPort is > 0 and <= 65535
            ? ApiResult<(string, int)>.Ok((value.Trim('[', ']'), actualPort))
            : ApiResult<(string, int)>.Fail("CONFIGURATION_INVALID", "SSH 端口不正确。");
    }

    /// <summary>仅接受 SHA256 指纹，兼容 OpenSSH base64 和冒号分隔十六进制表示。</summary>
    public static bool FingerprintMatches(string expected, byte[] hostKey)
    {
        var fingerprint = SHA256.HashData(hostKey);
        var text = expected.Trim();
        if (text.StartsWith("SHA256:", StringComparison.OrdinalIgnoreCase)) text = text[7..];
        if (text.Replace(":", "").Length == 64 && text.Replace(":", "").All(Uri.IsHexDigit))
            return CryptographicOperations.FixedTimeEquals(fingerprint, Convert.FromHexString(text.Replace(":", "")));
        try
        {
            var decoded = Convert.FromBase64String(text.PadRight((text.Length + 3) / 4 * 4, '='));
            return decoded.Length == fingerprint.Length && CryptographicOperations.FixedTimeEquals(decoded, fingerprint);
        }
        catch (FormatException) { return false; }
    }

    /// <summary>部署器使用 POSIX 位掩码；SSH.NET 的权限参数使用八进制数字表示，例如 384 必须传为 600。</summary>
    public static short ToSftpPermissionMode(short permissionBits)
    {
        if (permissionBits is < 0 or > 4095)
            throw new ArgumentOutOfRangeException(nameof(permissionBits), "POSIX 权限必须在 0000 至 7777 范围内。");
        return (short)(((permissionBits >> 9) & 7) * 1000 + ((permissionBits >> 6) & 7) * 100 +
            ((permissionBits >> 3) & 7) * 10 + (permissionBits & 7));
    }

    private sealed class SshRemoteSession(DeploymentTargetContext target, string host, int port,
        List<PrivateKeyFile> keys) : IRemoteSession
    {
        private SftpClient? sftp;
        private SshClient? ssh;
        public bool SupportsCommandRecovery => true;
        public bool HostTrusted { get; private set; }
        public string ObservedFingerprint { get; private set; } = "";

        public async Task ConnectAsync(CancellationToken ct)
        {
            sftp = new SftpClient(Connection()) { OperationTimeout = TimeSpan.FromSeconds(
                Math.Clamp(target.Configuration.OperationTimeoutSeconds, 5, 3600)) };
            sftp.HostKeyReceived += CheckKey;
            await sftp.ConnectAsync(ct);
        }

        private Renci.SshNet.ConnectionInfo Connection()
        {
            AuthenticationMethod authentication;
            if (target.AuthenticationMode == "PrivateKey")
            {
                using var input = new MemoryStream(Encoding.UTF8.GetBytes(target.Credentials.PrivateKey));
                var key = string.IsNullOrEmpty(target.Credentials.PrivateKeyPassphrase)
                    ? new PrivateKeyFile(input) : new PrivateKeyFile(input, target.Credentials.PrivateKeyPassphrase);
                keys.Add(key);
                authentication = new PrivateKeyAuthenticationMethod(target.Username, key);
            }
            else authentication = new PasswordAuthenticationMethod(target.Username, target.Credentials.Password);
            return new Renci.SshNet.ConnectionInfo(host, port, target.Username, authentication)
            { Timeout = TimeSpan.FromSeconds(Math.Clamp(target.Configuration.ConnectionTimeoutSeconds, 5, 120)) };
        }

        private void CheckKey(object? sender, HostKeyEventArgs arguments)
        {
            ObservedFingerprint = "SHA256:" + arguments.FingerPrintSHA256;
            HostTrusted = FingerprintMatches(target.Configuration.HostKeyFingerprint, arguments.HostKey);
            arguments.CanTrust = HostTrusted;
        }

        public async Task<RemoteFileInfo> StatAsync(string path, CancellationToken ct)
        {
            try
            {
                var file = await sftp!.GetAsync(RemotePathHelper.ToSftp(path), ct);
                var a = file.Attributes;
                short mode = (short)((a.OwnerCanRead ? 256 : 0) | (a.OwnerCanWrite ? 128 : 0) | (a.OwnerCanExecute ? 64 : 0) |
                    (a.GroupCanRead ? 32 : 0) | (a.GroupCanWrite ? 16 : 0) | (a.GroupCanExecute ? 8 : 0) |
                    (a.OthersCanRead ? 4 : 0) | (a.OthersCanWrite ? 2 : 0) | (a.OthersCanExecute ? 1 : 0));
                return new(true, a.IsDirectory, a.IsSymbolicLink, a.Size, mode);
            }
            catch (SftpPathNotFoundException) { return new(false); }
        }

        public async Task<RemoteDirectoryListing> ListDirectoryAsync(string path, int limit, CancellationToken ct)
        {
            var entries = new List<RemoteDirectoryEntry>();
            var truncated = false;
            await foreach (var file in sftp!.ListDirectoryAsync(RemotePathHelper.ToSftp(path), ct))
            {
                if (file.Name is "." or "..") continue;
                if (entries.Count >= limit) { truncated = true; break; }
                // 仅使用目录条目的元数据，不对文件执行下载或任何写操作。
                var selectableName = file.Name.Length is > 0 and <= 255 && !file.Name.Any(char.IsControl) &&
                    !file.Name.Contains('/') && !file.Name.Contains('\\');
                entries.Add(new(file.Name, path.TrimEnd('/') + "/" + file.Name, file.IsDirectory, file.IsSymbolicLink,
                    file.IsRegularFile, Math.Max(0, file.Length), DateTime.SpecifyKind(file.LastWriteTimeUtc, DateTimeKind.Utc),
                    selectableName && !file.IsSymbolicLink && (file.IsDirectory || file.IsRegularFile)));
            }
            return new(path, RemotePathHelper.Parent(path), entries.OrderByDescending(entry => entry.IsDirectory)
                .ThenBy(entry => entry.Name, StringComparer.Ordinal).ToArray(), truncated, ObservedFingerprint);
        }

        public async Task<byte[]> ReadAsync(string path, int byteLimit, CancellationToken ct)
        {
            var info = await StatAsync(path, ct);
            if (!info.Exists || info.IsDirectory || info.IsSymbolicLink || info.Length > byteLimit)
                throw new IOException("远端文件不存在、类型不允许或超出体积限制。");
            using var output = new BoundedMemoryStream(byteLimit);
            await sftp!.DownloadFileAsync(RemotePathHelper.ToSftp(path), output, ct);
            return output.ToArray();
        }

        public async Task WriteNewAsync(string path, byte[] content, short? permissions, CancellationToken ct)
        {
            var remote = RemotePathHelper.ToSftp(path);
            // 在创建文件前转换并校验，避免把位掩码当作八进制数字传入 SSH.NET。
            short? mode = permissions.HasValue ? ToSftpPermissionMode(permissions.Value) : null;
            // CreateNew 不覆盖已有文件；先限制空文件权限，再写入私钥正文。
            await using var output = await sftp!.OpenAsync(remote, FileMode.CreateNew, FileAccess.Write, ct);
            if (mode.HasValue)
                await Task.Run(() => sftp.ChangePermissions(remote, mode.Value), ct);
            await output.WriteAsync(content, ct);
            await output.FlushAsync(ct);
        }

        public async Task CreateDirectoryAsync(string path, short? permissions, CancellationToken ct)
        {
            var remote = RemotePathHelper.ToSftp(path);
            short? mode = permissions.HasValue ? ToSftpPermissionMode(permissions.Value) : null;
            await sftp!.CreateDirectoryAsync(remote, ct);
            if (mode.HasValue)
                await Task.Run(() => sftp.ChangePermissions(remote, mode.Value), ct);
        }

        public Task MoveAsync(string source, string destination, CancellationToken ct) =>
            sftp!.RenameFileAsync(RemotePathHelper.ToSftp(source), RemotePathHelper.ToSftp(destination), ct);

        public async Task<ApiResult<bool>> CheckCommandRecoverySupportAsync(bool windows, CancellationToken ct)
        {
            var probe = windows ? WindowsRemoteCommandRecoveryProtocol.Availability() : "sh -c 'command -v flock >/dev/null 2>&1'";
            var result = await ExecuteAsync(probe, Math.Clamp(target.Configuration.OperationTimeoutSeconds, 5, 30), ct);
            return RemoteCommandRecoveryProtocol.AvailabilityResult(result, windows);
        }

        public Task<RemoteCommandResult> ExecuteTrackedAsync(RemoteCommandIdentity identity, string command, int timeoutSeconds, CancellationToken ct)
        {
            var wrapped = RemoteCommandRecoveryProtocol.Execute(identity, command);
            return wrapped.Success ? ExecuteAsync(wrapped.Data!, timeoutSeconds, ct) : Task.FromResult(new RemoteCommandResult(null, false));
        }

        public async Task<RemoteCommandEvidence> InspectCommandAsync(RemoteCommandIdentity identity, int timeoutSeconds, CancellationToken ct)
        {
            var query = RemoteCommandRecoveryProtocol.Inspect(identity);
            if (!query.Success) return new("Conflict");
            return RemoteCommandRecoveryProtocol.ReadEvidence(await ExecuteAsync(query.Data!, timeoutSeconds, ct));
        }

        public async Task<RemoteCommandResult> ExecuteAsync(string command, int timeoutSeconds, CancellationToken ct)
        {
            if (ssh is null)
            {
                ssh = new SshClient(Connection());
                ssh.HostKeyReceived += CheckKey;
                await ssh.ConnectAsync(ct);
            }
            using var execution = ssh.CreateCommand(command);
            execution.CommandTimeout = TimeSpan.FromSeconds(timeoutSeconds);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
            try
            {
                var operation = execution.ExecuteAsync(timeout.Token);
                var stdout = DrainAsync(execution.OutputStream, timeout.Token);
                var stderr = DrainAsync(execution.ExtendedOutputStream, timeout.Token);
                await Task.WhenAll(operation, stdout, stderr);
                return new(execution.ExitStatus, execution.ExitStatus.HasValue, stdout.Result, stderr.Result);
            }
            catch (Exception ex) when (ex is SshException or IOException or OperationCanceledException or SocketException)
            {
                // 即使取消已发送终止信号，也不能证明远端动作没有完成。
                return new(null, false);
            }
        }

        public ValueTask DisposeAsync()
        {
            ssh?.Dispose(); sftp?.Dispose();
            foreach (var key in keys) key.Dispose();
            keys.Clear();
            return ValueTask.CompletedTask;
        }

        private static async Task<string> DrainAsync(Stream stream, CancellationToken ct)
        {
            using var output = new MemoryStream();
            var buffer = new byte[8192];
            int read;
            while ((read = await stream.ReadAsync(buffer, ct)) > 0)
            {
                var keep = Math.Min(read, Math.Max(0, 65536 - (int)output.Length));
                if (keep > 0) output.Write(buffer, 0, keep);
            }
            return Encoding.UTF8.GetString(output.ToArray());
        }
    }

    private sealed class BoundedMemoryStream(int limit) : MemoryStream
    {
        private void Check(int count) { if (Length + count > limit) throw new IOException("远端文件超出读取体积限制。"); }
        public override void Write(byte[] buffer, int offset, int count) { Check(count); base.Write(buffer, offset, count); }
        public override void Write(ReadOnlySpan<byte> buffer) { Check(buffer.Length); base.Write(buffer); }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        { Write(buffer, offset, count); return Task.CompletedTask; }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        { Write(buffer.Span); return ValueTask.CompletedTask; }
    }
}
