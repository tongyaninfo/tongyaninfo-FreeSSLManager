using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using SslManager.Api.Models;
using SslManager.Api.Service.impl.Deployment.Transports;

namespace SslManager.Tests;

/// <summary>通过真实回环 TCP 连接验证 SSH 错误分类、脱敏和调用者取消，不访问外部服务器。</summary>
public sealed class SshConnectionDiagnosticsTests
{
    [Fact]
    public async Task RefusedConnectionReportsBackendNetworkFailureInsteadOfBadCredentials()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var logger = new CapturingLogger();

        var result = await new SshRemoteTransport(logger)
            .ConnectWithIdentityAsync(Target(port), default).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.False(result.Success);
        Assert.Equal("REMOTE_CONNECTION_FAILED", result.Code);
        Assert.Contains(nameof(SocketError.ConnectionRefused), result.Message);
        Assert.Contains("后端进程", result.Message);
        Assert.DoesNotContain("认证失败", result.Message);
        Assert.Contains(nameof(SocketException), Assert.Single(logger.Messages));
    }

    [Fact]
    public async Task ServerDisconnectKeepsHandshakeReasonButRedactsPasswordFromResponseAndLog()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var logger = new CapturingLogger();
        var target = Target(((IPEndPoint)listener.LocalEndpoint).Port);
        var connecting = new SshRemoteTransport(logger).ConnectWithIdentityAsync(target, default);
        using var server = await listener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(10));

        // 模拟 SSH 服务端在握手时主动断开，并故意在诊断正文中回显敏感值。
        var stream = server.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes("SSH-2.0-LocalDiagnosticsServer\r\n"));
        await stream.WriteAsync(DisconnectPacket("diagnostic failure: " + target.Credentials.Password));
        var result = await connecting.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.False(result.Success);
        Assert.Equal("REMOTE_CONNECTION_FAILED", result.Code);
        Assert.Contains("SSH 握手", result.Message);
        Assert.Contains("diagnostic failure", result.Message);
        Assert.Contains("[REDACTED]", result.Message);
        Assert.DoesNotContain(target.Credentials.Password, result.Message);
        var message = Assert.Single(logger.Messages);
        Assert.Contains("diagnostic failure", message);
        Assert.Contains("[REDACTED]", message);
        Assert.DoesNotContain(target.Credentials.Password, message);
    }

    [Fact]
    public async Task CallerCancellationIsPropagatedDuringHandshake()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        using var cancellation = new CancellationTokenSource();
        var logger = new CapturingLogger();
        var connecting = new SshRemoteTransport(logger).ConnectWithIdentityAsync(
            Target(((IPEndPoint)listener.LocalEndpoint).Port), cancellation.Token);
        using var server = await listener.AcceptTcpClientAsync().WaitAsync(TimeSpan.FromSeconds(10));

        // TCP 已连接但服务端尚未发送 SSH 标识，确保取消发生在实际握手中。
        cancellation.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => connecting.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Empty(logger.Messages);
    }

    private static DeploymentTargetContext Target(int port) => new()
    {
        Endpoint = IPAddress.Loopback.ToString(), Port = port, Username = "local-diagnostics",
        AuthenticationMode = "Password", Credentials = new() { Password = "diagnostic-password-with-comma," },
        Configuration = new() { ConnectionTimeoutSeconds = 5, OperationTimeoutSeconds = 5 }
    };

    private static byte[] DisconnectPacket(string description)
    {
        // RFC 4253：SSH_MSG_DISCONNECT、原因代码、UTF-8 说明及空语言标签；消息尚未加密。
        var text = Encoding.UTF8.GetBytes(description);
        var payload = new byte[1 + 4 + 4 + text.Length + 4];
        payload[0] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(1), 2);
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(5), (uint)text.Length);
        text.CopyTo(payload.AsSpan(9));
        var padding = 8 - ((payload.Length + 5) % 8);
        if (padding < 4) padding += 8;
        var packet = new byte[4 + 1 + payload.Length + padding];
        BinaryPrimitives.WriteUInt32BigEndian(packet, (uint)(1 + payload.Length + padding));
        packet[4] = (byte)padding;
        payload.CopyTo(packet.AsSpan(5));
        return packet;
    }

    private sealed class CapturingLogger : ILogger<SshRemoteTransport>
    {
        public List<string> Messages { get; } = [];
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Messages.Add(formatter(state, exception));
    }
}
