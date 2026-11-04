using System.Net;
using System.Text;
using System.Text.Json;
using MailKit;
using MailKit.Security;
using Microsoft.Extensions.Options;
using SslManager.Api.Common.Mail;
using SslManager.Api.Models.Mail;
using SslManager.Api.Service.impl.Mail;

namespace SslManager.Tests;

public sealed class MailTransportTests
{
    private static readonly MailTransportEndpoint Endpoint = new("mail.example.test", 465, "SslOnConnect", "sender@example.test", "synthetic-password");
    private static MailTransportMessage Message(params string[] recipients) => new("synthetic@example.test", "sender@example.test", "测试发件人",
        recipients, "测试主题", "纯文本测试正文", new DateTime(2026, 11, 2, 0, 0, 0, DateTimeKind.Utc));

    [Fact]
    public async Task ServerAcceptance_IsRecordedWithoutClaimingDelivery()
    {
        using var script = new SmtpScriptStream();
        var result = await Transport(script).SendAsync(Endpoint, Message("to@example.test"), CancellationToken.None);
        Assert.Equal("Accepted", result.Status);
        Assert.Equal("MAIL_ACCEPTED", result.Code);
        Assert.Contains("不代表", result.Message);
        Assert.True(script.DataCompleted);
    }

    [Fact]
    public async Task LostFinalReply_IsUnknown()
    {
        using var script = new SmtpScriptStream(dropFinalReply: true);
        var result = await Transport(script).SendAsync(Endpoint, Message("to@example.test"), CancellationToken.None);
        Assert.Equal("Unknown", result.Status);
        Assert.Equal("MAIL_RESULT_UNKNOWN", result.Code);
        Assert.True(script.DataCompleted);
    }

    [Fact]
    public async Task LostRecipientReply_BeforeDataIsFailed()
    {
        using var script = new SmtpScriptStream(dropRecipientReply: true);
        var result = await Transport(script).SendAsync(Endpoint, Message("to@example.test"), CancellationToken.None);
        Assert.Equal("Failed", result.Status);
        Assert.False(script.DataCompleted);
    }

    [Fact]
    public async Task OneRejectedRecipient_AbortsBeforeSendingToAnyone()
    {
        using var script = new SmtpScriptStream(rejectAddress: "reject@example.test");
        var result = await Transport(script).SendAsync(Endpoint, Message("ok@example.test", "reject@example.test"), CancellationToken.None);
        Assert.Equal("Failed", result.Status);
        Assert.Equal("MAIL_SMTP_REJECTED", result.Code);
        Assert.False(script.DataCompleted);
        Assert.DoesNotContain("synthetic-server-private-response", result.Message);
    }

    [Fact]
    public void Mime_UsesFrozenMessageIdAndUtf8PlainText()
    {
        var message = Message("to@example.test");
        using var mime = MailKitTransport.CreateMime(message);
        Assert.Equal(message.MessageId, mime.MessageId);
        Assert.Equal(message.CreatedAtUtc, mime.Date.UtcDateTime);
        Assert.Equal(message.Body, mime.TextBody);
        Assert.Null(mime.HtmlBody);
        Assert.Equal("utf-8", Assert.IsType<MimeKit.TextPart>(mime.Body).ContentType.Charset);
    }

    [Fact]
    public void Mime_RejectsHeaderInjection()
    {
        Assert.Throws<ArgumentException>(() => MailKitTransport.CreateMime(Message("to@example.test") with { Subject = "subject\r\nBcc: hidden@example.test" }));
        Assert.Throws<ArgumentException>(() => MailKitTransport.CreateMime(Message("To <to@example.test>")));
    }

    [Fact]
    public void Credentials_CannotBeSerializedOrPrinted()
    {
        Assert.DoesNotContain(Endpoint.Password, JsonSerializer.Serialize(Endpoint));
        Assert.DoesNotContain(Endpoint.Password, Endpoint.ToString());
    }

    [Theory]
    [InlineData("None")]
    [InlineData("Auto")]
    [InlineData("StartTlsWhenAvailable")]
    public void CleartextAndOpportunisticSecurity_AreRejected(string security)
        => Assert.Throws<ArgumentException>(() => MailEndpointGuard.TlsOption(security));

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("169.254.169.254")]
    [InlineData("::1")]
    [InlineData("::ffff:127.0.0.1")]
    [InlineData("fe80::1")]
    public void LoopbackAndMetadataEndpoints_AreForbidden(string address)
        => Assert.True(MailEndpointGuard.IsForbidden(IPAddress.Parse(address)));

    [Fact]
    public async Task ProductionGuard_RejectsLoopbackWithoutConnecting()
    {
        var transport = new MailKitTransport(new MailEndpointGuard(Options.Create(new MailEndpointOptions())));
        var result = await transport.ProbeAsync(Endpoint with { Host = "127.0.0.1" }, CancellationToken.None);
        Assert.False(result.Success);
        Assert.Equal("MAIL_INVALID_CONFIGURATION", result.Code);
    }

    private static MailKitTransport Transport(Stream stream) => new(new ScriptConnector(stream));

    private sealed class ScriptConnector(Stream stream) : MailEndpointGuard(Options.Create(new MailEndpointOptions()))
    {
        public override Task ConnectAsync(MailKit.MailService client, MailTransportEndpoint endpoint, CancellationToken ct)
            // 无网络的协议测试替身不建立 TLS；生产连接器始终强制 TLS 并验证证书。
            => client.ConnectAsync(stream, endpoint.Host, endpoint.Port, SecureSocketOptions.None, ct);
    }

    /// <summary>仅处理合成 SMTP 会话，不连接任何真实邮箱，也不创建测试文件。</summary>
    private sealed class SmtpScriptStream(string? rejectAddress = null, bool dropFinalReply = false, bool dropRecipientReply = false) : Stream
    {
        private readonly Queue<byte> _responses = new(Encoding.ASCII.GetBytes("220 test ESMTP ready\r\n"));
        private readonly StringBuilder _incoming = new();
        private bool _data;
        public bool DataCompleted { get; private set; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override Task FlushAsync(CancellationToken ct) => Task.CompletedTask;
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_responses.Count == 0) throw new IOException("Synthetic disconnected SMTP stream.");
            var read = 0;
            while (read < count && _responses.TryDequeue(out var value)) buffer[offset + read++] = value;
            return read;
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            var bytes = new byte[buffer.Length];
            var read = Read(bytes, 0, bytes.Length);
            bytes.AsMemory(0, read).CopyTo(buffer);
            return ValueTask.FromResult(read);
        }
        public override void Write(byte[] buffer, int offset, int count) => Process(Encoding.UTF8.GetString(buffer, offset, count));
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        { Process(Encoding.UTF8.GetString(buffer.Span)); return ValueTask.CompletedTask; }
        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        { Write(buffer, offset, count); return Task.CompletedTask; }
        private void Process(string text)
        {
            _incoming.Append(text);
            if (_data)
            {
                if (!_incoming.ToString().EndsWith("\r\n.\r\n", StringComparison.Ordinal)) return;
                DataCompleted = true;
                _data = false;
                _incoming.Clear();
                if (!dropFinalReply) Reply("250 accepted\r\n");
                return;
            }
            while (_incoming.ToString().Contains("\r\n", StringComparison.Ordinal))
            {
                var input = _incoming.ToString();
                var end = input.IndexOf("\r\n", StringComparison.Ordinal);
                var command = input[..end];
                _incoming.Remove(0, end + 2);
                if (command.StartsWith("EHLO", StringComparison.Ordinal)) Reply("250-test\r\n250 AUTH PLAIN\r\n");
                else if (command.StartsWith("AUTH", StringComparison.Ordinal)) Reply("235 authenticated\r\n");
                else if (command.StartsWith("MAIL", StringComparison.Ordinal)) Reply("250 sender accepted\r\n");
                else if (command.StartsWith("RCPT", StringComparison.Ordinal))
                {
                    if (!dropRecipientReply) Reply(rejectAddress is not null && command.Contains(rejectAddress, StringComparison.Ordinal)
                        ? "550 synthetic-server-private-response\r\n" : "250 recipient accepted\r\n");
                }
                else if (command == "DATA") { _data = true; Reply("354 continue\r\n"); break; }
                else if (command == "RSET") Reply("250 reset\r\n");
                else if (command == "QUIT") Reply("221 bye\r\n");
                else throw new IOException("Unexpected synthetic SMTP command.");
            }
        }
        private void Reply(string text) { foreach (var value in Encoding.ASCII.GetBytes(text)) _responses.Enqueue(value); }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
