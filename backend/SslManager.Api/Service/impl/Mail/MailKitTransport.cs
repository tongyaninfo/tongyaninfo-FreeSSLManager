using System.Net.Sockets;
using System.Text;
using MailKit;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;
using SslManager.Api.Common.Mail;
using SslManager.Api.Models.Mail;

namespace SslManager.Api.Service.impl.Mail;

/// <summary>仅支持 SMTP 密码认证与强制 TLS；不重发邮件，也不保存协议或服务器自由文本。</summary>
public sealed class MailKitTransport(MailEndpointGuard guard) : IMailTransport
{
    public async Task<MailTransportProbeResult> ProbeAsync(MailTransportEndpoint endpoint, CancellationToken ct)
    {
        using var timeout = Timeout(endpoint, ct);
        using var client = new SmtpClient();
        try
        {
            ValidateEndpoint(endpoint);
            client.Timeout = Math.Clamp(endpoint.TimeoutSeconds, 5, 120) * 1000;
            await guard.ConnectAsync(client, endpoint, timeout.Token);
            await client.AuthenticateAsync(endpoint.Username, endpoint.Password, timeout.Token);
            return new(true, "MAIL_CONNECTION_OK", "SMTP 连接与认证成功。");
        }
        catch (Exception ex) when (IsExpected(ex))
        {
            var result = Failure(ex, ct);
            return new(false, result.Code, result.Message);
        }
    }

    public async Task<MailTransportResult> SendAsync(MailTransportEndpoint endpoint, MailTransportMessage message, CancellationToken ct)
    {
        using var timeout = Timeout(endpoint, ct);
        using var submission = new SubmissionObserver();
        using var client = new SmtpClient(submission);
        try
        {
            ValidateEndpoint(endpoint);
            using var mime = CreateMime(message);
            client.Timeout = Math.Clamp(endpoint.TimeoutSeconds, 5, 120) * 1000;
            await guard.ConnectAsync(client, endpoint, timeout.Token);
            await client.AuthenticateAsync(endpoint.Username, endpoint.Password, timeout.Token);
            // 固定采用 DATA 路径，状态观察器只识别提交边界，不处理或保存认证和邮件字节。
            client.Capabilities &= ~SmtpCapabilities.Chunking;
            submission.Armed = true;
            await client.SendAsync(mime, timeout.Token);
            return new("Accepted", "MAIL_ACCEPTED", "邮件服务器已受理，不代表收件人已收到。");
        }
        catch (SmtpCommandException)
        {
            // 默认 SmtpClient 在任一收件人被拒绝时终止事务，不向其余收件人发送部分邮件。
            return new("Failed", "MAIL_SMTP_REJECTED", "SMTP 服务器明确拒绝邮件，请检查发件身份、收件地址或服务器策略。");
        }
        catch (Exception ex) when (IsExpected(ex))
        {
            if (submission.Started)
                return new("Unknown", "MAIL_RESULT_UNKNOWN", "邮件提交期间连接中断，结果未知，请人工核验；系统不会自动重发。");
            return Failure(ex, ct);
        }
    }

    /// <summary>人工邮件保持纯文本；提醒邮件提供 UTF-8 文本与 HTML 替代正文，地址仍禁止显示名和换行注入。</summary>
    public static MimeMessage CreateMime(MailTransportMessage message)
    {
        if (message.To.Count is < 1 or > 50 || string.IsNullOrWhiteSpace(message.Subject)
            || message.Subject.Length > 300 || message.Subject.Contains('\r') || message.Subject.Contains('\n')
            || string.IsNullOrWhiteSpace(message.Body) || message.Body.Length > 100000
            || message.HtmlBody is not null && (string.IsNullOrWhiteSpace(message.HtmlBody) || message.HtmlBody.Length > 100000)
            || string.IsNullOrWhiteSpace(message.MessageId) || message.MessageId.Any(char.IsControl))
            throw new ArgumentException("邮件收件人、主题或正文无效。");
        var mime = new MimeMessage
        {
            MessageId = message.MessageId,
            Date = new DateTimeOffset(DateTime.SpecifyKind(message.CreatedAtUtc, DateTimeKind.Utc)),
            Subject = message.Subject
        };
        try
        {
            mime.From.Add(Address(message.FromAddress, message.FromName));
            foreach (var recipient in message.To) mime.To.Add(Address(recipient, ""));
            var body = new TextPart("plain") { ContentTransferEncoding = ContentEncoding.QuotedPrintable };
            body.SetText(Encoding.UTF8, message.Body);
            if (message.HtmlBody is null) mime.Body = body;
            else
            {
                var html = new TextPart("html") { ContentTransferEncoding = ContentEncoding.QuotedPrintable };
                html.SetText(Encoding.UTF8, message.HtmlBody);
                mime.Body = new MultipartAlternative { body, html };
            }
            return mime;
        }
        catch { mime.Dispose(); throw; }
    }

    private static MailboxAddress Address(string address, string name)
    {
        if (string.IsNullOrWhiteSpace(address) || address.Length > 254 || address.Contains('\r') || address.Contains('\n')
            || !MailboxAddress.TryParse(address, out var parsed) || parsed.Address != address
            || name.Length > 100 || name.Contains('\r') || name.Contains('\n'))
            throw new ArgumentException("邮件地址无效。");
        return new MailboxAddress(Encoding.UTF8, name, address);
    }

    private static void ValidateEndpoint(MailTransportEndpoint endpoint)
    {
        _ = MailEndpointGuard.TlsOption(endpoint.Security);
        if (string.IsNullOrWhiteSpace(endpoint.Username) || endpoint.Username.Length > 254
            || endpoint.Username.Contains('\r') || endpoint.Username.Contains('\n') || string.IsNullOrEmpty(endpoint.Password))
            throw new ArgumentException("SMTP 账号或密码尚未配置。");
    }

    private static CancellationTokenSource Timeout(MailTransportEndpoint endpoint, CancellationToken ct)
    {
        var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(Math.Clamp(endpoint.TimeoutSeconds, 5, 120)));
        return timeout;
    }

    private static bool IsExpected(Exception ex) => ex is IOException or SocketException or TimeoutException
        or OperationCanceledException or ArgumentException or FormatException or AuthenticationException
        or SslHandshakeException or ProtocolException or InvalidOperationException or SmtpCommandException;

    private static MailTransportResult Failure(Exception ex, CancellationToken ct) => ex switch
    {
        SslHandshakeException => new("Failed", "MAIL_TLS_FAILED", "TLS 协商或证书校验失败，请检查 SMTP 安全模式与证书。"),
        AuthenticationException => new("Failed", "MAIL_AUTH_FAILED", "SMTP 认证失败，请检查账号与密码或邮箱授权码。"),
        OperationCanceledException when ct.IsCancellationRequested => new("Failed", "MAIL_CANCELLED", "操作已取消，邮件尚未提交。"),
        OperationCanceledException or TimeoutException => new("Failed", "MAIL_TIMEOUT", "SMTP 操作超时，邮件尚未提交。"),
        ArgumentException or FormatException or InvalidOperationException => new("Failed", "MAIL_INVALID_CONFIGURATION", "SMTP 配置或邮件参数无效，请检查主机、安全模式、账号与邮件地址。"),
        _ => new("Failed", "MAIL_CONNECTION_FAILED", "SMTP 连接或协议操作失败，邮件尚未提交。")
    };

    /// <summary>借用 SDK 协议观察回调只记录 DATA 布尔边界，不保存、输出或检查凭据及正文内容。</summary>
    private sealed class SubmissionObserver : IProtocolLogger
    {
        private static ReadOnlySpan<byte> DataCommand => "DATA\r\n"u8;
        private int _offset;
        private bool _matching = true;
        public bool Armed { get; set; }
        public bool Started { get; private set; }
        public IAuthenticationSecretDetector? AuthenticationSecretDetector { get; set; }
        public void LogConnect(Uri uri) { }
        public void LogServer(byte[] buffer, int offset, int count) { }
        public void Dispose() { }
        public void LogClient(byte[] buffer, int offset, int count)
        {
            if (!Armed || Started) return;
            foreach (var value in buffer.AsSpan(offset, count))
            {
                _matching &= _offset < DataCommand.Length && value == DataCommand[_offset];
                _offset = Math.Min(_offset + 1, DataCommand.Length + 1);
                if (value != '\n') continue;
                if (_matching && _offset == DataCommand.Length) { Started = true; return; }
                _offset = 0;
                _matching = true;
            }
        }
    }
}
