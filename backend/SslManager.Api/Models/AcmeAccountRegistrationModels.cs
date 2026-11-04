namespace SslManager.Api.Models;

/// <summary>显式注册结果只含可复用的公开账户标识，私钥仍通过现有管理员主动查看接口获取。</summary>
public sealed record AcmeAccountRegistrationView(string AccountUrl, string DirectoryUrl, string PublicKeyThumbprint,
    string Status, DateTime? RegisteredAtUtc);
