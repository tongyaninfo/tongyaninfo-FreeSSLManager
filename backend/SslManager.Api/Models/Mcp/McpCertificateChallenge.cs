namespace SslManager.Api.Models.Mcp;

/// <summary>显式授权读取的域名验证资料；Value仅用于工具响应，禁止进入调用审计及操作公开摘要。</summary>
public sealed record McpCertificateChallenge(string Purpose, string Domain, string Name, string Type,
    string Value, bool IsPersistent, bool IsRelative = false)
{
    public override string ToString() => "McpCertificateChallenge { 验证值已隐藏 }";
}
