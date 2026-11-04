namespace SslManager.Api.Models.Mcp;

/// <summary>密钥权限继承所属客户端；管理输入不能直接指定用户或扩大资源权限。</summary>
public sealed record McpApiKeyInput(string Name, DateTime? ExpiresAtUtc = null);
public sealed record McpApiKeyRevisionInput(int? ConfigRevision = null);
public sealed record McpApiKeyView(string Id, string ClientId, string Name, string Prefix, bool Enabled,
    DateTime? ExpiresAtUtc, DateTime CreatedAtUtc, DateTime UpdatedAtUtc, DateTime? LastUsedAtUtc,
    DateTime? RevokedAtUtc, int ConfigRevision);
/// <summary>仅显式创建或轮换返回一次明文，不得缓存或进入普通日志。</summary>
public sealed record McpApiKeyCreated(McpApiKeyView Key, string ApiKey)
{
    public override string ToString() => "McpApiKeyCreated { 一次性密钥已隐藏 }";
}
