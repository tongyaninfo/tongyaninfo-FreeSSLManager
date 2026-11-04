using System.ComponentModel.DataAnnotations;

namespace SslManager.Api.Models;

/// <summary>本地登录用户；密码仅保存 PasswordHasher 生成的哈希。</summary>
public sealed class UserAccount
{
    [MaxLength(64)] public string Id { get; set; } = "";
    [MaxLength(80)] public string Username { get; set; } = "";
    [MaxLength(80)] public string NormalizedUsername { get; set; } = "";
    [MaxLength(100)] public string DisplayName { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    [MaxLength(20)] public string Role { get; set; } = "viewer";
    public bool Enabled { get; set; } = true;
    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
}
