using System.ComponentModel.DataAnnotations;

namespace SslManager.Api.Models;

public sealed class LoginInput
{
    [Required, StringLength(80)] public string Username { get; set; } = "";
    [Required, StringLength(256)] public string Password { get; set; } = "";
}

/// <summary>已登录用户修改自己的密码；旧密码用于确认当前会话持有人。</summary>
public sealed class ChangePasswordInput
{
    [Required, StringLength(256)] public string CurrentPassword { get; set; } = "";
    [Required, StringLength(256)] public string NewPassword { get; set; } = "";
}

public sealed class SetupInput
{
    [Required, StringLength(80)] public string Username { get; set; } = "";
    [Required, StringLength(256)] public string Password { get; set; } = "";
    [StringLength(100)] public string DisplayName { get; set; } = "";
}

public sealed class UserInput
{
    [Required, StringLength(80)] public string Username { get; set; } = "";
    /// <summary>创建时必须填写；更新时空字符串表示保留原密码。</summary>
    [StringLength(256)] public string Password { get; set; } = "";
    [StringLength(100)] public string DisplayName { get; set; } = "";
    [Required, StringLength(20)] public string Role { get; set; } = "viewer";
    public bool Enabled { get; set; } = true;
}

public sealed record CurrentUser(string Id, string Username, string Name, string Role);
public sealed record ManagedUser(string Id, string Username, string DisplayName, string Role, bool Enabled,
    DateTime CreatedAtUtc, DateTime UpdatedAtUtc);
public sealed record SetupStatus(bool NeedsSetup);
public sealed record CsrfToken(string Token);
