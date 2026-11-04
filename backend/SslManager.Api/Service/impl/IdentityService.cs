using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

public sealed class IdentityService(AppDbContext db, IPasswordHasher<UserAccount> passwords, IIdGenerator ids)
    : IIdentityService
{
    // SQLite 单实例部署下串行处理初始化和用户修改，避免同时降级最后两位管理员。
    private static readonly SemaphoreSlim UserWriteGate = new(1, 1);
    private static readonly Regex UsernamePattern = new("^[A-Za-z0-9_.@-]{1,80}$", RegexOptions.CultureInvariant);

    public Task<bool> IsSetupRequiredAsync(CancellationToken ct) => IsEmptyAsync(ct);

    private async Task<bool> IsEmptyAsync(CancellationToken ct) => !await db.Users.AnyAsync(ct);

    public async Task<ApiResult<CurrentUser>> SetupAsync(SetupInput input, CancellationToken ct)
    {
        var validation = ValidateUser(input.Username, input.Password, input.DisplayName, "admin", true);
        if (validation is not null) return ApiResult<CurrentUser>.Fail("VALIDATION", validation);
        await UserWriteGate.WaitAsync(ct);
        try
        {
            if (await db.Users.AnyAsync(ct))
                return ApiResult<CurrentUser>.Fail("CONFLICT", "管理员已初始化，请使用现有账号登录。");
            var user = NewUser(input.Username.Trim(), input.DisplayName, "admin", true);
            user.PasswordHash = passwords.HashPassword(user, input.Password);
            db.Users.Add(user);
            await db.SaveChangesAsync(ct);
            return ApiResult<CurrentUser>.Ok(ToCurrent(user), "管理员已初始化。");
        }
        finally { UserWriteGate.Release(); }
    }

    public async Task<ApiResult<CurrentUser>> LoginAsync(LoginInput input, CancellationToken ct)
    {
        var username = (input.Username ?? "").Trim().ToUpperInvariant();
        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(input.Password) || input.Password.Length > 256)
            return InvalidLogin();
        await UserWriteGate.WaitAsync(ct);
        try
        {
            var user = await db.Users.SingleOrDefaultAsync(x => x.NormalizedUsername == username, ct);
            // 不向匿名调用者区分不存在、停用和密码错误。
            if (user is null || !user.Enabled) return InvalidLogin();
            var verified = passwords.VerifyHashedPassword(user, user.PasswordHash, input.Password);
            if (verified == PasswordVerificationResult.Failed) return InvalidLogin();
            if (verified == PasswordVerificationResult.SuccessRehashNeeded)
            {
                user.PasswordHash = passwords.HashPassword(user, input.Password);
                user.UpdatedAtUtc = DateTime.UtcNow;
                await db.SaveChangesAsync(ct);
            }
            return ApiResult<CurrentUser>.Ok(ToCurrent(user), "登录成功。");
        }
        finally { UserWriteGate.Release(); }
    }

    public async Task<ApiResult<CurrentUser>> ChangePasswordAsync(string userId, ChangePasswordInput input, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(userId)) return ApiResult<CurrentUser>.Fail("UNAUTHORIZED", "登录已失效，请重新登录。");
        if (string.IsNullOrEmpty(input.CurrentPassword) || input.CurrentPassword.Length > 256)
            return ApiResult<CurrentUser>.Fail("VALIDATION", "请输入当前密码，且长度不能超过 256 个字符。");
        if (string.IsNullOrEmpty(input.NewPassword) || input.NewPassword.Length > 256)
            return ApiResult<CurrentUser>.Fail("VALIDATION", "请输入新密码，且长度不能超过 256 个字符。");
        if (input.CurrentPassword == input.NewPassword)
            return ApiResult<CurrentUser>.Fail("VALIDATION", "新密码不能与当前密码相同。");

        await UserWriteGate.WaitAsync(ct);
        try
        {
            var user = await db.Users.SingleOrDefaultAsync(x => x.Id == userId, ct);
            if (user is null || !user.Enabled)
                return ApiResult<CurrentUser>.Fail("UNAUTHORIZED", "登录已失效，请重新登录。");
            if (passwords.VerifyHashedPassword(user, user.PasswordHash, input.CurrentPassword) == PasswordVerificationResult.Failed)
                return ApiResult<CurrentUser>.Fail("VALIDATION", "当前密码不正确。");

            user.PasswordHash = passwords.HashPassword(user, input.NewPassword);
            user.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(ct);
            return ApiResult<CurrentUser>.Ok(ToCurrent(user), "密码修改成功。");
        }
        finally { UserWriteGate.Release(); }
    }

    public async Task<ApiResult<CurrentUser>> GetCurrentUserAsync(string userId, CancellationToken ct)
    {
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == userId, ct);
        return user is null || !user.Enabled
            ? ApiResult<CurrentUser>.Fail("UNAUTHORIZED", "登录已失效，请重新登录。")
            : ApiResult<CurrentUser>.Ok(ToCurrent(user));
    }

    public async Task<ApiResult<IReadOnlyList<ManagedUser>>> ListUsersAsync(CancellationToken ct)
    {
        var users = await db.Users.AsNoTracking().OrderBy(x => x.CreatedAtUtc).ToListAsync(ct);
        return ApiResult<IReadOnlyList<ManagedUser>>.Ok(users.Select(ToManaged).ToArray());
    }

    public async Task<ApiResult<ManagedUser>> CreateUserAsync(UserInput input, CancellationToken ct)
    {
        var validation = ValidateUser(input.Username, input.Password, input.DisplayName, input.Role, true);
        if (validation is not null) return ApiResult<ManagedUser>.Fail("VALIDATION", validation);
        await UserWriteGate.WaitAsync(ct);
        try
        {
            var normalized = input.Username.Trim().ToUpperInvariant();
            if (await db.Users.AnyAsync(x => x.NormalizedUsername == normalized, ct))
                return ApiResult<ManagedUser>.Fail("CONFLICT", "该用户名已存在。");
            var user = NewUser(input.Username.Trim(), input.DisplayName, input.Role, input.Enabled);
            user.PasswordHash = passwords.HashPassword(user, input.Password);
            db.Users.Add(user);
            await db.SaveChangesAsync(ct);
            return ApiResult<ManagedUser>.Ok(ToManaged(user), "用户已创建。");
        }
        finally { UserWriteGate.Release(); }
    }

    public async Task<ApiResult<ManagedUser>> UpdateUserAsync(string id, UserInput input, CancellationToken ct)
    {
        var validation = ValidateUser(input.Username, input.Password, input.DisplayName, input.Role, false);
        if (validation is not null) return ApiResult<ManagedUser>.Fail("VALIDATION", validation);
        await UserWriteGate.WaitAsync(ct);
        try
        {
            var user = await db.Users.SingleOrDefaultAsync(x => x.Id == id, ct);
            if (user is null) return ApiResult<ManagedUser>.Fail("NOT_FOUND", "用户不存在。");
            var normalized = input.Username.Trim().ToUpperInvariant();
            if (await db.Users.AnyAsync(x => x.Id != id && x.NormalizedUsername == normalized, ct))
                return ApiResult<ManagedUser>.Fail("CONFLICT", "该用户名已存在。");
            if (user.Enabled && user.Role == "admin" && (!input.Enabled || input.Role != "admin") &&
                !await db.Users.AnyAsync(x => x.Id != id && x.Enabled && x.Role == "admin", ct))
                return ApiResult<ManagedUser>.Fail("CONFLICT", "不能停用或降级最后一位启用的管理员。");
            user.Username = input.Username.Trim();
            user.NormalizedUsername = normalized;
            user.DisplayName = string.IsNullOrWhiteSpace(input.DisplayName) ? user.Username : input.DisplayName.Trim();
            user.Role = input.Role;
            user.Enabled = input.Enabled;
            if (!string.IsNullOrEmpty(input.Password)) user.PasswordHash = passwords.HashPassword(user, input.Password);
            user.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(ct);
            return ApiResult<ManagedUser>.Ok(ToManaged(user), "用户已更新。");
        }
        finally { UserWriteGate.Release(); }
    }

    private UserAccount NewUser(string username, string displayName, string role, bool enabled)
    {
        var now = DateTime.UtcNow;
        return new UserAccount { Id = ids.NewId(), Username = username, NormalizedUsername = username.ToUpperInvariant(),
            DisplayName = string.IsNullOrWhiteSpace(displayName) ? username : displayName.Trim(), Role = role,
            Enabled = enabled, CreatedAtUtc = now, UpdatedAtUtc = now };
    }

    private static string? ValidateUser(string? username, string? password, string? displayName, string? role, bool requirePassword)
    {
        if (!UsernamePattern.IsMatch((username ?? "").Trim())) return "用户名支持 1～80 位字母、数字、下划线、短横线、点和 @。";
        if (requirePassword && string.IsNullOrEmpty(password)) return "请输入密码。";
        if (password?.Length > 256) return "密码不能超过 256 个字符。";
        if (displayName?.Length > 100) return "显示名称不能超过 100 个字符。";
        if (role is not ("admin" or "viewer")) return "角色仅支持 admin 或 viewer。";
        return null;
    }

    private static ApiResult<CurrentUser> InvalidLogin() => ApiResult<CurrentUser>.Fail("UNAUTHORIZED", "用户名或密码错误，或账号已停用。");
    private static CurrentUser ToCurrent(UserAccount user) => new(user.Id, user.Username, user.DisplayName, user.Role);
    private static ManagedUser ToManaged(UserAccount user) => new(user.Id, user.Username, user.DisplayName, user.Role,
        user.Enabled, user.CreatedAtUtc, user.UpdatedAtUtc);
}
