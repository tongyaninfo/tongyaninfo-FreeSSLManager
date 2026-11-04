using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Mcp;

/// <summary>预分配密钥复用客户端授权；无 OAuth 证书也可签发，明文只在创建/轮换内存中出现一次。</summary>
public sealed class McpApiKeyService(AppDbContext db, IIdGenerator ids) : IMcpApiKeyService
{
    public async Task<ApiResult<McpApiKeyView[]>> ListAsync(string clientId, CancellationToken ct)
    {
        var client = await FindClientAsync(clientId, ct);
        if (client is null) return Fail<McpApiKeyView[]>("NOT_FOUND", "客户端不存在。");
        var rows = await db.McpApiKeys.AsNoTracking().Where(x => x.ClientId == client.ClientId)
            .OrderByDescending(x => x.CreatedAtUtc).ToArrayAsync(ct);
        return ApiResult<McpApiKeyView[]>.Ok(rows.Select(View).ToArray());
    }

    public async Task<ApiResult<McpApiKeyCreated>> CreateAsync(string clientId, McpApiKeyInput input, CancellationToken ct)
    {
        if (InvalidInput(input)) return Fail<McpApiKeyCreated>("VALIDATION", "请输入不超过 100 字的密钥名称和晚于当前时间的有效期。");
        var client = await FindClientAsync(clientId, ct);
        if (client is null) return Fail<McpApiKeyCreated>("NOT_FOUND", "客户端不存在。");
        if (!await db.Users.AsNoTracking().AnyAsync(x => x.Id == client.BoundUserId && x.Enabled, ct))
            return Fail<McpApiKeyCreated>("VALIDATION", "请先为客户端绑定有效用户。");
        if (client.ExpiresAtUtc is { } clientExpiry && (input.ExpiresAtUtc is null || input.ExpiresAtUtc > clientExpiry))
            return Fail<McpApiKeyCreated>("VALIDATION", "密钥有效期不能晚于所属客户端。");
        if (await db.McpApiKeys.CountAsync(x => x.ClientId == client.ClientId && x.RevokedAtUtc == null, ct) >= 100)
            return Fail<McpApiKeyCreated>("VALIDATION", "单客户端最多保留 100 个未撤销密钥，请先撤销不再使用的密钥。");
        var (row, secret) = NewKey(client.ClientId, input.Name.Trim(), input.ExpiresAtUtc);
        db.McpApiKeys.Add(row); await db.SaveChangesAsync(ct);
        return ApiResult<McpApiKeyCreated>.Ok(new(View(row), secret));
    }

    public async Task<ApiResult<McpApiKeyView>> SetStatusAsync(string id, McpStatusInput input, CancellationToken ct)
    {
        var row = await db.McpApiKeys.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return Fail<McpApiKeyView>("NOT_FOUND", "密钥不存在。");
        if (input.ConfigRevision != row.ConfigRevision) return Fail<McpApiKeyView>("CONFLICT", "密钥已变化，请刷新。");
        if (row.RevokedAtUtc is not null) return Fail<McpApiKeyView>("KEY_REVOKED", "已撤销的密钥不能重新启用，请创建新密钥。");
        if (input.Enabled && row.ExpiresAtUtc <= DateTime.UtcNow) return Fail<McpApiKeyView>("KEY_EXPIRED", "密钥已过期，请创建新密钥。");
        row.Enabled = input.Enabled; row.UpdatedAtUtc = DateTime.UtcNow; row.ConfigRevision++;
        try { await db.SaveChangesAsync(ct); return ApiResult<McpApiKeyView>.Ok(View(row)); }
        catch (DbUpdateConcurrencyException) { db.ChangeTracker.Clear(); return Fail<McpApiKeyView>("CONFLICT", "密钥已被其他请求修改，请刷新。"); }
    }

    public async Task<ApiResult<McpApiKeyCreated>> RotateAsync(string id, CancellationToken ct, int? configRevision = null)
    {
        var row = await db.McpApiKeys.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return Fail<McpApiKeyCreated>("NOT_FOUND", "密钥不存在。");
        if (configRevision != row.ConfigRevision) return Fail<McpApiKeyCreated>("CONFLICT", "密钥已变化，请刷新。");
        if (row.RevokedAtUtc is not null || row.ExpiresAtUtc <= DateTime.UtcNow)
            return Fail<McpApiKeyCreated>("KEY_REVOKED", "已撤销或过期的密钥不能轮换，请创建新密钥。");
        // 新 ID 确保旧操作仍绑定已撤销凭据，换发后不会借用新密钥继续后台写入。
        var (replacement, secret) = NewKey(row.ClientId, row.Name, row.ExpiresAtUtc);
        replacement.Enabled = row.Enabled;
        row.Enabled = false; row.RevokedAtUtc = row.UpdatedAtUtc = DateTime.UtcNow; row.ConfigRevision++;
        db.McpApiKeys.Add(replacement);
        try { await db.SaveChangesAsync(ct); return ApiResult<McpApiKeyCreated>.Ok(new(View(replacement), secret)); }
        catch (DbUpdateConcurrencyException) { db.ChangeTracker.Clear(); return Fail<McpApiKeyCreated>("CONFLICT", "密钥已被其他请求修改，请刷新。"); }
    }

    public async Task<ApiResult<McpApiKeyView>> RevokeAsync(string id, CancellationToken ct, int? configRevision = null)
    {
        var row = await db.McpApiKeys.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return Fail<McpApiKeyView>("NOT_FOUND", "密钥不存在。");
        if (configRevision != row.ConfigRevision) return Fail<McpApiKeyView>("CONFLICT", "密钥已变化，请刷新。");
        row.Enabled = false; row.RevokedAtUtc ??= DateTime.UtcNow; row.UpdatedAtUtc = DateTime.UtcNow; row.ConfigRevision++;
        try { await db.SaveChangesAsync(ct); return ApiResult<McpApiKeyView>.Ok(View(row)); }
        catch (DbUpdateConcurrencyException) { db.ChangeTracker.Clear(); return Fail<McpApiKeyView>("CONFLICT", "密钥已被其他请求修改，请刷新。"); }
    }

    public async Task<McpApiKey?> ValidateAsync(string secret, CancellationToken ct)
    {
        if (secret.Length != 86 || !secret.StartsWith("sslm_", StringComparison.Ordinal) || secret[21] != '_') return null;
        var prefix = secret[..21];
        var row = await db.McpApiKeys.AsNoTracking().SingleOrDefaultAsync(x => x.Prefix == prefix, ct);
        if (row is null || !row.Enabled || row.RevokedAtUtc is not null || row.ExpiresAtUtc <= DateTime.UtcNow) return null;
        var expected = Encoding.ASCII.GetBytes(row.SecretHash);
        var actual = Encoding.ASCII.GetBytes(Hash(secret));
        return CryptographicOperations.FixedTimeEquals(expected, actual) ? row : null;
    }

    private Task<McpClient?> FindClientAsync(string id, CancellationToken ct) => db.McpClients.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
    private static bool InvalidInput(McpApiKeyInput input) => string.IsNullOrWhiteSpace(input.Name) || input.Name.Length > 100
        || input.Name.Any(char.IsControl) || input.ExpiresAtUtc <= DateTime.UtcNow;
    private (McpApiKey Key, string Secret) NewKey(string clientId, string name, DateTime? expiry)
    {
        var prefix = "sslm_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
        var secret = prefix + "_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        var now = DateTime.UtcNow;
        return (new() { Id = ids.NewId(), ClientId = clientId, Name = name, Prefix = prefix, SecretHash = Hash(secret),
            ExpiresAtUtc = expiry, CreatedAtUtc = now, UpdatedAtUtc = now }, secret);
    }
    internal static McpApiKeyView View(McpApiKey row) => new(row.Id, row.ClientId, row.Name, row.Prefix, row.Enabled,
        row.ExpiresAtUtc, row.CreatedAtUtc, row.UpdatedAtUtc, row.LastUsedAtUtc, row.RevokedAtUtc, row.ConfigRevision);
    private static string Hash(string secret) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
    private static ApiResult<T> Fail<T>(string code, string message) => ApiResult<T>.Fail(code, message);
}
