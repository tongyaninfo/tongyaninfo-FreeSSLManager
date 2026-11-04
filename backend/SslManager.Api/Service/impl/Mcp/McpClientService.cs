using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Data;
using SslManager.Api.Models.Mcp;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace SslManager.Api.Service.impl.Mcp;

/// <summary>客户端及 OAuth 注册同事务保存，秘密只在显式创建或轮换时返回一次。</summary>
public sealed class McpClientService(AppDbContext db, IOpenIddictApplicationManager applications, IIdGenerator ids) : IMcpClientService
{
    public async Task<ApiResult<PageResult<McpClientView>>> ListAsync(int page, int pageSize, CancellationToken ct, string? search = null)
    {
        if (page < 1 || pageSize is < 1 or > 100) return Fail<PageResult<McpClientView>>("VALIDATION", "分页参数无效。");
        var query = db.McpClients.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search)) query = query.Where(x => x.Name.Contains(search) || x.ClientId.Contains(search));
        var count = await query.CountAsync(ct);
        var rows = await query.OrderByDescending(x => x.CreatedAtUtc).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return ApiResult<PageResult<McpClientView>>.Ok(new(rows.Select(View).ToArray(), count, page, pageSize));
    }
    public async Task<ApiResult<McpClientCreated>> CreateAsync(McpClientInput input, CancellationToken ct)
    {
        var error = await ValidateAsync(input, ct);
        if (error is not null) return Fail<McpClientCreated>("VALIDATION", error);
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var clientId = "ssl_" + ids.NewId();
        var secret = input.ClientType == "confidential" ? Secret() : null;
        var descriptor = Descriptor(clientId, input, secret);
        await AddResourceAsync(descriptor, ct);
        var application = await applications.CreateAsync(descriptor, ct);
        var now = DateTime.UtcNow;
        var row = new McpClient { Id = ids.NewId(), OAuthApplicationId = (await applications.GetIdAsync(application, ct))!,
            ClientId = clientId, CreatedAtUtc = now, UpdatedAtUtc = now };
        Apply(row, input); db.McpClients.Add(row);
        await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
        return ApiResult<McpClientCreated>.Ok(new(View(row), secret));
    }
    public async Task<ApiResult<McpClientView>> UpdateAsync(string id, McpClientInput input, CancellationToken ct)
    {
        var error = await ValidateAsync(input, ct);
        if (error is not null) return Fail<McpClientView>("VALIDATION", error);
        var row = await db.McpClients.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return Fail<McpClientView>("NOT_FOUND", "客户端不存在。");
        if (input.ConfigRevision != row.ConfigRevision) return Fail<McpClientView>("CONFLICT", "客户端已变化，请刷新。");
        if (row.ClientType != input.ClientType) return Fail<McpClientView>("VALIDATION", "客户端公开/机密类型创建后不可变，请创建另一个客户端。");
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        var application = await applications.FindByIdAsync(row.OAuthApplicationId, ct);
        if (application is null) return Fail<McpClientView>("NOT_FOUND", "OAuth 客户端不存在。");
        var descriptor = new OpenIddictApplicationDescriptor();
        await applications.PopulateAsync(descriptor, application, ct);
        var replacement = Descriptor(row.ClientId, input, null);
        await AddResourceAsync(replacement, ct);
        descriptor.DisplayName = replacement.DisplayName; descriptor.RedirectUris.Clear(); descriptor.RedirectUris.UnionWith(replacement.RedirectUris);
        descriptor.Permissions.Clear(); descriptor.Permissions.UnionWith(replacement.Permissions);
        await applications.UpdateAsync(application, descriptor, ct);
        Apply(row, input); row.ConfigRevision++; row.UpdatedAtUtc = DateTime.UtcNow;
        await RevokeEntriesAsync(row.OAuthApplicationId, ct);
        await RevokeApiKeysAsync(row.ClientId, ct);
        await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct);
        return ApiResult<McpClientView>.Ok(View(row));
    }
    public async Task<ApiResult<McpClientView>> SetStatusAsync(string id, McpStatusInput input, CancellationToken ct)
    {
        var row = await db.McpClients.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return Fail<McpClientView>("NOT_FOUND", "客户端不存在。");
        if (input.ConfigRevision.HasValue && input.ConfigRevision != row.ConfigRevision) return Fail<McpClientView>("CONFLICT", "客户端已变化。");
        if (input.Enabled)
        {
            var validation = await ValidateAsync(new()
            {
                Name = row.Name, ClientType = row.ClientType, GrantType = row.GrantType, BoundUserId = row.BoundUserId,
                Scopes = McpConfigurationService.Strings(row.ScopesJson), RedirectUris = McpConfigurationService.Strings(row.RedirectUrisJson),
                ExpiresAtUtc = row.ExpiresAtUtc
            }, ct);
            if (validation is not null) return Fail<McpClientView>("VALIDATION", validation);
            var application = await applications.FindByIdAsync(row.OAuthApplicationId, ct);
            if (application is null) return Fail<McpClientView>("NOT_FOUND", "OAuth 客户端不存在。");
            var descriptor = new OpenIddictApplicationDescriptor(); await applications.PopulateAsync(descriptor, application, ct);
            await AddResourceAsync(descriptor, ct); await applications.UpdateAsync(application, descriptor, ct);
        }
        row.Enabled = input.Enabled; row.ConfigRevision++; row.UpdatedAtUtc = DateTime.UtcNow;
        if (!input.Enabled) await RevokeEntriesAsync(row.OAuthApplicationId, ct);
        await db.SaveChangesAsync(ct); return ApiResult<McpClientView>.Ok(View(row));
    }
    public async Task<ApiResult<McpSecretView>> RotateSecretAsync(string id, CancellationToken ct)
    {
        var row = await db.McpClients.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return Fail<McpSecretView>("NOT_FOUND", "客户端不存在。");
        if (row.ClientType != "confidential") return Fail<McpSecretView>("VALIDATION", "Public 客户端没有客户端秘密。");
        var application = await applications.FindByIdAsync(row.OAuthApplicationId, ct);
        if (application is null) return Fail<McpSecretView>("NOT_FOUND", "OAuth 客户端不存在。");
        var secret = Secret(); await applications.UpdateAsync(application, secret, ct);
        row.ConfigRevision++; row.UpdatedAtUtc = DateTime.UtcNow;
        await RevokeEntriesAsync(row.OAuthApplicationId, ct); await db.SaveChangesAsync(ct);
        return ApiResult<McpSecretView>.Ok(new(row.ClientId, secret));
    }
    public async Task<ApiResult<bool>> RevokeAsync(string id, CancellationToken ct)
    {
        var row = await db.McpClients.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return Fail<bool>("NOT_FOUND", "客户端不存在。");
        await RevokeEntriesAsync(row.OAuthApplicationId, ct); row.ConfigRevision++; row.UpdatedAtUtc = DateTime.UtcNow;
        await RevokeApiKeysAsync(row.ClientId, ct);
        await db.SaveChangesAsync(ct); return ApiResult<bool>.Ok(true);
    }
    public async Task<ApiResult<McpAllowRulesView>> GetRulesAsync(string id, CancellationToken ct)
    {
        var row = await db.McpClients.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return Fail<McpAllowRulesView>("NOT_FOUND", "客户端不存在。");
        var rules = await db.McpAllowRules.AsNoTracking().Where(x => x.ClientId == row.ClientId).OrderBy(x => x.Id).ToListAsync(ct);
        return ApiResult<McpAllowRulesView>.Ok(new(rules.Select(Rule).ToArray(), row.ConfigRevision));
    }
    public async Task<ApiResult<McpAllowRulesView>> SaveRulesAsync(string id, McpAllowRulesInput input, CancellationToken ct)
    {
        if (input.Rules is null || input.Rules.Count > 100) return Fail<McpAllowRulesView>("VALIDATION", "规则数量不能超过 100。");
        var row = await db.McpClients.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return Fail<McpAllowRulesView>("NOT_FOUND", "客户端不存在。");
        if (row.ConfigRevision != input.ConfigRevision) return Fail<McpAllowRulesView>("CONFLICT", "白名单已变化，请刷新。");
        foreach (var rule in input.Rules)
        {
            if (rule.ToolNames is null || rule.AccountIds is null || rule.Domains is null || rule.TargetIds is null || rule.AllowedCidrs is null || rule.Scopes is null
                || rule.ToolNames.Length == 0 || rule.ToolNames.Length > 100 || rule.AccountIds.Length > 200 || rule.Domains.Length > 200 || rule.TargetIds.Length > 200
                || rule.AllowedCidrs.Length > 100 || rule.AllowedCidrs.Any(value => !McpNetwork.ValidCidr(value))
                || rule.ToolNames.Any(value => !McpToolCatalog.All.Any(tool => tool.Name == value))
                || rule.ApprovalMode is not ("Manual" or "Preauthorized") || rule.Scopes.Any(scope => scope is not ("mcp.read" or "mcp.write")))
                return Fail<McpAllowRulesView>("VALIDATION", "白名单工具、资源、来源、scope 或审批方式无效。");
        }
        await using var transaction = await db.Database.BeginTransactionAsync(ct);
        db.McpAllowRules.RemoveRange(await db.McpAllowRules.Where(x => x.ClientId == row.ClientId).ToListAsync(ct));
        foreach (var rule in input.Rules) db.McpAllowRules.Add(new()
        {
            Id = ids.NewId(), ClientId = row.ClientId, ToolNamesJson = JsonSerializer.Serialize(rule.ToolNames.Distinct()),
            AccountIdsJson = JsonSerializer.Serialize(rule.AccountIds.Distinct()), DomainsJson = JsonSerializer.Serialize(rule.Domains.Select(McpNetwork.NormalizeDomain).Distinct()),
            TargetIdsJson = JsonSerializer.Serialize(rule.TargetIds.Distinct()), AllowedCidrsJson = JsonSerializer.Serialize(rule.AllowedCidrs.Distinct()),
            ScopesJson = JsonSerializer.Serialize(rule.Scopes.Distinct()), AllAccounts = rule.AllAccounts, AllDomains = rule.AllDomains,
            AllTargets = rule.AllTargets, ApprovalMode = rule.ApprovalMode, Enabled = rule.Enabled, ExpiresAtUtc = rule.ExpiresAtUtc,
            ConfigRevision = row.ConfigRevision + 1
        });
        row.ConfigRevision++; row.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct); await transaction.CommitAsync(ct); return await GetRulesAsync(id, ct);
    }
    public async Task<ApiResult<McpConnectionProfile>> ProfileAsync(string id, CancellationToken ct)
    {
        var row = await db.McpClients.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return Fail<McpConnectionProfile>("NOT_FOUND", "客户端不存在。");
        var settings = await db.McpSettings.AsNoTracking().SingleOrDefaultAsync(ct);
        var address = settings?.PublicBaseUrl ?? "";
        if (!McpNetwork.ValidBaseUrl(address)) return Fail<McpConnectionProfile>("MCP_NOT_READY", "请先保存有效的公开 HTTPS 基址，再生成连接模板。");
        return ApiResult<McpConnectionProfile>.Ok(new(address + "/mcp", row.ClientId, "streamable-http", row.GrantType,
            McpConfigurationService.Strings(row.ScopesJson), address + "/oauth/mcp/authorize", address + "/oauth/mcp/token",
            settings?.SystemName ?? "Free SSL Manager", settings?.InstanceId ?? ""));
    }
    private async Task<string?> ValidateAsync(McpClientInput input, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(input.Name) || input.Name.Length > 100 || input.Name.Any(char.IsControl)) return "客户端名称无效。";
        if (input.ClientType is not ("public" or "confidential") || input.GrantType is not ("authorization_code" or "client_credentials")
            || input.ClientType == "public" && input.GrantType != "authorization_code") return "客户端类型与授权方式不匹配。";
        if (input.Scopes is null || input.Scopes.Any(scope => scope is not ("mcp.read" or "mcp.write")) || input.RedirectUris is null || input.RedirectUris.Length > 20)
            return "客户端 scope 或回调数量无效。";
        if (input.GrantType == "authorization_code" && input.RedirectUris.Length == 0) return "授权码客户端必须预注册回调地址。";
        if (input.RedirectUris.Any(value => !Uri.TryCreate(value, UriKind.Absolute, out var uri) || !string.IsNullOrEmpty(uri.UserInfo)
            || uri.Fragment != "" || !(uri.Scheme == "https" || uri.Scheme == "http" && uri.IsLoopback))) return "回调仅允许 HTTPS 或本机回环 HTTP 地址。";
        if (input.ExpiresAtUtc <= DateTime.UtcNow) return "客户端有效期必须晚于现在。";
        var user = await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == input.BoundUserId && x.Enabled, ct);
        if (user is null) return "绑定用户不存在或已停用。";
        if (user.Role != "admin" && input.Scopes.Contains("mcp.write")) return "查看者不能取得写入 scope。";
        return null;
    }
    private async Task RevokeEntriesAsync(string applicationId, CancellationToken ct)
    {
        await db.Set<McpOAuthToken>().Where(x => x.Application != null && x.Application.Id == applicationId)
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, Statuses.Revoked), ct);
        await db.Set<McpOAuthAuthorization>().Where(x => x.Application != null && x.Application.Id == applicationId)
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.Status, Statuses.Revoked), ct);
    }
    private Task<int> RevokeApiKeysAsync(string clientId, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        return db.McpApiKeys.Where(x => x.ClientId == clientId && x.RevokedAtUtc == null)
            .ExecuteUpdateAsync(update => update.SetProperty(x => x.Enabled, false).SetProperty(x => x.RevokedAtUtc, now)
                .SetProperty(x => x.UpdatedAtUtc, now).SetProperty(x => x.ConfigRevision, x => x.ConfigRevision + 1), ct);
    }
    private async Task AddResourceAsync(OpenIddictApplicationDescriptor descriptor, CancellationToken ct)
    {
        var address = await db.McpSettings.AsNoTracking().Select(x => x.PublicBaseUrl).SingleOrDefaultAsync(ct);
        if (address is not null && McpNetwork.ValidBaseUrl(address)) descriptor.AddResourcePermissions(address + "/mcp");
    }
    private static OpenIddictApplicationDescriptor Descriptor(string id, McpClientInput input, string? secret)
    {
        var descriptor = new OpenIddictApplicationDescriptor { ClientId = id, ClientSecret = secret, DisplayName = input.Name.Trim(),
            ClientType = input.ClientType, ConsentType = ConsentTypes.Explicit };
        descriptor.Permissions.UnionWith([Permissions.Endpoints.Token, Permissions.Endpoints.Revocation]);
        if (input.GrantType == "authorization_code")
        {
            descriptor.Permissions.UnionWith([Permissions.Endpoints.Authorization, Permissions.GrantTypes.AuthorizationCode,
                Permissions.GrantTypes.RefreshToken, Permissions.ResponseTypes.Code]);
            descriptor.Requirements.Add(Requirements.Features.ProofKeyForCodeExchange);
        }
        else descriptor.Permissions.Add(Permissions.GrantTypes.ClientCredentials);
        foreach (var scope in input.Scopes) descriptor.Permissions.Add(Permissions.Prefixes.Scope + scope);
        foreach (var redirect in input.RedirectUris) descriptor.RedirectUris.Add(new(redirect));
        return descriptor;
    }
    private static void Apply(McpClient row, McpClientInput input)
    {
        row.Name = input.Name.Trim(); row.ClientType = input.ClientType; row.GrantType = input.GrantType;
        row.BoundUserId = input.BoundUserId; row.ScopesJson = JsonSerializer.Serialize(input.Scopes.Distinct());
        row.RedirectUrisJson = JsonSerializer.Serialize(input.RedirectUris.Distinct()); row.ExpiresAtUtc = input.ExpiresAtUtc;
    }
    internal static McpClientView View(McpClient row) => new(row.Id, row.ClientId, row.Name, row.ClientType, row.GrantType,
        row.BoundUserId, McpConfigurationService.Strings(row.ScopesJson), McpConfigurationService.Strings(row.RedirectUrisJson), row.Enabled,
        row.ExpiresAtUtc, row.ConfigRevision, row.CreatedAtUtc, row.UpdatedAtUtc, row.LastUsedAtUtc);
    internal static McpAllowRuleInput Rule(McpAllowRule row) => new()
    {
        ToolNames = McpConfigurationService.Strings(row.ToolNamesJson), AccountIds = McpConfigurationService.Strings(row.AccountIdsJson),
        Domains = McpConfigurationService.Strings(row.DomainsJson), TargetIds = McpConfigurationService.Strings(row.TargetIdsJson),
        AllowedCidrs = McpConfigurationService.Strings(row.AllowedCidrsJson), Scopes = McpConfigurationService.Strings(row.ScopesJson),
        AllAccounts = row.AllAccounts, AllDomains = row.AllDomains, AllTargets = row.AllTargets,
        ApprovalMode = row.ApprovalMode, Enabled = row.Enabled, ExpiresAtUtc = row.ExpiresAtUtc
    };
    private static string Secret() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));
    private static ApiResult<T> Fail<T>(string code, string message) => ApiResult<T>.Fail(code, message);
}
