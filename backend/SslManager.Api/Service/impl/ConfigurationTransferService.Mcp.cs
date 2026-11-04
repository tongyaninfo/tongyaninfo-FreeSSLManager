using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Api.Service.impl;

public sealed partial class ConfigurationTransferService
{
    private static void ExportMcpConfiguration(ConfigurationPackage package, ConfigurationSnapshot snapshot)
    {
        if (snapshot.McpSettings is { } settings)
            package.McpSettings = new()
            {
                Enabled = false, PublicBaseUrl = settings.PublicBaseUrl, Mode = settings.Mode,
                AllowedCidrs = McpStrings(settings.AllowedCidrsJson), AllowedOrigins = McpStrings(settings.AllowedOriginsJson),
                AllowedTools = McpStrings(settings.AllowedToolsJson), SystemName = settings.SystemName, RateLimitPerMinute = settings.RateLimitPerMinute,
                MaxConcurrentCalls = settings.MaxConcurrentCalls, LogRetentionDays = settings.LogRetentionDays
            };
        var index = 0;
        foreach (var client in snapshot.McpClients)
        {
            var entry = new McpClientConfiguration
            {
                // 包内引用键与真实业务客户端/OAuth Client ID 无关，不能被当作可登录身份。
                SourceId = "mcp-client-" + ++index,
                Settings = new() { Name = client.Name, ClientType = client.ClientType, GrantType = client.GrantType,
                    Scopes = McpStrings(client.ScopesJson), RedirectUris = McpStrings(client.RedirectUrisJson), ExpiresAtUtc = client.ExpiresAtUtc }
            };
            foreach (var row in snapshot.McpAllowRules.Where(rule => rule.ClientId == client.ClientId))
            {
                var rule = new McpAllowRuleInput
                {
                    ToolNames = McpStrings(row.ToolNamesJson), AccountIds = McpStrings(row.AccountIdsJson), Domains = McpStrings(row.DomainsJson),
                    TargetIds = McpStrings(row.TargetIdsJson), AllowedCidrs = McpStrings(row.AllowedCidrsJson), Scopes = McpStrings(row.ScopesJson),
                    AllAccounts = row.AllAccounts, AllDomains = row.AllDomains, AllTargets = row.AllTargets,
                    ApprovalMode = row.ApprovalMode, ExpiresAtUtc = row.ExpiresAtUtc, Enabled = false
                };
                if (rule.AccountIds.Any(id => snapshot.Accounts.All(account => account.Id != id)) ||
                    rule.TargetIds.Any(id => snapshot.Targets.All(target => target.Id != id)))
                    throw new InvalidOperationException("MCP 规则缺少可移植资源，须先修正引用。");
                entry.AllowRules.Add(rule);
            }
            package.McpClients.Add(entry);
        }
    }

    private async Task ValidateMcpConfigurationAsync(ConfigurationPackage package, string mode, ConfigurationSnapshot snapshot, ImportPlan plan, CancellationToken ct)
    {
        if (package.McpSettings is { } settings)
        {
            var before = plan.Errors.Count;
            if (string.IsNullOrWhiteSpace(settings.SystemName) || settings.SystemName.Trim().Length > 100 || settings.SystemName.Any(char.IsControl))
                plan.Errors.Add(new("mcpSettings.systemName", "系统名称必须为 1 至 100 字且不包含控制字符。"));
            if (settings.Mode is not ("ReadOnly" or "ControlledWrite") || settings.RateLimitPerMinute is < 1 or > 600 ||
                settings.MaxConcurrentCalls is < 1 or > 32 || settings.LogRetentionDays is < 1 or > 365 ||
                settings.PublicBaseUrl is null || settings.PublicBaseUrl.Length > 2048 ||
                settings.PublicBaseUrl.Length > 0 && !McpNetwork.ValidBaseUrl(settings.PublicBaseUrl.Trim().TrimEnd('/')))
                plan.Errors.Add(new("mcpSettings", "MCP 模式、公开 HTTPS 地址、限流、并发或日志期限无效。"));
            if (settings.AllowedCidrs is null || settings.AllowedOrigins is null || settings.AllowedTools is null ||
                settings.AllowedCidrs.Length > 100 || settings.AllowedOrigins.Length > 50 || settings.AllowedTools.Length > 100 ||
                settings.AllowedCidrs.Any(value => value is null || !McpNetwork.ValidCidr(value)) ||
                settings.AllowedOrigins.Any(value => value is null || !McpNetwork.ValidOrigin(value)) ||
                settings.AllowedTools.Any(value => value is null || !McpToolCatalog.All.Any(tool => tool.Name == value)))
                plan.Errors.Add(new("mcpSettings", "MCP 来源、Origin 或工具白名单无效。"));
            var action = plan.Errors.Count > before ? "Invalid" : snapshot.McpSettings is null ? "Create" : mode == "CreateOnly" ? "Conflict" : "Update";
            if (action == "Conflict") plan.Errors.Add(new("mcpSettings", "当前实例已有 MCP 设置，请使用更新模式。"));
            plan.Items.Add(new("McpSettings", "default", "MCP 服务（导入后关闭，公开地址待重新配置）", action));
        }
        else if (package.McpClients.Count > 0)
            plan.Items.Add(new("McpSettings", "default", "MCP 服务（导入客户端时强制关闭并清空公开地址）", snapshot.McpSettings is null ? "Create" : "Update"));

        var keys = package.McpClients.Where(item => item?.Settings is not null).Select(item => NameKey(item.Settings.Name)).ToArray();
        var sourceIds = package.McpClients.Where(item => item is not null).Select(item => item.SourceId).ToArray();
        for (var index = 0; index < package.McpClients.Count; index++)
        {
            var item = package.McpClients[index];
            var path = $"mcpClients[{index}]";
            if (item?.Settings is null || item.AllowRules is null) { InvalidItem(plan, "McpClient", path); continue; }
            var before = plan.Errors.Count;
            ValidateSourceId(item.SourceId, sourceIds, path, plan);
            ValidateName(item.Settings.Name, path, plan);
            if (mcpApplications is null) plan.Errors.Add(new(path, "当前实例未配置 MCP OAuth 持久存储，不能导入客户端。"));
            var input = item.Settings;
            if (input.ClientType is not ("public" or "confidential") || input.GrantType is not ("authorization_code" or "client_credentials") ||
                input.ClientType == "public" && input.GrantType != "authorization_code" || input.Scopes is null || input.Scopes.Length > 20 ||
                input.Scopes.Any(scope => scope is not ("mcp.read" or "mcp.write")) || input.RedirectUris is null || input.RedirectUris.Length > 20 ||
                input.GrantType == "authorization_code" && input.RedirectUris.Length == 0 ||
                input.RedirectUris.Any(value => value is null || value.Length > 2048 || !Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
                    !string.IsNullOrEmpty(uri.UserInfo) || uri.Fragment != "" || !(uri.Scheme == "https" || uri.Scheme == "http" && uri.IsLoopback)))
                plan.Errors.Add(new(path + ".settings", "MCP 客户端类型、授权流程、scope 或回调地址无效。"));
            if (item.AllowRules.Count > 100) plan.Errors.Add(new(path + ".allowRules", "单客户端规则不得超过 100 条。"));
            for (var ruleIndex = 0; ruleIndex < item.AllowRules.Count; ruleIndex++)
            {
                var rule = item.AllowRules[ruleIndex];
                var rulePath = path + $".allowRules[{ruleIndex}]";
                if (rule is null || rule.ToolNames is null || rule.AccountIds is null || rule.Domains is null || rule.TargetIds is null ||
                    rule.AllowedCidrs is null || rule.Scopes is null || rule.ToolNames.Length is < 1 or > 100 || rule.AccountIds.Length > 200 ||
                    rule.Domains.Length > 200 || rule.TargetIds.Length > 200 || rule.AllowedCidrs.Length > 100 || rule.Scopes.Length > 20 ||
                    rule.ToolNames.Any(value => value is null || !McpToolCatalog.All.Any(tool => tool.Name == value)) ||
                    rule.AllowedCidrs.Any(value => value is null || !McpNetwork.ValidCidr(value)) || rule.Scopes.Any(scope => scope is not ("mcp.read" or "mcp.write")) ||
                    rule.Domains.Any(domain => domain is null || !ValidMcpDomain(domain)) || rule.ApprovalMode is not ("Manual" or "Preauthorized"))
                { plan.Errors.Add(new(rulePath, "MCP 规则的工具、资源、来源、scope 或审批模式无效。")); continue; }
                if (rule.AccountIds.Any(id => id is null || !plan.Accounts.ContainsKey(id)))
                    plan.Errors.Add(new(rulePath + ".accountIds", "规则引用的云账号不在配置包中或包内引用键无效。"));
                if (rule.TargetIds.Any(id => id is null || !plan.Targets.ContainsKey(id)))
                    plan.Errors.Add(new(rulePath + ".targetIds", "规则引用的部署目标不在配置包中或包内引用键无效。"));
            }
            var matches = snapshot.McpClients.Where(client => NameKey(client.Name) == NameKey(input.Name)).Select(client => client.Id).ToArray();
            Register(plan, "McpClient", item.SourceId, input.Name, path, NameKey(input.Name), keys, matches, mode, before, plan.McpClients);
        }
        var updates = plan.McpClients.Values.Where(value => value is not null).ToArray();
        var clientIds = snapshot.McpClients.Where(client => updates.Contains(client.Id)).Select(client => client.ClientId).ToArray();
        if (clientIds.Length > 0 && await db.McpOperations.AsNoTracking().AnyAsync(operation => clientIds.Contains(operation.ClientId) &&
            (operation.Status == "Queued" || operation.Status == "Dispatching" || operation.Status == "Executing" || operation.Status == "Waiting" ||
                operation.Status == "Unknown" || operation.Status == "Preparing" || (operation.Status == "Prepared" || operation.Status == "Approved") && operation.ApprovalExpiresAtUtc > DateTime.UtcNow), ct))
            plan.Errors.Add(new("mcpClients", "待更新客户端存在待审批、活跃或结果未知的 MCP 操作，请先核对处理。"));
    }

    private async Task ApplyMcpConfigurationAsync(ConfigurationPackage package, ImportPlan plan,
        IReadOnlyDictionary<string, string> accountIds, IReadOnlyDictionary<string, string> targetIds, DateTime now, CancellationToken ct)
    {
        if (package.McpSettings is null && package.McpClients.Count == 0) return;
        var settings = await db.McpSettings.SingleOrDefaultAsync(ct);
        if (settings is null) { settings = new(); db.McpSettings.Add(settings); }
        else settings.ConfigRevision++;
        settings.Enabled = false;
        settings.PublicBaseUrl = ""; // 源实例地址不能自动成为目标实例的信任边界，管理员须重新填写。
        if (settings.InstanceId.Length == 0) settings.InstanceId = ids.NewId();
        settings.UpdatedAtUtc = now;
        if (package.McpSettings is { } input)
        {
            settings.SystemName = input.SystemName.Trim(); // 名称可迁移，目标实例 ID 必须保留或独立生成。
            settings.Mode = input.Mode; settings.AllowedCidrsJson = JsonSerializer.Serialize(input.AllowedCidrs.Distinct(), Json);
            settings.AllowedOriginsJson = JsonSerializer.Serialize(input.AllowedOrigins.Distinct(), Json);
            settings.AllowedToolsJson = JsonSerializer.Serialize(input.AllowedTools.Distinct(), Json);
            settings.RateLimitPerMinute = input.RateLimitPerMinute; settings.MaxConcurrentCalls = input.MaxConcurrentCalls; settings.LogRetentionDays = input.LogRetentionDays;
        }
        foreach (var item in package.McpClients)
        {
            var existing = plan.McpClients[item.SourceId];
            var row = existing is null ? new McpClient { Id = ids.NewId(), CreatedAtUtc = now }
                : await db.McpClients.SingleAsync(client => client.Id == existing, ct);
            if (existing is not null)
            {
                // 更新只撤销旧身份，保留旧 OAuth 应用和历史，不把源实例身份套在本地授权之上。
                var applicationId = row.OAuthApplicationId;
                await db.McpApiKeys.Where(key => key.ClientId == row.ClientId && key.RevokedAtUtc == null)
                    .ExecuteUpdateAsync(update => update.SetProperty(key => key.Enabled, false).SetProperty(key => key.RevokedAtUtc, now)
                        .SetProperty(key => key.UpdatedAtUtc, now).SetProperty(key => key.ConfigRevision, key => key.ConfigRevision + 1), ct);
                await db.Set<McpOAuthToken>().Where(token => token.Application != null && token.Application.Id == applicationId)
                    .ExecuteUpdateAsync(update => update.SetProperty(token => token.Status, OpenIddictConstants.Statuses.Revoked), ct);
                await db.Set<McpOAuthAuthorization>().Where(authorization => authorization.Application != null && authorization.Application.Id == applicationId)
                    .ExecuteUpdateAsync(update => update.SetProperty(authorization => authorization.Status, OpenIddictConstants.Statuses.Revoked), ct);
                db.McpAllowRules.RemoveRange(await db.McpAllowRules.Where(rule => rule.ClientId == row.ClientId).ToListAsync(ct));
            }
            var clientId = "ssl_" + ids.NewId();
            // 机密客户端用随机占位秘密交给框架哈希，明文只在此调用内存中，既不导出也不返回。
            var descriptor = new OpenIddictApplicationDescriptor { ClientId = clientId, DisplayName = item.Settings.Name.Trim(),
                ClientType = item.Settings.ClientType, ConsentType = OpenIddictConstants.ConsentTypes.Explicit,
                ClientSecret = item.Settings.ClientType == "confidential" ? Convert.ToBase64String(RandomNumberGenerator.GetBytes(48)) : null };
            var application = await mcpApplications!.CreateAsync(descriptor, ct);
            row.OAuthApplicationId = (await mcpApplications.GetIdAsync(application, ct))!;
            row.ClientId = clientId; row.Name = item.Settings.Name.Trim(); row.ClientType = item.Settings.ClientType; row.GrantType = item.Settings.GrantType;
            row.BoundUserId = ""; row.Enabled = false; row.LastUsedAtUtc = null;
            row.ScopesJson = JsonSerializer.Serialize(item.Settings.Scopes.Distinct(), Json);
            row.RedirectUrisJson = JsonSerializer.Serialize(item.Settings.RedirectUris.Distinct(), Json);
            row.ExpiresAtUtc = item.Settings.ExpiresAtUtc; row.UpdatedAtUtc = now; row.ConfigRevision = existing is null ? 1 : row.ConfigRevision + 1;
            if (existing is null) db.McpClients.Add(row);
            foreach (var rule in item.AllowRules)
                db.McpAllowRules.Add(new()
                {
                    Id = ids.NewId(), ClientId = clientId, Enabled = false, ToolNamesJson = JsonSerializer.Serialize(rule.ToolNames.Distinct(), Json),
                    AccountIdsJson = JsonSerializer.Serialize(rule.AccountIds.Select(id => accountIds[id]).Distinct(), Json),
                    TargetIdsJson = JsonSerializer.Serialize(rule.TargetIds.Select(id => targetIds[id]).Distinct(), Json),
                    DomainsJson = JsonSerializer.Serialize(rule.Domains.Select(McpNetwork.NormalizeDomain).Distinct(), Json),
                    AllowedCidrsJson = JsonSerializer.Serialize(rule.AllowedCidrs.Distinct(), Json), ScopesJson = JsonSerializer.Serialize(rule.Scopes.Distinct(), Json),
                    AllAccounts = rule.AllAccounts, AllDomains = rule.AllDomains, AllTargets = rule.AllTargets,
                    ApprovalMode = rule.ApprovalMode, ExpiresAtUtc = rule.ExpiresAtUtc, ConfigRevision = row.ConfigRevision
                });
        }
    }

    private static bool ValidMcpDomain(string domain)
    {
        domain = McpNetwork.NormalizeDomain(domain);
        return domain.Length <= 253 && CertificateManagementService.IsValidDomain(domain.StartsWith("*.", StringComparison.Ordinal) ? domain[2..] : domain);
    }
    private static string[] McpStrings(string json) => JsonSerializer.Deserialize<string[]>(json, Json) is { } values && values.All(value => value is not null)
        ? values : throw new JsonException();
}
