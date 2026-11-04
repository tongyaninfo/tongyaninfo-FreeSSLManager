using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service.impl.Deployment;

namespace SslManager.Api.Service.impl.Mcp;

public sealed partial class McpOperationService
{
    /// <summary>管理类操作只建立不可变来源摘要；账号、目标凭据均由通用业务信封加密保存。</summary>
    private async Task<ApiResult<BusinessSnapshot>> BuildAdministrationSnapshotAsync(McpCallerContext caller, string tool, JsonElement input, CancellationToken ct)
    {
        if (tool.StartsWith("ssl_accounts_", StringComparison.Ordinal))
        {
            if (businessAccounts is null) return BusinessSnapshotDenied("MCP_SERVICE_UNAVAILABLE");
            var accountId = BusinessText(input, "accountId");
            var existing = tool == "ssl_accounts_create" ? null : await db.CloudAccounts.AsNoTracking().SingleOrDefaultAsync(x => x.Id == accountId, ct);
            if (tool != "ssl_accounts_create" && existing is null) return BusinessSnapshotDenied();
            if (tool is "ssl_accounts_create" or "ssl_accounts_update")
            {
                var account = AdministrationInput<CloudAccountInput>(input, "account");
                if (account is null || existing is not null && existing.Provider != account.Provider)
                    return BusinessSnapshotDenied("VALIDATION");
                if (tool == "ssl_accounts_create" && !await AdministrationBroadAsync(caller, tool, new("__new_account__"), accounts: true, ct))
                    return BusinessSnapshotDenied("FORBIDDEN");
                return ApiResult<BusinessSnapshot>.Ok(new([new(existing?.Id ?? "__new_account__")],
                    existing is null ? BusinessHash(new { create = true }) : BusinessHash(existing), existing?.Id ?? "",
                    JsonSerializer.Serialize(new { action = tool, accountId = existing?.Id ?? "", provider = account.Provider,
                        account.Enabled, account.UseForCertificates, account.UseForDns, credentialsProvided = account.AccessKeyId.Length > 0 || account.AccessKeySecret.Length > 0,
                        account.AutoSyncEnabled, account.AutoSyncIntervalUnit, account.AutoSyncIntervalValue,
                        acmeRegistration = "NotRequested" }, Json)));
            }
            if (tool != "ssl_accounts_test" || BusinessText(input, "testKind") is not ("Certificate" or "Dns"))
                return BusinessSnapshotDenied("VALIDATION");
            return ApiResult<BusinessSnapshot>.Ok(new([new(accountId)], BusinessHash(existing!), accountId,
                JsonSerializer.Serialize(new { action = tool, accountId, testKind = BusinessText(input, "testKind"), externalMutation = false }, Json)));
        }

        if (tool.StartsWith("ssl_deployment_targets_", StringComparison.Ordinal))
        {
            var targetId = BusinessText(input, "targetId");
            var existing = tool == "ssl_deployment_targets_create" ? null : await db.DeploymentTargets.AsNoTracking().SingleOrDefaultAsync(x => x.Id == targetId, ct);
            if (tool != "ssl_deployment_targets_create" && existing is null) return BusinessSnapshotDenied();
            DeploymentTargetConfiguration? previous = null;
            if (existing is not null)
            {
                try { previous = JsonSerializer.Deserialize<DeploymentTargetConfiguration>(existing.ConfigurationJson, Json); }
                catch (JsonException) { return BusinessSnapshotDenied("TARGET_INVALID"); }
                if (previous is null) return BusinessSnapshotDenied("TARGET_INVALID");
            }
            var resources = new List<McpResourceScope> { new("", NormalizeDomain(previous?.SourceDomain), existing?.Id ?? "__new_target__") };
            if (tool is "ssl_deployment_targets_create" or "ssl_deployment_targets_update")
            {
                var target = AdministrationInput<DeploymentTargetInput>(input, "target");
                if (target?.Configuration is null || !AdministrationCommandsAllowed(target.Configuration, previous)
                    || existing is not null && (target.ExecutorKey != existing.ExecutorKey || target.ConfigRevision is not null && target.ConfigRevision != existing.ConfigRevision))
                    return BusinessSnapshotDenied("VALIDATION");
                var proposed = new McpResourceScope("", NormalizeDomain(target.Configuration.SourceDomain), existing?.Id ?? "__new_target__");
                resources.Add(proposed);
                if (existing is null && !await AdministrationBroadAsync(caller, tool, proposed, accounts: false, ct))
                    return BusinessSnapshotDenied("FORBIDDEN");
                var destination = AdministrationEndpoint(target.Endpoint, target.Port, target.ExecutorKey);
                return ApiResult<BusinessSnapshot>.Ok(new(resources.Distinct().ToArray(),
                    existing is null ? BusinessHash(new { create = true }) : BusinessHash(existing), existing?.Id ?? "",
                    JsonSerializer.Serialize(new { action = tool, targetId = existing?.Id ?? "", executorKey = target.ExecutorKey,
                        target.Enabled, configRevision = existing?.ConfigRevision ?? 0, sourceDomain = NormalizeDomain(target.Configuration.SourceDomain),
                        previousSourceDomain = NormalizeDomain(previous?.SourceDomain), destinationHost = destination.Host, destinationPort = destination.Port,
                        commands = previous is null ? "None" : "PreserveExisting", credentialsProvided = target.Password.Length > 0 || target.ApiToken.Length > 0 || target.PrivateKey.Length > 0 }, Json)));
            }
            if (tool is not ("ssl_deployment_targets_status" or "ssl_deployment_targets_discover")) return BusinessSnapshotDenied("TOOL_NOT_FOUND");
            if (tool == "ssl_deployment_targets_status" && (!input.TryGetProperty("enabled", out var enabled) || enabled.ValueKind is not (JsonValueKind.True or JsonValueKind.False)))
                return BusinessSnapshotDenied("VALIDATION");
            return ApiResult<BusinessSnapshot>.Ok(new(resources.ToArray(), BusinessHash(existing!), targetId,
                JsonSerializer.Serialize(new { action = tool, targetId, configRevision = existing!.ConfigRevision,
                    enabled = tool == "ssl_deployment_targets_status" ? input.GetProperty("enabled").GetBoolean() : existing.Enabled,
                    externalMutation = false }, Json)));
        }

        if (tool.StartsWith("ssl_deployment_tasks_", StringComparison.Ordinal))
        {
            var taskId = BusinessText(input, "taskId");
            var task = await db.DeploymentTasks.AsNoTracking().SingleOrDefaultAsync(x => x.Id == taskId, ct);
            if (task is null) return BusinessSnapshotDenied();
            var batch = await db.DeploymentBatches.AsNoTracking().SingleOrDefaultAsync(x => x.Id == task.BatchId, ct);
            var certificate = batch is null ? null : await db.Certificates.AsNoTracking().SingleOrDefaultAsync(x => x.Id == batch.CertificateId, ct);
            var target = await db.DeploymentTargets.AsNoTracking().SingleOrDefaultAsync(x => x.Id == task.TargetId, ct);
            if (batch is null || certificate is null || target is null) return BusinessSnapshotDenied();
            if (tool == "ssl_deployment_tasks_cancel" && task.Status is not ("Draft" or "Queued" or "Running" or "Recovering")
                || tool == "ssl_deployment_tasks_resolve" && task.Status != "NeedsAttention"
                || tool == "ssl_deployment_tasks_retry_plan" && (task.Status is not ("Failed" or "Cancelled" or "Resolved") || task.SourceTaskId.Length > 0)
                || tool == "ssl_deployment_tasks_rollback_plan" && (task.Status is not ("Succeeded" or "Failed" or "Resolved") || task.SourceTaskId.Length > 0))
                return BusinessSnapshotDenied("INVALID_STATE");
            if (tool == "ssl_deployment_tasks_resolve" && (string.IsNullOrWhiteSpace(BusinessText(input, "note")) || BusinessText(input, "note").Length > 1000 || BusinessText(input, "note").Any(char.IsControl)))
                return BusinessSnapshotDenied("VALIDATION");
            var scope = new McpResourceScope(certificate.AccountId, NormalizeDomain(CertificateManagementService.PrimaryDomain(certificate.Domain)), target.Id);
            // 取消请求固定任务身份与配置，不绑定正在运行任务的心跳、进度和租约，避免正常推进让审批永远失效。
            var binding = new { task.Id, task.BatchId, task.TargetId, task.SourceTaskId, task.ConfigRevision, task.ResourceKey,
                task.MaterialSnapshotId, task.PlanJson, sourceStatus = tool == "ssl_deployment_tasks_cancel" ? "Cancelable" : task.Status,
                receipt = tool == "ssl_deployment_tasks_cancel" ? "" : task.ReceiptJson,
                target = new { target.Id, target.ConfigRevision, target.Enabled, target.ExecutorKey, target.Endpoint, target.Port,
                    target.AuthenticationMode, target.TlsFingerprint, target.ConfigurationJson },
                certificateId = certificate.Id, certificate.AccountId, certificate.Domain, certificate.Status, certificate.NotAfterUtc };
            return ApiResult<BusinessSnapshot>.Ok(new([scope], BusinessHash(binding), task.Id,
                JsonSerializer.Serialize(new { action = tool, taskId, batchId = task.BatchId, targetId = target.Id,
                    certificateId = certificate.Id, sourceStatus = task.Status, createsDraftOnly = tool.EndsWith("_plan", StringComparison.Ordinal),
                    noteDigest = tool == "ssl_deployment_tasks_resolve" ? BusinessHash(BusinessText(input, "note")) : "" }, Json), certificate.Id));
        }
        return BusinessSnapshotDenied("TOOL_NOT_FOUND");
    }

    private async Task<BusinessExecution> ExecuteAdministrationBusinessAsync(McpOperation operation, string tool, JsonElement input, CancellationToken ct)
    {
        var caller = Caller(operation);
        // 通用门禁之外，创建动作再次要求显式宽范围授权，不能用空资源匹配替代 AllAccounts/AllTargets。
        if (tool == "ssl_accounts_create" && !await AdministrationBroadAsync(caller, tool, new("__new_account__"), true, ct)
            || tool == "ssl_deployment_targets_create" && !await AdministrationBroadAsync(caller, tool,
                new("", NormalizeDomain(AdministrationInput<DeploymentTargetInput>(input, "target")?.Configuration?.SourceDomain), "__new_target__"), false, ct))
            return new(false, "FORBIDDEN", "Blocked");
        var gate = await RecheckBusinessAuthorizationAsync(operation, ct);
        if (!gate.Success) return new(false, AdministrationCode(gate.Code), "Blocked");

        if (tool is "ssl_accounts_create" or "ssl_accounts_update")
        {
            if (businessAccounts is null) return new(false, "MCP_SERVICE_UNAVAILABLE", "Failed");
            var account = AdministrationInput<CloudAccountInput>(input, "account");
            if (account is null) return new(false, "VALIDATION", "Failed");
            var result = tool == "ssl_accounts_create" ? await businessAccounts.CreateAsync(account, ct)
                : await businessAccounts.UpdateAsync(BusinessText(input, "accountId"), account, ct);
            return new(result.Success, AdministrationCode(result.Code), result.Success ? "Succeeded" : "Failed",
                result.Data is null ? null : new { accountId = result.Data.Id, result.Data.Provider, result.Data.Enabled,
                    result.Data.UseForCertificates, result.Data.UseForDns, acmeRegistration = "NotRequested" });
        }
        if (tool == "ssl_accounts_test") return await TestAdministrationAccountAsync(operation, input, ct);
        if (tool is "ssl_deployment_targets_create" or "ssl_deployment_targets_update")
        {
            var id = tool == "ssl_deployment_targets_create" ? null : BusinessText(input, "targetId");
            var target = AdministrationInput<DeploymentTargetInput>(input, "target");
            if (target?.Configuration is null) return new(false, "VALIDATION", "Failed");
            var existing = id is null ? null : await db.DeploymentTargets.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
            var previous = existing is null ? null : JsonSerializer.Deserialize<DeploymentTargetConfiguration>(existing.ConfigurationJson, Json);
            if (!AdministrationCommandsAllowed(target.Configuration, previous)) return new(false, "FORBIDDEN", "Blocked");
            if (previous is not null)
            {
                // MCP 不提供编辑脚本的入口；更新其他连接资料时只沿用后台已保存的命令。
                target.Configuration.ValidationCommands = previous.ValidationCommands;
                target.Configuration.PostCommands = previous.PostCommands;
                if (string.IsNullOrEmpty(target.Configuration.Shell)) target.Configuration.Shell = previous.Shell;
                target.ConfigRevision = JsonSerializer.Deserialize<JsonElement>(ReadResources(operation).SummaryJson, Json).GetProperty("configRevision").GetInt32();
            }
            var result = await targets.SaveAsync(id, target, ct);
            return new(result.Success, AdministrationCode(result.Code), result.Success ? "Succeeded" : "Failed",
                result.Data is null ? null : new { targetId = result.Data.Id, result.Data.ExecutorKey, result.Data.Enabled, result.Data.ConfigRevision });
        }
        if (tool == "ssl_deployment_targets_status")
        {
            var result = await targets.SetStatusAsync(BusinessText(input, "targetId"), input.GetProperty("enabled").GetBoolean(), ct);
            return new(result.Success, AdministrationCode(result.Code), result.Success ? "Succeeded" : "Failed",
                result.Data is null ? null : new { targetId = result.Data.Id, result.Data.Enabled, result.Data.ConfigRevision });
        }
        if (tool == "ssl_deployment_targets_discover") return await DiscoverAdministrationTargetAsync(operation, BusinessText(input, "targetId"), ct);
        if (tool.EndsWith("_retry_plan", StringComparison.Ordinal) || tool.EndsWith("_rollback_plan", StringComparison.Ordinal))
            return await PlanAdministrationTaskAsync(operation, tool, BusinessText(input, "taskId"), ct);
        if (tool == "ssl_deployment_tasks_cancel")
        {
            var result = await deployments.CancelAsync(BusinessText(input, "taskId"), ct);
            return new(result.Success, AdministrationCode(result.Code), result.Success ? "Succeeded" : "Failed",
                result.Data is null ? null : new { taskId = result.Data.Id, result.Data.BatchId, result.Data.Status, result.Data.CancelRequested });
        }
        if (tool == "ssl_deployment_tasks_resolve")
        {
            // 说明原文仍在加密输入中，业务审计只保存摘要，避免未知凭据被任意备注带入明文日志。
            var result = await deployments.ResolveAsync(BusinessText(input, "taskId"), "MCP受控人工核对，原说明摘要：" + BusinessHash(BusinessText(input, "note")),
                operation.EffectiveUserId, "MCP", ct);
            return new(result.Success, AdministrationCode(result.Code), result.Success ? "Succeeded" : "Failed",
                result.Data is null ? null : new { taskId = result.Data.Id, result.Data.Status, manuallyResolved = true, remoteSuccessConfirmed = false });
        }
        return new(false, "TOOL_NOT_FOUND", "Failed");
    }

    private async Task<BusinessExecution> TestAdministrationAccountAsync(McpOperation operation, JsonElement input, CancellationToken ct)
    {
        if (businessAccounts is null || businessProviders is null) return new(false, "MCP_SERVICE_UNAVAILABLE", "Failed");
        var accountId = BusinessText(input, "accountId");
        var credentials = await businessAccounts.GetCredentialsAsync(accountId, ct);
        if (!credentials.Success || credentials.Data is null) return new(false, AdministrationCode(credentials.Code), "Failed");
        var gate = await RecheckBusinessAuthorizationAsync(operation, ct);
        if (!gate.Success) return new(false, AdministrationCode(gate.Code), "Blocked");
        ApiResult<CloudConnectionTest> result;
        if (BusinessText(input, "testKind") == "Dns")
        {
            var provider = businessProviders.ResolveDns(credentials.Data.Provider);
            if (!provider.Success || provider.Data is null) return new(false, AdministrationCode(provider.Code), "Failed");
            result = await provider.Data.TestDnsAsync(credentials.Data, ct);
        }
        else
        {
            var provider = businessProviders.ResolveCertificate(credentials.Data.Provider);
            if (!provider.Success || provider.Data is null) return new(false, AdministrationCode(provider.Code), "Failed");
            result = await provider.Data.TestAsync(credentials.Data, ct);
        }
        var code = AdministrationCode(result.Code);
        await businessAccounts.RecordTestAsync(accountId, result.Success, code, "MCP受控连接测试已完成，仅保存业务码。", ct);
        return new(result.Success, code, result.Success ? "Succeeded" : "Failed", new { accountId, testKind = BusinessText(input, "testKind"), connected = result.Success });
    }

    private async Task<BusinessExecution> DiscoverAdministrationTargetAsync(McpOperation operation, string targetId, CancellationToken ct)
    {
        var result = await targets.DiscoverAsync(targetId, ct);
        if (!result.Success || result.Data is null) return new(false, AdministrationCode(result.Code), "Failed");
        var caller = Caller(operation);
        async Task<string[]> AllowedDomains(IEnumerable<string> domains)
        {
            var selected = new List<string>();
            foreach (var domain in domains.Take(100))
            {
                var normalized = NormalizeDomain(domain);
                if (!CertificateManagementService.IsValidDomain(normalized)) continue;
                if ((await authorization.AuthorizeAsync(caller, operation.ToolName, new("", normalized, targetId), true, ct)).Success) selected.Add(normalized);
            }
            return selected.Distinct().ToArray();
        }
        var certificates = new List<object>();
        foreach (var item in result.Data.Certificates.Take(200))
        {
            var domains = await AllowedDomains(item.Domains);
            if (domains.Length > 0 && AdministrationPublicId(item.Id)) certificates.Add(new { id = item.Id, domains });
        }
        var sites = new List<object>();
        foreach (var item in result.Data.Sites.Take(200))
        {
            var domains = await AllowedDomains(item.Domains);
            if (domains.Length > 0 && AdministrationPublicId(item.Id)) sites.Add(new { id = item.Id, domains });
        }
        return new(true, "OK", "Succeeded", new { targetId, certificates, sites, truncated = result.Data.Certificates.Count > 200 || result.Data.Sites.Count > 200 });
    }

    private async Task<BusinessExecution> PlanAdministrationTaskAsync(McpOperation operation, string tool, string taskId, CancellationToken ct)
    {
        if (deployments is not DeploymentService concrete) return new(false, "MCP_DEPLOYMENT_UNSUPPORTED", "Failed");
        var source = await db.DeploymentTasks.AsNoTracking().SingleAsync(x => x.Id == taskId, ct);
        var batch = await db.DeploymentBatches.AsNoTracking().SingleAsync(x => x.Id == source.BatchId, ct);
        var resources = ReadResources(operation).Resources;
        var request = new DeploymentPlanRequest([new(source.TargetId)]);
        var childKey = "mcp-plan-" + operation.Id;
        var prepared = await PrepareAsync(Caller(operation), "Deployment", "ssl_deployment_plan", new DeploymentArguments(batch.CertificateId, request),
            resources, JsonSerializer.Serialize(new { sourceOperationId = operation.Id, sourceTaskId = taskId, action = tool }, Json), childKey, ct, preparing: true);
        if (!prepared.Success || prepared.Data is null) return new(false, AdministrationCode(prepared.Code), "Failed");
        var child = await db.McpOperations.SingleAsync(x => x.Id == prepared.Data.Id, ct);
        var plan = tool.EndsWith("_rollback_plan", StringComparison.Ordinal)
            ? await concrete.RollbackPlanForMcpAsync(taskId, child, ct)
            : await concrete.PlanForMcpAsync(batch.CertificateId, request, child, ct);
        if (!plan.Success || plan.Data is null)
        {
            await FailedPreparationAsync(child, AdministrationCode(plan.Code), "部署管理计划未生成。", ct);
            return new(false, AdministrationCode(plan.Code), "Failed");
        }
        var summary = JsonSerializer.Serialize(new { sourceTaskId = taskId, certificateId = batch.CertificateId, action = tool,
            fingerprint = plan.Data.Certificate.Fingerprint,
            batchId = plan.Data.BatchId, planRevision = plan.Data.PlanRevision,
            targets = plan.Data.Targets.Select(x => new { targetId = x.TargetId, configRevision = x.ConfigRevision, action = x.Plan.Action }) }, Json);
        child.ResourceJson = JsonSerializer.Serialize(ReadResources(child) with { SummaryJson = summary }, Json);
        child.Status = child.ApprovedAtUtc.HasValue ? "Approved" : "Prepared";
        child.Code = "PREPARED"; child.Message = "部署管理计划已生成；按原部署审批和提交链路继续。"; child.Version++;
        operation.BatchId = plan.Data.BatchId; operation.CertificateId = batch.CertificateId; operation.PlanRevision = plan.Data.PlanRevision;
        await db.SaveChangesAsync(ct);
        return new(true, "PREPARED", "Succeeded", new { deploymentOperationId = child.Id, deploymentIdempotencyKey = childKey,
            batchId = plan.Data.BatchId, planRevision = plan.Data.PlanRevision, sourceTaskId = taskId, requiresDeploymentApproval = child.Status == "Prepared" });
    }

    private async Task<bool> AdministrationBroadAsync(McpCallerContext caller, string tool, McpResourceScope scope, bool accounts, CancellationToken ct)
    {
        var permission = await authorization.AuthorizeAsync(caller, tool, scope, false, ct);
        return permission.Success && permission.Data?.Rules.Any(rule => accounts ? rule.AllAccounts : rule.AllTargets) == true;
    }
    private static T? AdministrationInput<T>(JsonElement input, string property) where T : class
    {
        try
        {
            if (!input.TryGetProperty(property, out var value) || value.ValueKind != JsonValueKind.Object) return null;
            var result = value.Deserialize<T>(Json);
            if (result is not null)
                foreach (var propertyInfo in typeof(T).GetProperties().Where(x => x.PropertyType == typeof(string) && x.CanWrite && x.GetValue(result) is null))
                    propertyInfo.SetValue(result, "");
            return result is not null && Validator.TryValidateObject(result, new ValidationContext(result), [], true) ? result : null;
        }
        catch (Exception exception) when (exception is JsonException or ArgumentException) { return null; }
    }
    private static bool AdministrationCommandsAllowed(DeploymentTargetConfiguration proposed, DeploymentTargetConfiguration? previous)
    {
        if (proposed.ValidationCommands is null || proposed.PostCommands is null) return false;
        if (!string.IsNullOrEmpty(proposed.Shell) && proposed.Shell != previous?.Shell && proposed.Shell is not ("sh" or "bash" or "powershell" or "pwsh" or "cmd")) return false;
        return (proposed.ValidationCommands.Count == 0 || previous is not null && BusinessHash(proposed.ValidationCommands) == BusinessHash(previous.ValidationCommands))
            && (proposed.PostCommands.Count == 0 || previous is not null && BusinessHash(proposed.PostCommands) == BusinessHash(previous.PostCommands));
    }
    private static bool AdministrationPublicId(string value) => Regex.IsMatch(value, "^[A-Za-z0-9._:-]{1,128}$", RegexOptions.CultureInvariant);
    /// <summary>审批只显示实际连接主机和端口，不能把 URL 中的用户信息、路径或查询凭据带入公开摘要。</summary>
    private static (string Host, int Port) AdministrationEndpoint(string endpoint, int port, string executorKey)
    {
        Uri.TryCreate(endpoint, UriKind.Absolute, out var absolute);
        var host = absolute is not null && absolute.Host.Length > 0 ? absolute.IdnHost
            : Uri.TryCreate("ssh://" + endpoint, UriKind.Absolute, out var ssh) ? ssh.IdnHost
            : System.Net.IPAddress.TryParse(endpoint.Trim('[', ']'), out var ip) ? ip.ToString() : "";
        var selectedPort = port > 0 ? port : absolute?.Port is > 0 ? absolute.Port : 22;
        if (executorKey == "synology.dsm.7.x")
        {
            try { selectedPort = SynologyDsmApiClient.BaseUri(new() { Endpoint = endpoint, Port = port }).Port; }
            catch (ArgumentException) { selectedPort = port; } // 无效配置留给原业务校验拒绝，不把路径或查询复制到摘要。
        }
        return (host, selectedPort);
    }
    private static string AdministrationCode(string code) => Regex.IsMatch(code, "^[A-Z][A-Z0-9_]{0,79}$", RegexOptions.CultureInvariant) ? code : "BUSINESS_FAILED";
}
