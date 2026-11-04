using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service.impl.Deployment;
using SslManager.Api.Service.impl.Mail;

namespace SslManager.Api.Service.impl;

public sealed partial class ConfigurationTransferService
{
    private static (ConfigurationPackage? Package, string Hash, List<ConfigurationImportIssue> Errors) ParsePackage(ConfigurationImportRequest request)
    {
        var errors = new List<ConfigurationImportIssue>();
        if (request.Mode is not ("CreateOnly" or "UpdateByName")) errors.Add(new("mode", "导入模式必须为 CreateOnly 或 UpdateByName。"));
        if (request.Package.ValueKind != JsonValueKind.Object)
            errors.Add(new("package", "配置包必须是 JSON 对象。"));
        if (errors.Count > 0) return (null, "", errors);
        var raw = request.Package.GetRawText();
        if (Encoding.UTF8.GetByteCount(raw) > MaximumPackageBytes)
            return (null, "", [new("package", "配置包不能超过 5 MiB。")]);
        try
        {
            if (!HasProperty(request.Package, "format") || !HasProperty(request.Package, "version") ||
                !HasProperty(request.Package, "cloudAccounts") || !HasProperty(request.Package, "deploymentTargets") ||
                !HasProperty(request.Package, "certificateSchedules") || HasDuplicateProperties(request.Package))
                return (null, "", [new("package", "配置包缺少必要字段，或包含重复字段。")]);
            var package = JsonSerializer.Deserialize<ConfigurationPackage>(raw, Json);
            if (package is null || package.Format != "free-ssl-manager.configuration" || package.Version != 1)
                return (null, "", [new("package", "配置包格式标识或版本不受支持。")]);
            if (package.CloudAccounts is null || package.DeploymentTargets is null || package.CertificateSchedules is null || package.McpClients is null)
                return (null, "", [new("package", "云账号、部署目标和证书计划必须为数组。")]);
            if (RecordCount(package) is < 1 or > MaximumRecords)
                return (null, "", [new("package", "配置包须包含 1～1000 条配置。")]);
            return (package, Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(raw))), errors);
        }
        catch (Exception exception) when (exception is JsonException or NotSupportedException or InvalidOperationException)
        {
            // 严格拒绝未知字段和错误类型，不将解析器可能携带输入内容的消息返回给客户端。
            return (null, "", [new("package", "配置 JSON 含未知字段、错误类型或无效结构。")]);
        }
    }

    private static bool HasProperty(JsonElement element, string name) => element.EnumerateObject()
        .Any(property => string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase));

    private static bool HasDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in element.EnumerateObject())
                if (!names.Add(property.Name) || HasDuplicateProperties(property.Value)) return true;
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var value in element.EnumerateArray()) if (HasDuplicateProperties(value)) return true;
        return false;
    }

    private async Task<ImportPlan> CreatePlanAsync(ConfigurationPackage package, string mode, ConfigurationSnapshot snapshot, CancellationToken ct)
    {
        var plan = new ImportPlan();
        var accountKeys = package.CloudAccounts.Where(item => item?.Settings is not null).Select(item => AccountKey(item.Settings.Provider, item.Settings.Name)).ToArray();
        var targetKeys = package.DeploymentTargets.Where(item => item?.Settings is not null).Select(item => NameKey(item.Settings.Name)).ToArray();
        var scheduleKeys = package.CertificateSchedules.Where(item => item?.Settings is not null).Select(item => NameKey(item.Settings.Name)).ToArray();
        var accountSourceIds = package.CloudAccounts.Where(item => item is not null).Select(item => item.SourceId).ToArray();
        var targetSourceIds = package.DeploymentTargets.Where(item => item is not null).Select(item => item.SourceId).ToArray();
        var scheduleSourceIds = package.CertificateSchedules.Where(item => item is not null).Select(item => item.SourceId).ToArray();
        for (var index = 0; index < package.CloudAccounts.Count; index++)
        {
            var path = $"cloudAccounts[{index}]";
            var item = package.CloudAccounts[index];
            if (item?.Settings is null) { InvalidItem(plan, "CloudAccount", path); continue; }
            var input = item.Settings;
            var before = plan.Errors.Count;
            ValidateSourceId(item.SourceId, accountSourceIds, path, plan);
            if (ValidateAttributes(input, path + ".settings", plan))
            {
                var validation = CloudAccountStore.Validate(input, true);
                if (validation is not null) plan.Errors.Add(new(path + ".settings", validation));
            }
            ValidateName(input.Name, path, plan);
            var key = AccountKey(input.Provider, input.Name);
            var matchedAccounts = snapshot.Accounts.Where(row => AccountKey(row.Provider, row.Name) == key).ToArray();
            // 导入与普通保存遵守相同目录边界，不能把已审批的测试账号原地变成正式签发账号。
            if (mode == "UpdateByName" && input.Provider == "Acme" && matchedAccounts.Length == 1 &&
                matchedAccounts[0].AcmeDirectoryUrl != input.AcmeDirectoryUrl)
                plan.Errors.Add(new(path + ".settings.acmeDirectoryUrl", "ACME 正式与测试目录不能原地切换，请分别创建账号配置。"));
            if (mode == "UpdateByName" && input.Provider == "Acme" && matchedAccounts.Length == 1)
            {
                var existing = matchedAccounts[0];
                if (existing.AcmeAccountMode != input.AcmeAccountMode)
                    plan.Errors.Add(new(path + ".settings.acmeAccountMode", "ACME 账号接入模式不能原地切换，请新增接入配置。"));
                var originalAccountUrl = string.IsNullOrEmpty(existing.ProtectedAccessKeyId) ? "" :
                    protection.CreateProtector(CloudAccountStore.ConfigurationProtectionPurpose, existing.Id).Unprotect(existing.ProtectedAccessKeyId);
                if (!string.IsNullOrEmpty(input.AccessKeyId) && input.AccessKeyId != originalAccountUrl)
                    plan.Errors.Add(new(path + ".settings.accessKeyId", "已有 ACME 接入不能切换账号 URL，请为另一个外部账号新增接入配置。"));
                if (!string.IsNullOrEmpty(input.AccessKeySecret) && !string.IsNullOrEmpty(existing.ProtectedAccessKeySecret) &&
                    AcmeProtocolClient.IsValidAccountKey(input.AccessKeySecret))
                {
                    var originalKey = protection.CreateProtector(CloudAccountStore.ConfigurationProtectionPurpose, existing.Id)
                        .Unprotect(existing.ProtectedAccessKeySecret);
                    if (AcmeProtocolClient.Thumbprint(originalKey) != AcmeProtocolClient.Thumbprint(input.AccessKeySecret))
                        plan.Errors.Add(new(path + ".settings.accessKeySecret", "已有 ACME 账号私钥不能替换，请为另一账号新增接入配置。"));
                }
            }
            var matches = matchedAccounts.Select(row => row.Id).ToArray();
            Register(plan, "CloudAccount", item.SourceId, input.Name, path, key, accountKeys, matches, mode, before, plan.Accounts);
        }
        for (var index = 0; index < package.DeploymentTargets.Count; index++)
        {
            var path = $"deploymentTargets[{index}]";
            var item = package.DeploymentTargets[index];
            if (item?.Settings is null) { InvalidItem(plan, "DeploymentTarget", path); continue; }
            var input = item.Settings;
            var before = plan.Errors.Count;
            ValidateSourceId(item.SourceId, targetSourceIds, path, plan);
            if (ValidateAttributes(input, path + ".settings", plan))
            {
                var resolved = executors.Resolve(input.ExecutorKey);
                if (!resolved.Success || resolved.Data is null) plan.Errors.Add(new(path + ".settings.executorKey", "执行器不存在或当前不可用。"));
                else
                {
                    DeploymentTargetService.NormalizeConfiguration(input);
                    var validation = DeploymentTargetService.Validate(input, resolved.Data.Descriptor)
                        ?? DeploymentTargetService.ValidateCredentials(input, DeploymentTargetService.CredentialsFromInput(input));
                    if (validation is null) validation = await DeploymentTargetService.ValidateSourceConfigurationAsync(db, input, false, ct);
                    if (validation is not null) plan.Errors.Add(new(path + ".settings", validation));
                }
            }
            ValidateName(input.Name, path, plan);
            var key = NameKey(input.Name);
            var matches = snapshot.Targets.Where(row => NameKey(row.Name) == key).ToArray();
            if (mode == "UpdateByName" && matches.Length == 1 && matches[0].ExecutorKey != input.ExecutorKey)
                plan.Errors.Add(new(path + ".settings.executorKey", "同名目标的执行器不同，不能原地更换执行器。"));
            Register(plan, "DeploymentTarget", item.SourceId, input.Name, path, key, targetKeys,
                matches.Select(row => row.Id).ToArray(), mode, before, plan.Targets);
        }
        for (var index = 0; index < package.CertificateSchedules.Count; index++)
        {
            var path = $"certificateSchedules[{index}]";
            var item = package.CertificateSchedules[index];
            if (item?.Settings is null) { InvalidItem(plan, "CertificateSchedule", path); continue; }
            var input = item.Settings;
            var before = plan.Errors.Count;
            ValidateSourceId(item.SourceId, scheduleSourceIds, path, plan);
            if (ValidateAttributes(input, path + ".settings", plan))
            {
                var validation = CertificateScheduleService.ValidateStructure(input);
                if (validation is not null) plan.Errors.Add(new(path + ".settings", validation));
            }
            ValidateName(input.Name, path, plan);
            if (!plan.Accounts.ContainsKey(input.AccountId ?? "")) plan.Errors.Add(new(path + ".settings.accountId", "计划引用的云账号不在配置包中或引用键无效。"));
            if (input.DnsZoneId is not null) plan.Errors.Add(new(path + ".settings.dnsZoneId", "配置包不能携带源实例的 DNS 本地主键，请使用可移植 DNS 区域引用。"));
            if (item.DnsAccountSourceId is not null && (!plan.Accounts.ContainsKey(item.DnsAccountSourceId) ||
                string.IsNullOrWhiteSpace(item.DnsProviderZoneId) || !CertificateManagementService.IsValidDomain(item.DnsZoneName ?? "") ||
                !CertificateManagementService.BelongsTo(input.Domain, item.DnsZoneName!)))
                plan.Errors.Add(new(path + ".dnsAccountSourceId", "可移植 DNS 区域引用无效或不覆盖计划域名。"));
            foreach (var targetId in input.TargetIds ?? [])
            {
                if (!plan.Targets.ContainsKey(targetId ?? "")) plan.Errors.Add(new(path + ".settings.targetIds", "计划引用的部署目标不在配置包中或引用键无效。"));
                else
                {
                    var target = package.DeploymentTargets.FirstOrDefault(candidate => candidate?.SourceId == targetId)?.Settings;
                    if (target is null) continue;
                    if (target.ExecutorKey is not ("linux.files.ssh.v1" or "synology.dsm.7.x" or "safeline.ce.9.x" or "harbor.compose.ssh.v1"))
                        plan.Errors.Add(new(path + ".settings.targetIds", "计划引用了不支持自动申请部署的目标。"));
                    if (target.ExecutorKey is ("linux.files.ssh.v1" or "harbor.compose.ssh.v1") && target.Configuration is not null &&
                        DeploymentSourceBinding.NormalizeDomain(target.Configuration.SourceDomain) != input.Domain)
                        plan.Errors.Add(new(path + ".settings.targetIds", "Linux 或 Harbor 目标的来源域名须与计划域名一致。"));
                }
            }
            var key = NameKey(input.Name);
            var matches = snapshot.Schedules.Where(row => NameKey(row.Name) == key).Select(row => row.Id).ToArray();
            Register(plan, "CertificateSchedule", item.SourceId, input.Name, path, key, scheduleKeys, matches, mode, before, plan.Schedules);
        }
        if (package.MailSettings is { } mail)
        {
            var before = plan.Errors.Count;
            if (ValidateAttributes(mail, "mailSettings", plan))
            {
                var validation = MailService.ValidateSettings(mail);
                if (validation is not null) plan.Errors.Add(new("mailSettings", validation));
                if (string.IsNullOrWhiteSpace(mail.Password)) plan.Errors.Add(new("mailSettings.password", "导入的邮箱配置必须包含完整密码，不能沿用目标实例旧值。"));
            }
            var action = plan.Errors.Count > before ? "Invalid" : snapshot.Mail is null ? "Create" : mode == "CreateOnly" ? "Conflict" : "Update";
            if (action == "Conflict") plan.Errors.Add(new("mailSettings", "当前实例已有邮箱配置，请使用按名称更新模式。"));
            plan.Items.Add(new("MailSettings", "default", "SMTP", action));
        }
        if (package.ExpiryReminderSettings is { } reminders)
        {
            var before = plan.Errors.Count;
            if (ValidateAttributes(reminders, "expiryReminderSettings", plan))
            {
                var validation = ExpiryReminderService.Validate(reminders);
                if (validation is not null) plan.Errors.Add(new("expiryReminderSettings", validation));
            }
            var action = plan.Errors.Count > before ? "Invalid" : snapshot.ExpiryReminders is null ? "Create" : mode == "CreateOnly" ? "Conflict" : "Update";
            if (action == "Conflict") plan.Errors.Add(new("expiryReminderSettings", "当前实例已有到期提醒规则，请使用按名称更新模式。"));
            plan.Items.Add(new("ExpiryReminderSettings", "default", "证书到期提醒", action));
        }
        await RejectActiveUpdatesAsync(plan, snapshot, ct);
        await ValidateMcpConfigurationAsync(package, mode, snapshot, plan, ct);
        return plan;
    }

    private static void InvalidItem(ImportPlan plan, string kind, string path)
    {
        plan.Items.Add(new(kind, "", "", "Invalid"));
        plan.Errors.Add(new(path, "配置项和 settings 均不能为空。"));
    }

    private static void ValidateSourceId(string? sourceId, string?[] ids, string path, ImportPlan plan)
    {
        if (string.IsNullOrWhiteSpace(sourceId) || sourceId.Length > 80 || sourceId.Any(char.IsControl) || sourceId != sourceId.Trim())
            plan.Errors.Add(new(path + ".sourceId", "包内引用键须为 1～80 个字符，不能含控制字符或首尾空白。"));
        else if (ids.Count(id => id == sourceId) > 1) plan.Errors.Add(new(path + ".sourceId", "包内引用键重复。"));
    }

    private static void ValidateName(string? name, string path, ImportPlan plan)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > 100 || name.Any(char.IsControl))
            plan.Errors.Add(new(path + ".settings.name", "配置名称不能为空，最多 100 字，不能含控制字符。"));
    }

    private static bool ValidateAttributes(object input, string path, ImportPlan plan)
    {
        var errors = new List<ValidationResult>();
        if (Validator.TryValidateObject(input, new ValidationContext(input), errors, true)) return true;
        foreach (var error in errors)
            foreach (var member in error.MemberNames.DefaultIfEmpty(""))
                plan.Errors.Add(new(path + (member.Length > 0 ? "." + JsonNamingPolicy.CamelCase.ConvertName(member) : ""), "字段格式、长度或范围不正确。"));
        return false;
    }

    private static string NameKey(string? name) => (name ?? "").Trim().ToUpperInvariant();
    private static string AccountKey(string? provider, string? name) => (provider ?? "") + "\0" + NameKey(name);

    private static void Register(ImportPlan plan, string kind, string sourceId, string? name, string path, string key,
        string[] packageKeys, string[] matches, string mode, int errorsBefore, Dictionary<string, string?> mapping)
    {
        var action = plan.Errors.Count > errorsBefore ? "Invalid" : "Create";
        if (packageKeys.Count(candidate => candidate == key) > 1)
        {
            action = "Conflict";
            plan.Errors.Add(new(path + ".settings.name", "配置包存在同类同名配置，不能确定导入关系。"));
        }
        if (matches.Length > 1 || matches.Length > 0 && mode == "CreateOnly")
        {
            action = "Conflict";
            plan.Errors.Add(new(path + ".settings.name", matches.Length > 1 ? "当前实例存在多个同名配置，无法自动匹配。" : "当前实例已存在同名配置。"));
        }
        else if (matches.Length == 1 && action != "Invalid" && action != "Conflict") action = "Update";
        plan.Items.Add(new(kind, sourceId ?? "", name ?? "", action));
        if (!string.IsNullOrWhiteSpace(sourceId) && !mapping.ContainsKey(sourceId)) mapping.Add(sourceId, matches.Length == 1 ? matches[0] : null);
    }

    private async Task RejectActiveUpdatesAsync(ImportPlan plan, ConfigurationSnapshot snapshot, CancellationToken ct)
    {
        var updates = plan.Items.Where(item => item.Action == "Update").ToArray();
        if (updates.Length == 0) return;
        var runs = await db.CertificateScheduleRuns.AsNoTracking().Where(item => item.Active)
            .Select(item => new { item.ScheduleId, item.ConfigSnapshotJson, item.TargetsJson, item.OldCertificatesJson }).ToListAsync(ct);
        var activeSchedules = runs.Select(item => item.ScheduleId).ToHashSet(StringComparer.Ordinal);
        var activeAccounts = snapshot.Schedules.Where(item => activeSchedules.Contains(item.Id)).Select(item => item.AccountId).ToHashSet(StringComparer.Ordinal);
        // 独立注册没有证书任务；仍须保留已提交/结果未知账户的原配置和密钥供核对。
        activeAccounts.UnionWith(snapshot.Accounts.Where(item => item.Provider == "Acme" &&
            item.AcmeRegistrationStatus is "Prepared" or "Submitting" or "Unknown").Select(item => item.Id));
        var activeZones = snapshot.Schedules.Where(item => activeSchedules.Contains(item.Id) && !string.IsNullOrEmpty(item.DnsZoneId))
            .Select(item => item.DnsZoneId!).ToHashSet(StringComparer.Ordinal);
        var activeTargets = new HashSet<string>(StringComparer.Ordinal);
        var unreadableRun = false;
        // 旧轮次可能没有完整目标快照，同时检查当前计划的绑定，避免仅更新目标时漏过活跃轮次。
        foreach (var schedule in snapshot.Schedules.Where(item => activeSchedules.Contains(item.Id)))
        {
            try
            {
                using var targets = JsonDocument.Parse(schedule.TargetIdsJson);
                foreach (var targetId in targets.RootElement.EnumerateArray())
                {
                    if (targetId.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(targetId.GetString()))
                    { unreadableRun = true; continue; }
                    activeTargets.Add(targetId.GetString()!);
                }
            }
            catch (Exception exception) when (exception is JsonException or InvalidOperationException) { unreadableRun = true; }
        }
        foreach (var run in runs)
        {
            try
            {
                using var config = JsonDocument.Parse(run.ConfigSnapshotJson);
                // 固定快照可能仍使用旧 DNS 区域；申请/吊销清理还会在嵌套记录中保存独立账号。
                CollectDnsResources(config.RootElement);
                foreach (var property in config.RootElement.EnumerateObject())
                {
                    if (property.Name.Equals("accountId", StringComparison.OrdinalIgnoreCase) && property.Value.ValueKind == JsonValueKind.String)
                        activeAccounts.Add(property.Value.GetString()!);
                    if (property.Name.Equals("targetIds", StringComparison.OrdinalIgnoreCase) && property.Value.ValueKind == JsonValueKind.Array)
                        foreach (var id in property.Value.EnumerateArray()) if (id.ValueKind == JsonValueKind.String) activeTargets.Add(id.GetString()!);
                }
                using var targets = JsonDocument.Parse(run.TargetsJson);
                foreach (var target in targets.RootElement.EnumerateArray())
                    foreach (var property in target.EnumerateObject())
                        if (property.Name.Equals("targetId", StringComparison.OrdinalIgnoreCase) && property.Value.ValueKind == JsonValueKind.String)
                            activeTargets.Add(property.Value.GetString()!);
                using var oldCertificates = JsonDocument.Parse(run.OldCertificatesJson);
                CollectDnsResources(oldCertificates.RootElement);
            }
            catch (Exception exception) when (exception is JsonException or InvalidOperationException) { unreadableRun = true; }
        }
        var riskyTasks = await db.DeploymentTasks.AsNoTracking().Where(item => item.Status == "Draft" || item.Status == "Queued" || item.Status == "Running"
            || item.Status == "Recovering" || item.Status == "NeedsAttention" || item.Status == "Failed" && (item.Code == "REMOTE_RESULT_UNKNOWN" || item.ReceiptJson.Length > 2))
            .Select(item => new { item.TargetId, item.BatchId }).ToListAsync(ct);
        foreach (var task in riskyTasks) activeTargets.Add(task.TargetId);
        var batchIds = riskyTasks.Select(item => item.BatchId).Distinct().ToArray();
        foreach (var accountId in await db.DeploymentBatches.AsNoTracking().Where(item => batchIds.Contains(item.Id))
            .Join(db.Certificates, batch => batch.CertificateId, certificate => certificate.Id, (_, certificate) => certificate.AccountId).Distinct().ToListAsync(ct))
            activeAccounts.Add(accountId);
        var busyCertificateIds = db.CertificateJobs.Where(item => item.Status == "Waiting" || item.Status == "Submitting" || item.Status == "SubmissionUnknown"
            || item.Status == "Pending" || item.Status == "Recovering" || item.Status == "NeedsAttention").Select(item => item.CertificateId);
        var busyCertificates = await db.Certificates.AsNoTracking().Where(item => busyCertificateIds.Contains(item.Id) || item.Status == "Submitting"
            || item.Status == "SubmissionUnknown" || item.Status == "PendingValidation" || item.Status == "Processing" || item.Status == "Revoking")
            .Select(item => new { item.Id, item.AccountId, item.DnsZoneId }).ToListAsync(ct);
        foreach (var certificate in busyCertificates)
        {
            activeAccounts.Add(certificate.AccountId);
            if (!string.IsNullOrEmpty(certificate.DnsZoneId)) activeZones.Add(certificate.DnsZoneId);
        }
        var busyIds = busyCertificates.Select(item => item.Id).ToArray();
        foreach (var zone in await db.ValidationRecords.AsNoTracking().Where(item => busyIds.Contains(item.CertificateId) && item.DnsZoneId != null)
            .Select(item => item.DnsZoneId!).Distinct().ToListAsync(ct))
            if (!string.IsNullOrEmpty(zone)) activeZones.Add(zone);
        if (activeZones.Count > 0)
        {
            var zones = await db.Domains.AsNoTracking().Where(item => activeZones.Contains(item.Id))
                .Select(item => new { item.Id, item.AccountId }).ToListAsync(ct);
            foreach (var zone in zones) activeAccounts.Add(zone.AccountId);
            // 已固定区域丢失时不能确认旧账号范围，保守拒绝覆盖配置，保留恢复现场。
            if (zones.Count != activeZones.Count) unreadableRun = true;
        }
        var mailSending = packageContainsMailUpdate(updates) && await db.MailMessages.AsNoTracking().AnyAsync(item => item.Status == "Sending", ct);
        var reminderSending = updates.Any(item => item.Kind == "ExpiryReminderSettings") &&
            (await db.CertificateExpiryAlerts.AsNoTracking().AnyAsync(item => item.PendingRequestId != "", ct) ||
             await db.MailMessages.AsNoTracking().AnyAsync(item => item.Status == "Sending" && item.CreatedByUserId == "system:certificate-expiry", ct));
        foreach (var item in updates)
        {
            var busy = item.Kind switch
            {
                "CloudAccount" => unreadableRun || activeAccounts.Contains(plan.Accounts[item.SourceId]!),
                "DeploymentTarget" => unreadableRun || activeTargets.Contains(plan.Targets[item.SourceId]!),
                "CertificateSchedule" => activeSchedules.Contains(plan.Schedules[item.SourceId]!),
                "MailSettings" => mailSending,
                "ExpiryReminderSettings" => reminderSending,
                _ => false
            };
            if (!busy) continue;
            var index = plan.Items.IndexOf(item);
            plan.Items[index] = item with { Action = "Conflict" };
            plan.Errors.Add(new(item.Kind == "MailSettings" ? "mailSettings" : item.Kind switch
            { "CloudAccount" => "cloudAccounts", "DeploymentTarget" => "deploymentTargets", "ExpiryReminderSettings" => "expiryReminderSettings", _ => "certificateSchedules" }, "相关配置存在运行中或待核对任务，请结束并核对任务后重新预览。"));
        }
        static bool packageContainsMailUpdate(ConfigurationImportItemPreview[] items) => items.Any(item => item.Kind == "MailSettings");

        void CollectDnsResources(JsonElement element)
        {
            if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in element.EnumerateArray()) CollectDnsResources(item);
                return;
            }
            if (element.ValueKind != JsonValueKind.Object) return;
            foreach (var property in element.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(property.Value.GetString()))
                {
                    if (property.Name.Equals("accountId", StringComparison.OrdinalIgnoreCase)) activeAccounts.Add(property.Value.GetString()!);
                    if (property.Name.Equals("dnsZoneId", StringComparison.OrdinalIgnoreCase) || property.Name.Equals("zoneId", StringComparison.OrdinalIgnoreCase))
                        activeZones.Add(property.Value.GetString()!);
                }
                CollectDnsResources(property.Value);
            }
        }
    }
}
