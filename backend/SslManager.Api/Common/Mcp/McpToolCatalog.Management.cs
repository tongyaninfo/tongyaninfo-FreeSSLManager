using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Common.Mcp;

public static partial class McpToolCatalog
{
    /// <summary>管理类业务同样使用明确 schema，不反射开放服务方法或任意命令执行。</summary>
    private static IEnumerable<McpToolDescriptor> ManagementTools()
    {
        McpToolDescriptor Manage(string name, string title, string description, string[] resources,
            Dictionary<string, object> fields, params string[] required)
        {
            fields["idempotencyKey"] = Key(); fields["operationId"] = Id();
            return Tool(name, title, description + " 首次只准备，Web 批准后携相同完整输入、幂等键和原 operationId 重入。", false,
                resources, fields, [.. required, "idempotencyKey"]);
        }
        yield return Manage("ssl_accounts_create", "新增云账号", "需要明确全部账号授权。凭据加密保存，不导出密钥，不隐式注册 ACME 账号。", ["account"], Fields(("account", AccountInputSchema())), "account");
        yield return Manage("ssl_accounts_update", "修改云账号", "绑定账号ID和原配置摘要，更新时空凭据沿用原值，不允许更换供应商。", ["account"], Fields(("accountId", Id()), ("account", AccountInputSchema())), "accountId", "account");
        yield return Manage("ssl_accounts_test", "测试云账号", "仅测试已保存账号的证书或DNS连接，不返回凭据或云原文。", ["account"], Fields(("accountId", Id()), ("testKind", Enum("Certificate", "Dns"))), "accountId", "testKind");
        yield return Manage("ssl_deployment_targets_create", "新增部署目标", "需要明确全部目标授权。只允许受支持执行器和无自定义命令配置；敏感字段加密保存。", ["domain", "target"], Fields(("target", TargetInputSchema())), "target");
        yield return Manage("ssl_deployment_targets_update", "修改部署目标", "校验原目标修订、原域名及新域名授权；自定义校验/后置命令只沿用后台既有配置。", ["domain", "target"], Fields(("targetId", Id()), ("target", TargetInputSchema())), "targetId", "target");
        yield return Manage("ssl_deployment_targets_status", "启停部署目标", "只修改授权范围内已保存目标。", ["domain", "target"], Fields(("targetId", Id()), ("enabled", Boolean())), "targetId", "enabled");
        yield return Manage("ssl_deployment_targets_discover", "发现目标证书与站点", "连接既有目标，仅返回域名授权范围内的远端资源标识，不返回远端消息和凭据。", ["domain", "target"], Fields(("targetId", Id())), "targetId");
        yield return Manage("ssl_deployment_tasks_cancel", "取消部署任务", "只请求取消原任务，不声称已回滚已发生写入。", ["account", "domain", "target"], Fields(("taskId", Id())), "taskId");
        yield return Manage("ssl_deployment_tasks_retry_plan", "准备部署重试计划", "只生成关联原Key的新草稿及独立审批操作，使用返回的部署operationId再次审批并提交，不直接执行。", ["account", "domain", "target"], Fields(("taskId", Id())), "taskId");
        yield return Manage("ssl_deployment_tasks_rollback_plan", "准备部署回滚计划", "只按原任务已有恢复材料生成回滚草稿及独立审批操作，不自动执行远端回滚。", ["account", "domain", "target"], Fields(("taskId", Id())), "taskId");
        yield return Manage("ssl_deployment_tasks_resolve", "记录部署人工核对", "仅处理待关注任务，保存说明摘要，不把人工处理宣称为远端执行成功。", ["account", "domain", "target"], Fields(("taskId", Id()), ("note", Text(1000))), "taskId", "note");
        yield return Manage("ssl_schedules_create", "新增续签计划", "固定账号、域名、DNS区域及目标；自动执行持续核对原Key，支持可选旧证书清理。", ["account", "domain", "target"], Fields(("schedule", ScheduleInputSchema())), "schedule");
        yield return Manage("ssl_schedules_update", "修改续签计划", "核对原计划修订以及原/新全部资源权限，已接受轮次保留其原身份。", ["account", "domain", "target"], Fields(("scheduleId", Id()), ("schedule", ScheduleInputSchema())), "scheduleId", "schedule");
        yield return Manage("ssl_schedules_status", "启停续签计划", "启用授权自动申请、部署及已配置清理；停用不伪称撤回已提交动作。", ["account", "domain", "target"], Fields(("scheduleId", Id()), ("enabled", Boolean())), "scheduleId", "enabled");
        yield return Manage("ssl_schedules_run", "立即执行续签计划", "只创建一轮持久任务并保留本次Key来源，未来写入仍检查原授权。", ["account", "domain", "target"], Fields(("scheduleId", Id())), "scheduleId");
        yield return Manage("ssl_schedule_runs_resume", "恢复续签轮次核对", "仅继续核对原轮次，不重发未知申请，不允许另一把Key接管原MCP轮次。", ["account", "domain", "target"], Fields(("runId", Id())), "runId");
        yield return Manage("ssl_schedule_runs_resolve", "结束待核对续签轮次", "管理员明确说明并结束待关注轮次，保留已有证书与部署，不能宣称未知远端动作成功。", ["account", "domain", "target"], Fields(("runId", Id()), ("note", Text(1000))), "runId", "note");
    }

    private static object ObjectSchema(Dictionary<string, object> properties, params string[] required) => new { type = "object", properties, required, additionalProperties = false };
    private static object Integer(int minimum, int maximum) => new { type = "integer", minimum, maximum };
    private static object IdArray(int minimum = 0, int maximum = 20) => new { type = "array", items = Id(), minItems = minimum, maxItems = maximum, uniqueItems = true };
    private static object SecretText(int maximum) => new Dictionary<string, object> { ["type"] = "string", ["maxLength"] = maximum, ["x-mcp-multiline"] = true };
    private static object AccountInputSchema() => ObjectSchema(Fields(
        ("name", Text(100)), ("provider", Enum("TencentCloud", "Aliyun", "Cloudflare", "Acme")),
        ("accessKeyId", Text(4096)), ("accessKeySecret", SecretText(8192)), ("enabled", Boolean()),
        ("useForCertificates", Boolean()), ("useForDns", Boolean()), ("contactName", Text(100)), ("contactEmail", Text(254)),
        ("contactPhone", Text(40)), ("aliyunContactId", Text(64)), ("acmeDirectoryUrl", Text(300)),
        ("acmeAccountMode", Enum("Existing", "Automatic")), ("autoSyncEnabled", Boolean()),
        ("autoSyncIntervalUnit", Enum("hour", "day")), ("autoSyncIntervalValue", Integer(1, 366)), ("autoSyncAtLocalTime", Text(5))), "name", "provider");
    private static object TargetInputSchema() => ObjectSchema(Fields(
        ("name", Text(100)), ("description", Text(500)), ("executorKey", Text(100)), ("endpoint", Text(2048)),
        ("port", Integer(0, 65535)), ("username", Text(200)), ("authenticationMode", Text(40)),
        ("password", SecretText(16384)), ("apiToken", SecretText(16384)), ("privateKey", SecretText(65536)),
        ("privateKeyPassphrase", SecretText(4096)), ("pfxPassword", SecretText(4096)), ("enabled", Boolean()),
        ("tlsFingerprint", Text(256)), ("configRevision", Integer(1, int.MaxValue)), ("configuration", TargetConfigurationSchema())), "name", "executorKey", "endpoint");
    private static object TargetConfigurationSchema() => ObjectSchema(Fields(
        ("certificateDescription", Text(200)), ("siteIds", IdArray()), ("remoteCertificateId", Text(100)), ("bindSites", Boolean()),
        ("operatingSystem", Text(40)), ("outputDirectory", Text(2048)), ("harborInstallDirectory", Text(2048)),
        ("harborComposeCommand", Enum("docker compose", "docker-compose")), ("harborProxyService", Text(100)),
        ("sourceDomain", Text(253)), ("sourceFormat", Text(40)), ("hostKeyFingerprint", Text(256)), ("createDirectory", Boolean()),
        ("verificationHost", Text(253)), ("verificationPort", Integer(1, 65535)), ("verificationServerName", Text(253)),
        ("connectionTimeoutSeconds", Integer(1, 600)), ("operationTimeoutSeconds", Integer(1, 3600)),
        ("files", new { type = "array", items = ObjectSchema(Fields(("role", Text(40)), ("fileName", Text(256)), ("directory", Text(2048)),
            ("sourceFileName", Text(2048))), "role", "fileName"), minItems = 0, maxItems = 50 })));
    private static object ScheduleInputSchema() => ObjectSchema(Fields(
        ("name", Text(100)), ("accountId", Id()), ("domain", Text(253)), ("alias", Text(100)),
        ("validationMode", Enum("ManagedDns", "NativeAutoDns")), ("dnsZoneId", Id()), ("autoCleanup", Boolean()),
        ("revokeOldCertificates", Boolean()), ("targetIds", IdArray(1)), ("intervalValue", Integer(1, 1200)),
        ("intervalUnit", Enum("hour", "day", "month")), ("firstRunAtUtc", Text(50)), ("enabled", Boolean()),
        ("configRevision", Integer(1, int.MaxValue))), "name", "accountId", "domain", "targetIds", "firstRunAtUtc");
}
