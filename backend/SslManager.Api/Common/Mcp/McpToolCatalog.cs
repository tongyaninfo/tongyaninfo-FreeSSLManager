using System.Text.Json;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Common.Mcp;

/// <summary>固定、可审核的工具目录；协议入口、管理页面和权限校验使用同一份能力定义。</summary>
public static class McpToolCatalog
{
    public const string ReadScope = "mcp.read";
    public const string WriteScope = "mcp.write";
    private static readonly HashSet<string> ViewerTools = new(StringComparer.Ordinal)
    {
        "ssl_domains_list", "ssl_dns_records_list", "ssl_certificates_list", "ssl_certificates_get",
        "ssl_operations_get", "ssl_system_status_get"
    };

    public static bool RequiresAdmin(string name) => !ViewerTools.Contains(name);
    public static IReadOnlyList<McpToolDescriptor> All { get; } = Create();

    private static IReadOnlyList<McpToolDescriptor> Create() =>
    [
        Tool("ssl_accounts_list", "查询云账号", "返回授权账号摘要及 ACME 正式/测试环境和注册就绪状态；Cloudflare 仅用于 DNS，不返回云密钥。", true, ["account"],
            Page(("provider", Text(40)))),
        Tool("ssl_domains_list", "查询托管域", "按白名单过滤后分页查询托管域。", true, ["account", "domain"],
            Page(("accountId", Id()), ("search", Text(253)))),
        Tool("ssl_dns_records_list", "查询 DNS 记录", "查询已授权托管域及名称范围中的记录。", true, ["account", "domain"],
            Page(("zoneId", Id()), ("type", Text(20)), ("name", Text(253))), ["zoneId"]),
        Tool("ssl_certificates_list", "查询证书", "按账号和业务域名过滤证书，返回测试环境及可部署标识；测试证书禁止部署，不下载材料。", true, ["account", "domain"],
            Page(("accountId", Id()), ("domain", Text(253)), ("status", Text(40)))),
        Tool("ssl_certificates_get", "读取证书详情", "读取授权证书的公开状态和申请进度，不返回私钥、验证值或内部快照。", true, ["account", "domain"],
            Fields(("certificateId", Id())), ["certificateId"]),
        Tool("ssl_deployment_executors_list", "查询部署执行器", "读取已注册执行器及其能力。", true, ["executor"], Fields()),
        Tool("ssl_deployment_targets_list", "查询部署目标", "仅返回被明确授权的目标摘要，不返回脚本、凭据或完整配置。", true, ["target"],
            Page(("domain", Text(253)))),
        Tool("ssl_deployments_list", "查询部署批次", "只显示证书及全部目标均被同一条规则授权的批次。", true, ["account", "domain", "target"],
            Page(("certificateId", Id()), ("targetId", Id()), ("status", Text(40)))),
        Tool("ssl_deployments_get", "读取部署批次", "读取完整授权批次的公开任务概要，不返回回执和材料快照。", true, ["account", "domain", "target"],
            Fields(("batchId", Id())), ["batchId"]),
        Tool("ssl_deployment_tasks_get", "读取部署任务", "读取授权任务阶段及验证状态；不返回远端输出、脚本或快照。", true, ["account", "domain", "target"],
            Fields(("taskId", Id())), ["taskId"]),
        Tool("ssl_schedules_list", "查询续签计划", "仅显示账号、域名及全部目标符合范围的计划。", true, ["account", "domain", "target"],
            Page(("accountId", Id()), ("domain", Text(253)))),
        Tool("ssl_schedules_get", "读取续签计划", "读取计划周期和公开状态，不暴露运行快照。", true, ["account", "domain", "target"],
            Fields(("scheduleId", Id())), ["scheduleId"]),
        Tool("ssl_schedule_runs_list", "查询续签轮次", "读取授权计划的轮次概要，不返回旧证书清理台账。", true, ["account", "domain", "target"],
            Page(("scheduleId", Id())), ["scheduleId"]),
        Tool("ssl_expiry_alerts_list", "查询证书预警", "读取授权证书的到期预警；保持管理员角色要求。", true, ["account", "domain"],
            Page(("domain", Text(253)), ("status", Text(40)))),
        Tool("ssl_operations_get", "查询受控操作", "只读取本客户端及有效调用用户自己的准备、审批和业务状态。", true, ["operation"],
            Fields(("operationId", Id())), ["operationId"]),
        Tool("ssl_system_status_get", "查询服务能力", "返回精简服务版本和调用者可见工具数量，不暴露主机路径或其他客户端。", true, ["system"], Fields()),
        Tool("ssl_certificate_application_prepare", "准备证书申请", "保存免费公网单域证书申请草稿，默认待管理员批准。腾讯云/阿里云默认 NativeAutoDns；ACME 仅支持 ManagedDns/ManualDns，有 dnsZoneId 时默认 ManagedDns，否则 ManualDns。跨账号 DNS 须指定已授权托管域 dnsZoneId，不隐式注册 ACME 账号。", false, ["account", "domain"],
            Fields(("accountId", Id()), ("domain", Text(253)), ("alias", Text(100)),
                ("validationMode", Enum("NativeAutoDns", "ManagedDns", "ManualDns", "File")), ("autoCleanup", Boolean()),
                ("dnsZoneId", Id()), ("instanceId", Id()), ("apiVersion", Enum("V2")), ("idempotencyKey", Key())),
            ["accountId", "domain", "idempotencyKey"]),
        Tool("ssl_certificate_application_submit", "提交已确认申请", "仅消费原申请草稿及相同幂等键，不接受重新指定的申请参数。", false, ["account", "domain"],
            Fields(("operationId", Id()), ("idempotencyKey", Key())), ["operationId", "idempotencyKey"]),
        Tool("ssl_deployment_plan", "准备证书部署", "读取已保存目标并生成材料、配置和状态固定的部署计划，默认待确认。", false, ["account", "domain", "target"],
            Fields(("certificateId", Id()), ("targetIds", new { type = "array", items = Id(), minItems = 1, maxItems = 20, uniqueItems = true }),
                ("idempotencyKey", Key())), ["certificateId", "targetIds", "idempotencyKey"]),
        Tool("ssl_deployment_submit", "提交已确认部署", "仅提交原计划与原调用身份，不传入私钥、命令或任意主机地址。", false, ["account", "domain", "target"],
            Fields(("operationId", Id()), ("idempotencyKey", Key())), ["operationId", "idempotencyKey"]),
        Tool("ssl_deployment_targets_test", "测试既有部署目标", "测试已保存目标；首次创建待确认操作，批准后携 operationId 重入。", false, ["target"],
            Fields(("targetId", Id()), ("idempotencyKey", Key()), ("operationId", Id())), ["targetId", "idempotencyKey"]),
        Tool("ssl_deployment_tasks_inspect", "核对既有部署任务", "核对授权任务；首次创建待确认操作，批准后携 operationId 重入。", false, ["account", "domain", "target"],
            Fields(("taskId", Id()), ("idempotencyKey", Key()), ("operationId", Id())), ["taskId", "idempotencyKey"])
    ];

    private static McpToolDescriptor Tool(string name, string title, string description, bool readOnly, string[] resources,
        Dictionary<string, object> fields, string[]? required = null)
    {
        // 云证书申请已有 instanceId 字段，因此部署实例确认使用独立名称，避免混用两个 ID。
        if (!readOnly)
        {
            fields["systemInstanceId"] = Id();
            required = [.. required ?? [], "systemInstanceId"];
            description += " 必须先查询 ssl_system_status_get 核对系统名称，并携带该系统的 systemInstanceId。";
        }
        var input = JsonSerializer.SerializeToElement(new { type = "object", properties = fields, required = required ?? [], additionalProperties = false });
        var output = JsonSerializer.SerializeToElement(new
        {
            type = "object", required = new[] { "success", "code", "message" },
            properties = new { success = new { type = "boolean" }, code = Text(100), message = Text(1000), data = new { } },
            additionalProperties = false
        });
        return new(name, title, description, readOnly, [readOnly ? ReadScope : WriteScope], resources, input, output);
    }

    private static Dictionary<string, object> Fields(params (string Name, object Schema)[] fields) => fields.ToDictionary(x => x.Name, x => x.Schema, StringComparer.Ordinal);
    private static Dictionary<string, object> Page(params (string Name, object Schema)[] fields)
    {
        var result = Fields(fields);
        result["page"] = new { type = "integer", minimum = 1, maximum = 100000 };
        result["pageSize"] = new { type = "integer", minimum = 1, maximum = 100 };
        return result;
    }
    private static object Text(int maximum) => new { type = "string", maxLength = maximum };
    private static object Id() => new { type = "string", minLength = 1, maxLength = 80 };
    private static object Key() => new { type = "string", minLength = 8, maxLength = 160 };
    private static object Boolean() => new { type = "boolean" };
    private static object Enum(params string[] values) => new Dictionary<string, object> { ["type"] = "string", ["enum"] = values };
}
