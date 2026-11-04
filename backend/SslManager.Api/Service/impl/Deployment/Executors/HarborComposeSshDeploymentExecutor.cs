using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl.Deployment.Executors;

/// <summary>Harbor 2.x Compose 证书部署；文件与恢复协议复用 SSH 编排，只激活 HTTPS 代理。</summary>
public sealed partial class HarborComposeSshDeploymentExecutor(RemoteFileDeploymentService files, IRemoteTransport transport)
    : IDeploymentExecutor, IDeploymentRecoveryExecutor, IRollbackDeploymentExecutor
{
    public const string ExecutorKey = "harbor.compose.ssh.v1";

    public DeploymentExecutorDescriptor Descriptor { get; } = new(ExecutorKey, "Harbor 2.x Docker Compose", "Harbor", "Linux", "SSH",
        SupportedProductVersions: "Harbor 2.x（Docker Compose，已配置 HTTPS）", AuthenticationModes: ["Password", "PrivateKey"],
        MaterialFormats: ["FullChain", "PrivateKey"], SupportsRollback: true);

    /// <summary>供保存、导入与执行共用校验；不访问网络或修改调用方的配置。</summary>
    public static string? ValidateConfiguration(DeploymentTargetConfiguration? configuration)
    {
        if (configuration is null) return "Harbor 部署配置不能为空。";
        var installDirectory = configuration.HarborInstallDirectory ?? "";
        var directory = RemotePathHelper.ValidateAbsolute(installDirectory, false);
        if (!directory.Success || installDirectory.Contains('{') || installDirectory.Contains('}'))
            return "Harbor 安装目录必须是没有模板变量的 Linux 绝对路径。";
        if (configuration.HarborComposeCommand is not ("docker compose" or "docker-compose"))
            return "Harbor Compose 命令仅支持 docker compose 或 docker-compose。";
        if (configuration.HarborProxyService is null || !ServiceName().IsMatch(configuration.HarborProxyService))
            return "Harbor 代理服务名只允许字母、数字、下划线和连字符，且必须以字母或数字开头。";
        var domain = DeploymentSourceBinding.NormalizeDomain(configuration.SourceDomain);
        if (domain.Length is 0 or > 253 || Uri.CheckHostName(domain) != UriHostNameType.Dns || domain.Contains('*') || domain.Any(char.IsWhiteSpace))
            return "请填写有效的 Harbor 绑定域名。";
        if (string.IsNullOrWhiteSpace(configuration.VerificationHost) ||
            Uri.CheckHostName(configuration.VerificationHost) == UriHostNameType.Unknown || configuration.VerificationHost.Any(char.IsWhiteSpace))
            return "请填写 Harbor HTTPS 生效验证的主机或 IP。";
        if (configuration.VerificationPort is < 1 or > 65535)
            return "Harbor HTTPS 生效验证端口必须为 1～65535。";
        if (DeploymentSourceBinding.NormalizeDomain(configuration.VerificationServerName) != domain)
            return "Harbor HTTPS 验证的 SNI 必须与绑定域名一致。";
        if (!string.IsNullOrEmpty(configuration.SourceFormat) || !string.IsNullOrEmpty(configuration.SourceCertificateId))
            return "Harbor 使用规范化完整证书链和私钥，不支持源格式包或旧证书 ID 绑定。";
        if (configuration.Files is null || configuration.Files.Count is not (2 or 4) ||
            configuration.Files.Count(file => file?.Role == "FullChain") != configuration.Files.Count / 2 ||
            configuration.Files.Count(file => file?.Role == "PrivateKey") != configuration.Files.Count / 2 ||
            !configuration.Files.Take(2).Any(file => file?.Role == "FullChain") || !configuration.Files.Take(2).Any(file => file?.Role == "PrivateKey") ||
            configuration.Files.Any(file => file is null || string.IsNullOrWhiteSpace(file.FileName) || !string.IsNullOrEmpty(file.SourceFileName)))
            return "Harbor 必须配置一对完整证书链和私钥，可再增加一对供 prepare 使用的源文件副本；前两项为生效文件。";
        if (configuration.ValidationCommands is not { Count: 0 } || configuration.PostCommands is not { Count: 0 })
            return "Harbor 的验证和代理激活命令由执行器固定生成，不支持自定义命令。";
        if (configuration.BindSites || configuration.SiteIds is not { Length: 0 } || !string.IsNullOrEmpty(configuration.RemoteCertificateId))
            return "Harbor Compose 执行器不支持平台证书 ID 或站点绑定。";
        if (configuration.CreateDirectory)
            return "Harbor 请使用代理账户可访问的已有证书目录，不支持自动创建目录。";
        return null;
    }

    public async Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct)
    {
        var derived = Derive(target);
        if (!derived.Success || derived.Data is null) return Fail<DeploymentConnectionTest>(derived.Code, derived.Message);
        var connected = await files.TestAsync(derived.Data, false, ct);
        if (!connected.Success) return connected;
        var probe = await ProbeAsync(derived.Data, ct);
        return probe.Success && probe.Data is not null
            ? ApiResult<DeploymentConnectionTest>.Ok(new("Harbor " + HarborImage().Match(probe.Data.ProxyImage).Groups[1].Value,
                "SSH、Compose 服务和 Harbor 2.x 代理镜像读取成功；未写入文件、未重建代理，未证明目录可写。",
                ["SftpRead", "HarborComposeRead", "ProxyRecreate", "StrictTlsVerification"]))
            : Fail<DeploymentConnectionTest>(probe.Code, probe.Message);
    }

    public async Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target, CertificateMaterialMetadata material,
        DeploymentSelection selection, CancellationToken ct)
    {
        if (!string.IsNullOrEmpty(selection.RemoteCertificateId) || selection.SiteIds is { Length: > 0 })
            return Fail<DeploymentTargetPlan>("CONFIGURATION_INVALID", "Harbor 不支持平台证书或站点选择。");
        var derived = Derive(target, material);
        if (!derived.Success || derived.Data is null) return Fail<DeploymentTargetPlan>(derived.Code, derived.Message);
        var probe = await ProbeAsync(derived.Data, ct);
        if (!probe.Success || probe.Data is null) return Fail<DeploymentTargetPlan>(probe.Code, probe.Message);
        derived = Derive(target, material, probe.Data);
        if (!derived.Success || derived.Data is null) return Fail<DeploymentTargetPlan>(derived.Code, derived.Message);
        var planned = await files.PlanAsync(derived.Data, material, false, ct);
        if (!planned.Success || planned.Data is null) return planned;
        // 文件前置条件兼容通用 FileState；额外的公开身份快照仅供 Harbor 固定命令和重启恢复使用。
        var preconditions = JsonNode.Parse(planned.Data.PreconditionsJson)!.AsObject();
        preconditions["HarborPlan"] = JsonSerializer.SerializeToNode(probe.Data);
        return ApiResult<DeploymentTargetPlan>.Ok(planned.Data with
        {
            PreconditionsJson = preconditions.ToJsonString(),
            Summary = planned.Data.Summary + $"只重建 Harbor {target.Configuration.HarborProxyService} 代理，并严格校验业务 HTTPS 证书。",
            Warnings = [.. planned.Data.Warnings ?? [], "重建代理时 HTTPS 访问会短暂中断；不停止数据库、registry 或其他服务。",
                "恢复原文件仅恢复证书和私钥；需要另行激活代理并验证 HTTPS，才能确认服务已回到旧证书。",
                .. target.Configuration.Files.Count == 2 ? new[] { "未配置 prepare 源文件副本；请确认 harbor.yml 的 certificate/private_key 源路径已同步更新，防止以后 prepare 覆盖为旧证书。" } : Array.Empty<string>()]
        });
    }

    public async Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct)
    {
        var derived = Derive(context.Target, context.Material.Metadata);
        if (!derived.Success || derived.Data is null) return Fail<DeploymentExecutionResult>(derived.Code, derived.Message);
        var identity = ReadIdentity(context.Plan);
        if (identity is null) return Fail<DeploymentExecutionResult>("PLAN_STALE", "Harbor 代理账户快照缺失或版本无效，请重新生成计划。");
        // 再次确认产品与 Compose 服务，避免在目标被改成其他服务后上传证书。
        var probe = await ProbeAsync(derived.Data, ct);
        if (!probe.Success) return Fail<DeploymentExecutionResult>(probe.Code, probe.Message);
        if (probe.Data != identity)
            return Fail<DeploymentExecutionResult>("PLAN_STALE", "Harbor 代理镜像或运行账户已变化，请重新生成计划。");
        derived = Derive(context.Target, context.Material.Metadata, identity);
        if (!derived.Success || derived.Data is null) return Fail<DeploymentExecutionResult>(derived.Code, derived.Message);
        return await files.ExecuteAsync(WithTarget(context, derived.Data), false, ct);
    }

    public Task<ApiResult<DeploymentRecoveryResult>> RecoverAsync(DeploymentExecutionContext context, CancellationToken ct)
    {
        var identity = ReadIdentity(context.Plan);
        if (identity is null)
            return Task.FromResult(Fail<DeploymentRecoveryResult>("PLAN_STALE", "Harbor 代理账户快照缺失或版本无效，不能猜测文件属主。"));
        var derived = Derive(context.Target, context.Material.Metadata, identity);
        // 恢复直接使用原计划冻结的账户，不依赖尚未恢复权限、可能已停止的代理容器。
        return derived.Success && derived.Data is not null
            ? files.RecoverAsync(WithTarget(context, derived.Data), false, ct)
            : Task.FromResult(Fail<DeploymentRecoveryResult>(derived.Code, derived.Message));
    }

    public Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct)
    {
        var derived = Derive(context.Target, context.Material);
        return derived.Success && derived.Data is not null
            ? files.InspectAsync(context with { Target = derived.Data }, false, ct)
            : Task.FromResult(Fail<DeploymentInspection>(derived.Code, derived.Message));
    }

    public async Task<ApiResult<DeploymentRollbackResult>> RollbackAsync(DeploymentRollbackContext context, CancellationToken ct)
    {
        var derived = Derive(context.Target);
        if (!derived.Success || derived.Data is null) return Fail<DeploymentRollbackResult>(derived.Code, derived.Message);
        var restored = await files.RollbackAsync(context with { Target = derived.Data }, ct);
        return restored.Success
            ? ApiResult<DeploymentRollbackResult>.Ok(new("原证书和私钥文件已恢复；尚未激活 Harbor 代理，当前服务可能仍使用新证书。请另行激活代理并验证 HTTPS。"))
            : restored;
    }

    private static ApiResult<DeploymentTargetContext> Derive(DeploymentTargetContext target, CertificateMaterialMetadata? material = null,
        HarborPlanIdentity? identity = null)
    {
        var error = ValidateConfiguration(target.Configuration);
        if (error is not null) return Fail<DeploymentTargetContext>("CONFIGURATION_INVALID", error);
        var domain = DeploymentSourceBinding.NormalizeDomain(target.Configuration.SourceDomain);
        if (material is not null && (DeploymentSourceBinding.NormalizeDomain(material.Domain) != domain ||
            !material.Domains.Any(name => DeploymentSourceBinding.NormalizeDomain(name) == domain)))
            return Fail<DeploymentTargetContext>("SOURCE_CERTIFICATE_MISMATCH", "Harbor 绑定域名与所选证书的主域名或域名范围不一致。");
        // 克隆只含公开参数的配置，禁止把固定命令回写到持久化目标或原始任务快照。
        var configuration = JsonSerializer.Deserialize<DeploymentTargetConfiguration>(JsonSerializer.Serialize(target.Configuration))!;
        configuration.Shell = "sh";
        configuration.VerificationServerName = domain;
        var compose = configuration.HarborComposeCommand;
        var service = RemoteCommandHelper.PosixQuote(configuration.HarborProxyService);
        // 官方 nginx-photon 使用非 root 账户；权限使用预览时冻结的数字账户，重启恢复不再依赖活动容器。
        var fileArguments = string.Join(" ", Enumerable.Range(1, configuration.Files.Count).Select(index => "{file" + index + "Path}"));
        var ownership = identity is null ? "" : "\nchown -- " + identity.Uid.ToString(CultureInfo.InvariantCulture) + ":" +
            identity.Gid.ToString(CultureInfo.InvariantCulture) + " " + fileArguments;
        configuration.ValidationCommands = [new(MaterialValidation + ownership, configuration.HarborInstallDirectory, 60)];
        var activation = $"{compose} up -d --no-deps --force-recreate {service} >/dev/null 2>&1\n" +
            $"attempt=0\nwhile [ \"$attempt\" -lt 30 ]; do\n" +
            $"  if {compose} exec -T {service} nginx -t >/dev/null 2>&1; then exit 0; fi\n" +
            "  attempt=$((attempt + 1))\n  sleep 1\ndone\nexit 1";
        configuration.PostCommands = [new(activation, configuration.HarborInstallDirectory,
            Math.Clamp(configuration.OperationTimeoutSeconds, 90, 1800), RetryOnInterruption: false)];
        return ApiResult<DeploymentTargetContext>.Ok(new()
        {
            Id = target.Id, Name = target.Name, ExecutorKey = target.ExecutorKey, ExecutorRevision = target.ExecutorRevision,
            Endpoint = target.Endpoint, Port = target.Port, Username = target.Username, AuthenticationMode = target.AuthenticationMode,
            TlsFingerprint = target.TlsFingerprint, ConfigRevision = target.ConfigRevision, Credentials = target.Credentials,
            Configuration = configuration
        });
    }

    private async Task<ApiResult<HarborPlanIdentity>> ProbeAsync(DeploymentTargetContext target, CancellationToken ct)
    {
        var connected = await transport.ConnectAsync(target, ct);
        if (!connected.Success || connected.Data is null) return Fail<HarborPlanIdentity>(connected.Code, connected.Message);
        await using var session = connected.Data;
        try
        {
            var path = target.Configuration.HarborInstallDirectory;
            for (var depth = 0; ; depth++)
            {
                var directory = await session.StatAsync(path, ct);
                if (depth >= 64 || !directory.Exists || !directory.IsDirectory || directory.IsSymbolicLink)
                    return Fail<HarborPlanIdentity>("CONFIGURATION_INVALID", "Harbor 安装目录或父目录不存在、不是普通目录或层级过深。");
                if (path == "/") break;
                path = RemotePathHelper.Parent(path);
            }
            var compose = target.Configuration.HarborComposeCommand;
            var service = RemoteCommandHelper.PosixQuote(target.Configuration.HarborProxyService);
            // 严格只输出镜像、UID、GID 三行；不读取完整容器配置、环境或秘密文件。
            var script = $"{compose} version >/dev/null 2>&1\nopenssl version >/dev/null 2>&1\n" +
                $"{compose} config --services 2>/dev/null | grep -Fx -- {service} >/dev/null\n" +
                $"container=$({compose} ps -q {service} 2>/dev/null)\n[ -n \"$container\" ]\n" +
                "docker inspect --format '{{.Config.Image}}' \"$container\" 2>/dev/null\n" +
                $"{compose} exec -T {service} id -u 2>/dev/null\n" +
                $"{compose} exec -T {service} id -g 2>/dev/null";
            var command = RemoteCommandHelper.Build(new(script, target.Configuration.HarborInstallDirectory, 30), "sh", false,
                new Dictionary<string, string>());
            if (!command.Success || command.Data is null) return Fail<HarborPlanIdentity>(command.Code, command.Message);
            var result = await session.ExecuteAsync(command.Data, 30, ct);
            if (!result.OutcomeKnown || result.ExitCode != 0)
                return Fail<HarborPlanIdentity>("HARBOR_PROBE_FAILED", "无法读取 Harbor Compose、OpenSSL 或运行中的代理，请核对安装目录、服务名和 Docker 权限。");
            var rows = result.Output.Trim().Replace("\r", "").Split('\n');
            if (rows.Length != 3 || result.Output.Length > 1024 || !TryAccount(rows[1], out var uid) || !TryAccount(rows[2], out var gid))
                return Fail<HarborPlanIdentity>("HARBOR_PROBE_FAILED", "Harbor 代理镜像或运行账户返回格式无效，不能安全确定证书属主。");
            return HarborImage().IsMatch(rows[0]) ? ApiResult<HarborPlanIdentity>.Ok(new(1, rows[0], uid, gid))
                : Fail<HarborPlanIdentity>("HARBOR_VERSION_UNSUPPORTED", "仅支持带明确 Harbor 2.x 版本标签的 nginx-photon 代理镜像，请核对实际安装方式。");
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or Renci.SshNet.Common.SshException or UnauthorizedAccessException)
        { return Fail<HarborPlanIdentity>("HARBOR_PROBE_FAILED", "Harbor 只读探测失败，请核对 SSH、Compose 服务和 Docker 权限。"); }
    }

    private static HarborPlanIdentity? ReadIdentity(DeploymentTargetPlan plan)
    {
        try
        {
            using var json = JsonDocument.Parse(plan.PreconditionsJson);
            if (!json.RootElement.TryGetProperty("HarborPlan", out var snapshot) || snapshot.ValueKind != JsonValueKind.Object ||
                !snapshot.TryGetProperty("SchemaVersion", out var version) || !version.TryGetInt32(out var number) || number != 1 ||
                !snapshot.TryGetProperty("ProxyImage", out var image) || image.ValueKind != JsonValueKind.String ||
                !snapshot.TryGetProperty("Uid", out var uid) || !uid.TryGetUInt32(out var user) || user == uint.MaxValue ||
                !snapshot.TryGetProperty("Gid", out var gid) || !gid.TryGetUInt32(out var group) || group == uint.MaxValue)
                return null;
            var proxyImage = image.GetString();
            return proxyImage is not null && proxyImage.Length <= 512 && HarborImage().IsMatch(proxyImage)
                ? new(1, proxyImage, user, group) : null;
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException)
        { return null; }
    }

    private static bool TryAccount(string value, out uint account) =>
        uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out account) && account != uint.MaxValue;

    private sealed record HarborPlanIdentity(int SchemaVersion, string ProxyImage, uint Uid, uint Gid);

    private static DeploymentExecutionContext WithTarget(DeploymentExecutionContext context, DeploymentTargetContext target) => new()
    {
        TaskId = context.TaskId, Target = target, Material = context.Material, Plan = context.Plan,
        ReportProgressAsync = context.ReportProgressAsync, IsRecovery = context.IsRecovery,
        ReceiptJson = context.ReceiptJson, SaveCheckpointAsync = context.SaveCheckpointAsync,
        BeforeExternalMutationAsync = context.BeforeExternalMutationAsync
    };

    // 只在远端 shell 内存比较公钥，不输出材料正文；每条解析命令失败都会阻止代理重建。
    private const string MaterialValidation = "openssl x509 -in {fullchainPath} -noout >/dev/null\n" +
        "openssl pkey -in {keyPath} -noout >/dev/null\n" +
        "certificate_key=$(openssl x509 -in {fullchainPath} -pubkey -noout)\n" +
        "private_key=$(openssl pkey -in {keyPath} -pubout)\n" +
        "if [ -z \"$certificate_key\" ] || [ \"$certificate_key\" != \"$private_key\" ]; then exit 1; fi";

    private static ApiResult<T> Fail<T>(string code, string message) => ApiResult<T>.Fail(code, message);
    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex ServiceName();
    [GeneratedRegex(@"^(?:[A-Za-z0-9._:-]+/)*nginx-photon:(v?2\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?)(?:@sha256:[a-fA-F0-9]{64})?$", RegexOptions.CultureInvariant)]
    private static partial Regex HarborImage();
}
