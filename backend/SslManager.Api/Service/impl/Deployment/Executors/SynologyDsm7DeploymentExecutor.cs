using System.Security.Cryptography;
using System.Text.Json;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service.impl.Deployment;

namespace SslManager.Api.Service.impl;

/// <summary>群晖 DSM 7.x 证书导入；原位替换仅保留服务关联，不主动调整默认项或服务配置。</summary>
public sealed class SynologyDsm7DeploymentExecutor(SynologyDsmApiClient clients)
    : IDeploymentExecutor, IDeploymentDiscoveryExecutor, IDeploymentRecoveryExecutor
{
    // 群晖以证书和完整链读回一致为部署成功依据，服务 HTTPS 观察只补充提示。
    private const string TlsObservationWarning = "业务 HTTPS 生效检查未通过，仅作提示，不影响证书部署成功。";

    public DeploymentExecutorDescriptor Descriptor => new("synology.dsm.7.x", "群晖 DSM 7.x", "Synology", "DSM", "HTTPS",
        SupportedProductVersions: "DSM 7.x（API 能力探测；具体设备需连接测试）",
        AuthenticationModes: ["Password"], MaterialFormats: ["Leaf", "Chain", "PrivateKey"]);

    public async Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct)
    {
        var discovery = await DiscoverAsync(target, ct);
        return discovery.Success && discovery.Data is not null
            ? ApiResult<DeploymentConnectionTest>.Ok(new(discovery.Data.ProductVersion,
                $"连接与读取成功，发现 {discovery.Data.Certificates.Count} 张证书、{discovery.Data.Sites.Count} 个关联服务；未导入证书。",
                ["CertificateRead", "ServiceRead", "PasswordLogin"]))
            : Fail<DeploymentConnectionTest, DeploymentDiscovery>(discovery);
    }

    public async Task<ApiResult<DeploymentDiscovery>> DiscoverAsync(DeploymentTargetContext target, CancellationToken ct)
    {
        var opened = await clients.OpenAsync(target, ct);
        if (!opened.Success || opened.Data is null) return Fail<DeploymentDiscovery, SynologyDsmSession>(opened);
        await using var session = opened.Data;
        var read = await ReadStateAsync(session, ct);
        if (!read.Success || read.Data is null) return Fail<DeploymentDiscovery, RemoteCertificate[]>(read);
        var certificates = read.Data.Select(cert => new DeploymentRemoteCertificate(cert.Id,
            string.IsNullOrWhiteSpace(cert.Description) ? cert.Id : cert.Description, cert.Domains,
            RelatedSiteIds: cert.Services.Select(service => service.Id).ToArray())).ToArray();
        var services = read.Data.SelectMany(cert => cert.Services.Select(service =>
            new DeploymentRemoteSite(service.Id, service.Name, [], cert.Id))).ToArray();
        return ApiResult<DeploymentDiscovery>.Ok(new(certificates, services, session.ProductVersion));
    }

    public async Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target,
        CertificateMaterialMetadata material, DeploymentSelection selection, CancellationToken ct)
    {
        if (target.Configuration.BindSites || target.Configuration.SiteIds.Length > 0 || selection.SiteIds is { Length: > 0 })
            return ApiResult<DeploymentTargetPlan>.Fail("VALIDATION", "群晖首版保留已有服务关联，不支持修改服务绑定。");
        var opened = await clients.OpenAsync(target, ct);
        if (!opened.Success || opened.Data is null) return Fail<DeploymentTargetPlan, SynologyDsmSession>(opened);
        await using var session = opened.Data;
        var read = await ReadStateAsync(session, ct);
        if (!read.Success || read.Data is null) return Fail<DeploymentTargetPlan, RemoteCertificate[]>(read);
        var state = read.Data;
        var remoteId = selection.UseConfiguredRemoteCertificateId && string.IsNullOrEmpty(selection.RemoteCertificateId)
            ? target.Configuration.RemoteCertificateId : selection.RemoteCertificateId;
        var description = string.IsNullOrWhiteSpace(target.Configuration.CertificateDescription)
            ? material.Domain : target.Configuration.CertificateDescription.Trim();
        var action = "Create";
        var oldFingerprint = "";
        var oldDigest = "";
        var selected = state.SingleOrDefault(cert => cert.Id == remoteId);
        var warnings = new List<string>
        {
            "本执行器不提供旧证书材料回滚；服务实际使用的新证书可通过 HTTPS 生效验证核对。"
        };
        if (selected is null)
        {
            // 远端 ID 可能因手动删除后重新导入而失效；按稳定描述找回，找不到则新增。
            var matches = state.Where(cert => string.Equals(cert.Description, description, StringComparison.Ordinal)).ToArray();
            if (matches.Length > 1)
                return ApiResult<DeploymentTargetPlan>.Fail("RESOURCE_AMBIGUOUS", "群晖存在多张相同描述的证书，请明确选择要更新的远端证书。");
            selected = matches.SingleOrDefault();
            if (!string.IsNullOrEmpty(remoteId))
                warnings.Add(selected is null ? "原远端证书已不存在，本次将新增证书。" : "原远端证书已不存在，本次更新描述一致的证书。");
            // 计划和后台复核都保存实际定位结果，新增时不能将失效 ID 传入 DSM。
            remoteId = selected?.Id ?? "";
        }
        if (selected is not null)
        {
            var exported = await session.ExportCertificateAsync(remoteId, ct);
            if (!exported.Success || exported.Data is null) return Fail<DeploymentTargetPlan, SynologyCertificateReadback>(exported);
            oldFingerprint = exported.Data.Fingerprint;
            oldDigest = exported.Data.MaterialDigest;
            description = selected.Description;
            action = oldFingerprint == material.Fingerprint && oldDigest == material.MaterialDigest ? "Skip" : "Update";
            if (selected.Services.Length > 0)
                warnings.Add("保留以下服务关联：" + string.Join("、", selected.Services.Select(service => service.Name)) + "。DSM 服务列表不保证提供各服务访问域名，请核对新证书覆盖范围。");
            var removed = exported.Data.Domains.Where(domain => !Covers(material.Domains, domain)).ToArray();
            if (removed.Length > 0)
                warnings.Add("新证书不再覆盖原证书的以下域名：" + string.Join("、", removed) + "。请确认使用这些域名的服务影响。");
            if (selected.IsDefault) warnings.Add("所选证书是 DSM 默认证书；替换后仍为默认，DSM 管理连接可能短暂中断。");
        }
        else if (!string.IsNullOrWhiteSpace(target.Configuration.VerificationHost))
            warnings.Add("新增证书不会自动分配给服务；HTTPS 生效检查仅作提示，证书和证书链读回一致即部署成功。");
        var conditions = new Preconditions(remoteId, description, oldFingerprint, oldDigest,
            state.Select(ToCondition).OrderBy(cert => cert.Id, StringComparer.Ordinal).ToArray());
        var summary = action switch
        {
            "Skip" => $"证书 {remoteId} 的证书和证书链已一致，核对关联后跳过上传。",
            "Update" => $"替换群晖证书 {remoteId}（{description}），保留 {selected!.Services.Length} 个服务关联和原默认状态。",
            _ => $"新增群晖证书（{description}）；不设为默认，不主动绑定服务。"
        };
        // 同一 DSM 实例串行，防止两个目标同时更换默认管理证书或影响同一服务。
        return ApiResult<DeploymentTargetPlan>.Ok(new("synology:" + SynologyDsmApiClient.BaseUri(target).Authority.ToLowerInvariant(),
            action, summary, JsonSerializer.Serialize(conditions), remoteId,
            SiteIds: [], Warnings: warnings.ToArray()));
    }

    public async Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct)
    {
        var conditions = ReadConditions(context.Plan);
        if (conditions is null || context.Plan.Action is not ("Create" or "Update" or "Skip") ||
            context.Plan.RemoteResourceId != conditions.CertificateId ||
            (context.Plan.Action == "Create") != string.IsNullOrEmpty(conditions.CertificateId))
            return ApiResult<DeploymentExecutionResult>.Fail("PLAN_STALE", "群晖部署计划无效，请重新预览。");
        var opened = await clients.OpenAsync(context.Target, ct);
        if (!opened.Success || opened.Data is null) return Fail<DeploymentExecutionResult, SynologyDsmSession>(opened);
        await using var session = opened.Data;
        var checkpoint = PlatformDeploymentCheckpoint.Read(context.ReceiptJson);
        if (checkpoint.Corrupt || checkpoint.SchemaVersion is < 0 or > 1)
            return ApiResult<DeploymentExecutionResult>.Fail("RECOVERY_RECEIPT_INVALID", "平台回执已损坏或版本不支持，不能推断尚未提交。");
        if (!context.IsRecovery)
        {
            checkpoint = PlatformDeploymentCheckpoint.Prepared(context.Plan);
            await checkpoint.SaveAsync(context, "Prepared", ct);
        }
        var remoteId = string.IsNullOrEmpty(checkpoint.RemoteId) ? conditions.CertificateId : checkpoint.RemoteId;
        var alreadyUploaded = false;
        if (context.IsRecovery)
        {
            if (string.IsNullOrEmpty(remoteId))
            {
                var found = await FindCreatedAsync(session, conditions, ct);
                if (found.Success && !string.IsNullOrEmpty(found.Data)) remoteId = found.Data;
                else if (checkpoint.UploadStarted)
                    return ApiResult<DeploymentExecutionResult>.Fail("REMOTE_RESULT_UNKNOWN", "原群晖导入尚未唯一核对，继续查询而不重复导入。");
            }
            if (!string.IsNullOrEmpty(remoteId))
            {
                var existing = await session.ExportCertificateAsync(remoteId, ct);
                if (!existing.Success || existing.Data is null) return Fail<DeploymentExecutionResult, SynologyCertificateReadback>(existing);
                alreadyUploaded = existing.Data.Fingerprint == context.Material.Metadata.Fingerprint && existing.Data.MaterialDigest == context.Material.Metadata.MaterialDigest;
            }
        }
        if (!alreadyUploaded)
        {
            if (context.IsRecovery && !checkpoint.CanStart)
                return ApiResult<DeploymentExecutionResult>.Fail(checkpoint.UploadStarted ? "REMOTE_RESULT_UNKNOWN" : "RECOVERY_EVIDENCE_MISSING",
                    "原导入缺少尚未提交的明确证明，只继续核对原资源，不重复导入。");
            var check = await CheckPreconditionsAsync(session, conditions, ct);
            if (!check.Success) return Fail<DeploymentExecutionResult, bool>(check);
        }
        ApiResult<DeploymentExecutionResult> AfterWriteFailure(string code, string message, string level = "None") =>
            new(false, code, message, new(message, remoteId, context.Material.Metadata.Fingerprint, level,
                ReceiptJson: checkpoint.Serialize()));
        if (context.Plan.Action != "Skip" && !alreadyUploaded)
        {
            var wasDefault = conditions.Certificates.SingleOrDefault(cert => cert.Id == remoteId)?.IsDefault == true;
            checkpoint.RemoteId = remoteId; checkpoint.Action = context.Plan.Action; checkpoint.UploadStarted = true; checkpoint.SubmissionState = "Submitting";
            await checkpoint.SaveAsync(context, "UploadIntent", ct);
            await context.ReportProgressAsync("Uploading", string.IsNullOrEmpty(remoteId) ? "正在向群晖导入新证书。" : "正在原位替换群晖证书并保留服务关联。", ct);
            if (context.BeforeExternalMutationAsync is not null) await context.BeforeExternalMutationAsync(ct);
            var imported = await session.ImportCertificateAsync(context.Material, remoteId, conditions.Description, wasDefault, ct);
            if (!imported.Success) return AfterWriteFailure(imported.Code, imported.Message);
            // 导入响应可能没有 ID；以计划前的 ID 集合和导入后的描述唯一定位新增资源。
            if (string.IsNullOrEmpty(remoteId))
            {
                var found = await FindCreatedAsync(session, conditions, ct);
                if (!found.Success || string.IsNullOrEmpty(found.Data))
                    return AfterWriteFailure("REMOTE_RESULT_UNKNOWN", "群晖已接收导入，但无法唯一定位新增证书，请先核对远端结果。");
                remoteId = found.Data;
            }
        }
        checkpoint.SchemaVersion = 1; checkpoint.UploadStarted = true; checkpoint.RemoteId = remoteId; checkpoint.UploadCompleted = true; checkpoint.SubmissionState = "Completed";
        await checkpoint.SaveAsync(context, "Uploaded", ct);
        await context.ReportProgressAsync("Verifying", "正在读回证书、证书链、默认状态和服务关联。", ct);
        var inspected = await InspectWithSessionAsync(session, conditions, remoteId, context.Material.Metadata, ct);
        if (!inspected.Success || inspected.Data?.MatchesExpected != true)
            return context.Plan.Action == "Skip"
                ? ApiResult<DeploymentExecutionResult>.Fail("PLAN_STALE", "跳过上传前核对失败，请重新预览。")
                : AfterWriteFailure(context.IsRecovery && inspected.Success && inspected.Data?.MatchesExpected == false ? "RECOVERY_CONFLICT" : "REMOTE_RESULT_UNKNOWN",
                    "群晖导入后的证书或服务关联未确认一致，请核对远端结果。系统不会自动重复上传。");
        var verification = "PlatformReadback";
        var message = context.Plan.Action switch
        {
            "Skip" => "群晖证书、证书链和服务关联已核对，跳过重复上传。",
            "Create" => "群晖证书已新增，证书链与原有服务关联已核对。",
            _ => "群晖证书和证书链已更新，默认状态与原有服务关联已核对。"
        };
        if (!string.IsNullOrWhiteSpace(context.Target.Configuration.VerificationHost))
        {
            var tls = await DeploymentTlsVerification.VerifyAsync(context.Target.Configuration, context.Material.Metadata, ct);
            if (tls.Success) verification = "TlsObserved";
            else message += TlsObservationWarning;
        }
        return ApiResult<DeploymentExecutionResult>.Ok(new(message,
            remoteId, context.Material.Metadata.Fingerprint, verification, Skipped: context.Plan.Action == "Skip",
            ReceiptJson: checkpoint.Serialize()));
    }

    public async Task<ApiResult<DeploymentRecoveryResult>> RecoverAsync(DeploymentExecutionContext context, CancellationToken ct) =>
        PlatformDeploymentRecovery.FromExecution(await ExecuteAsync(context, ct));

    public async Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct)
    {
        var conditions = ReadConditions(context.Plan);
        if (conditions is null) return ApiResult<DeploymentInspection>.Fail("PLAN_STALE", "群晖部署计划无效。");
        var opened = await clients.OpenAsync(context.Target, ct);
        if (!opened.Success || opened.Data is null) return Fail<DeploymentInspection, SynologyDsmSession>(opened);
        await using var session = opened.Data;
        var remoteId = conditions.CertificateId;
        if (string.IsNullOrEmpty(remoteId))
        {
            var found = await FindCreatedAsync(session, conditions, ct);
            if (!found.Success || string.IsNullOrEmpty(found.Data)) return Fail<DeploymentInspection, string>(found);
            remoteId = found.Data;
        }
        var inspected = await InspectWithSessionAsync(session, conditions, remoteId, context.Material, ct);
        if (!inspected.Success || inspected.Data?.MatchesExpected != true || string.IsNullOrWhiteSpace(context.Target.Configuration.VerificationHost))
            return inspected;
        var tls = await DeploymentTlsVerification.VerifyAsync(context.Target.Configuration, context.Material, ct);
        return tls.Success
            ? ApiResult<DeploymentInspection>.Ok(inspected.Data with { VerificationLevel = "TlsObserved", Message = "群晖证书、关联与业务 HTTPS 生效均已核对。" })
            : ApiResult<DeploymentInspection>.Ok(inspected.Data with { Message = inspected.Data.Message + TlsObservationWarning });
    }

    private static async Task<ApiResult<bool>> CheckPreconditionsAsync(SynologyDsmSession session, Preconditions expected, CancellationToken ct)
    {
        var read = await ReadStateAsync(session, ct);
        if (!read.Success || read.Data is null) return Fail<bool, RemoteCertificate[]>(read);
        var current = read.Data.Select(ToCondition).OrderBy(cert => cert.Id, StringComparer.Ordinal).ToArray();
        if (!current.SequenceEqual(expected.Certificates))
            return ApiResult<bool>.Fail("PLAN_STALE", "群晖证书列表、默认状态或服务关联已变化，请重新预览。");
        if (!string.IsNullOrEmpty(expected.CertificateId))
        {
            var exported = await session.ExportCertificateAsync(expected.CertificateId, ct);
            if (!exported.Success || exported.Data is null) return Fail<bool, SynologyCertificateReadback>(exported);
            if (exported.Data.Fingerprint != expected.Fingerprint || exported.Data.MaterialDigest != expected.MaterialDigest)
                return ApiResult<bool>.Fail("PLAN_STALE", "群晖远端证书材料在预览后发生变化，请重新预览。");
        }
        return ApiResult<bool>.Ok(true);
    }

    private static async Task<ApiResult<DeploymentInspection>> InspectWithSessionAsync(SynologyDsmSession session,
        Preconditions expected, string remoteId, CertificateMaterialMetadata material, CancellationToken ct)
    {
        var read = await ReadStateAsync(session, ct);
        if (!read.Success || read.Data is null) return Fail<DeploymentInspection, RemoteCertificate[]>(read);
        var current = read.Data;
        var target = current.SingleOrDefault(cert => cert.Id == remoteId);
        if (target is null) return ApiResult<DeploymentInspection>.Ok(new(false, "未找到本次部署的群晖证书。"));
        var previous = expected.Certificates.SingleOrDefault(cert => cert.Id == remoteId);
        var untouched = current.Where(cert => cert.Id != remoteId).Select(ToCondition).OrderBy(cert => cert.Id, StringComparer.Ordinal);
        if (!untouched.SequenceEqual(expected.Certificates.Where(cert => cert.Id != remoteId)) ||
            target.Description != expected.Description || target.IsDefault != (previous?.IsDefault ?? false) ||
            (previous is null ? target.Services.Length != 0 : target.ServicesDigest != previous.ServicesDigest))
            return ApiResult<DeploymentInspection>.Ok(new(false, "群晖默认状态或服务关联与部署计划不一致。"));
        var exported = await session.ExportCertificateAsync(remoteId, ct);
        if (!exported.Success || exported.Data is null) return Fail<DeploymentInspection, SynologyCertificateReadback>(exported);
        if (exported.Data.Fingerprint != material.Fingerprint || exported.Data.MaterialDigest != material.MaterialDigest)
            return ApiResult<DeploymentInspection>.Ok(new(false, "读回的群晖证书或证书链与本次材料不一致。", exported.Data.Fingerprint));
        return ApiResult<DeploymentInspection>.Ok(new(true, "群晖证书、证书链、默认状态与服务关联已核对。", exported.Data.Fingerprint, "PlatformReadback"));
    }

    private static async Task<ApiResult<string>> FindCreatedAsync(SynologyDsmSession session, Preconditions expected, CancellationToken ct)
    {
        var read = await ReadStateAsync(session, ct);
        if (!read.Success || read.Data is null) return Fail<string, RemoteCertificate[]>(read);
        var before = expected.Certificates.Select(cert => cert.Id).ToHashSet(StringComparer.Ordinal);
        var candidates = read.Data.Where(cert => !before.Contains(cert.Id) && cert.Description == expected.Description).ToArray();
        return candidates.Length == 1 ? ApiResult<string>.Ok(candidates[0].Id) :
            ApiResult<string>.Fail("RESOURCE_AMBIGUOUS", "无法唯一定位本次新增的群晖证书，请在 DSM 中核对。");
    }

    private static async Task<ApiResult<RemoteCertificate[]>> ReadStateAsync(SynologyDsmSession session, CancellationToken ct)
    {
        var response = await session.ListCertificatesAsync(ct);
        if (!response.Success) return Fail<RemoteCertificate[], JsonElement>(response);
        try
        {
            var items = response.Data.GetProperty("certificates");
            if (items.ValueKind != JsonValueKind.Array || items.GetArrayLength() > 1000) return Protocol<RemoteCertificate[]>();
            var result = new List<RemoteCertificate>();
            foreach (var item in items.EnumerateArray())
            {
                var id = item.GetProperty("id").GetString();
                var description = item.GetProperty("desc").GetString();
                var isDefault = item.GetProperty("is_default").GetBoolean();
                var services = item.GetProperty("services");
                if (string.IsNullOrWhiteSpace(id) || id.Length > 128 || description is null || services.ValueKind != JsonValueKind.Array)
                    return Protocol<RemoteCertificate[]>();
                var mapped = new List<RemoteService>();
                foreach (var service in services.EnumerateArray())
                {
                    if (service.ValueKind != JsonValueKind.Object || !service.TryGetProperty("service", out var serviceName) ||
                        serviceName.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(serviceName.GetString()))
                        return Protocol<RemoteCertificate[]>();
                    var display = service.TryGetProperty("display_name", out var label) && label.ValueKind == JsonValueKind.String
                        ? label.GetString() : null;
                    mapped.Add(new(Digest(service), string.IsNullOrWhiteSpace(display) ? serviceName.GetString()! : display));
                }
                var domains = new List<string>();
                if (item.TryGetProperty("subject", out var subject) && subject.ValueKind == JsonValueKind.Object &&
                    subject.TryGetProperty("common_name", out var commonName) && commonName.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(commonName.GetString()))
                    domains.Add(commonName.GetString()!);
                if (item.TryGetProperty("subject_alt_name", out var names) && names.ValueKind == JsonValueKind.Array)
                    domains.AddRange(names.EnumerateArray().Where(name => name.ValueKind == JsonValueKind.String).Select(name => name.GetString()!));
                var serviceDigest = JsonSerializer.Serialize(services.EnumerateArray().Select(Digest).Order(StringComparer.Ordinal));
                result.Add(new(id, description, isDefault, mapped.ToArray(), serviceDigest, Digest(item), domains.Distinct(StringComparer.OrdinalIgnoreCase).ToArray()));
            }
            if (result.Select(cert => cert.Id).Distinct(StringComparer.Ordinal).Count() != result.Count) return Protocol<RemoteCertificate[]>();
            if (response.Data.TryGetProperty("total", out var total) && (!total.TryGetInt32(out var count) || count != result.Count)) return Protocol<RemoteCertificate[]>();
            return ApiResult<RemoteCertificate[]>.Ok(result.ToArray());
        }
        catch (Exception ex) when (ex is InvalidOperationException or KeyNotFoundException or JsonException)
        { return Protocol<RemoteCertificate[]>(); }
    }

    // JSON 对象字段顺序不应影响前置条件；服务顺序同样不影响关联范围。
    private static object? Canonical(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Object => value.EnumerateObject().OrderBy(property => property.Name, StringComparer.Ordinal)
            .ToDictionary(property => property.Name, property => Canonical(property.Value)),
        JsonValueKind.Array => value.EnumerateArray().Select(Canonical).OrderBy(item => JsonSerializer.Serialize(item), StringComparer.Ordinal).ToArray(),
        _ => value.Clone()
    };
    private static string Digest(JsonElement value) => Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(Canonical(value))));
    private static CertificateCondition ToCondition(RemoteCertificate cert) => new(cert.Id, cert.Description, cert.IsDefault, cert.ServicesDigest, cert.StateDigest);
    private static Preconditions? ReadConditions(DeploymentTargetPlan plan)
    {
        try
        {
            var value = JsonSerializer.Deserialize<Preconditions>(plan.PreconditionsJson);
            return value?.Certificates is not null && value.Certificates.All(cert => cert is not null) ? value : null;
        }
        catch (JsonException) { return null; }
    }
    private static bool Covers(IEnumerable<string> domains, string name)
    {
        var normalized = name.TrimEnd('.').ToLowerInvariant();
        return domains.Select(domain => domain.TrimEnd('.').ToLowerInvariant()).Any(domain => domain == normalized ||
            (!normalized.StartsWith("*.", StringComparison.Ordinal) && domain.StartsWith("*.", StringComparison.Ordinal) &&
             normalized.EndsWith(domain[1..], StringComparison.Ordinal) && normalized.Count(c => c == '.') == domain.Count(c => c == '.')));
    }
    private static ApiResult<T> Fail<T, TSource>(ApiResult<TSource> result) => ApiResult<T>.Fail(result.Code, result.Message);
    private static ApiResult<T> Protocol<T>() => ApiResult<T>.Fail("SYNOLOGY_PROTOCOL_UNSUPPORTED", "群晖证书或服务列表格式不兼容，已停止操作。");
    private sealed record RemoteService(string Id, string Name);
    private sealed record RemoteCertificate(string Id, string Description, bool IsDefault, RemoteService[] Services, string ServicesDigest, string StateDigest, string[] Domains);
    private sealed record CertificateCondition(string Id, string Description, bool IsDefault, string ServicesDigest, string StateDigest);
    private sealed record Preconditions(string CertificateId, string Description, string Fingerprint, string MaterialDigest, CertificateCondition[] Certificates);
}
