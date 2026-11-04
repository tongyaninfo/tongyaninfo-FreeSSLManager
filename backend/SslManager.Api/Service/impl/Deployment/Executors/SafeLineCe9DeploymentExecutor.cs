using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service.impl.Deployment;

namespace SslManager.Api.Service.impl;

/// <summary>雷池社区版 9.x 证书执行器；证书资源和站点绑定分别核对。</summary>
public sealed class SafeLineCe9DeploymentExecutor(SafeLineCe9ApiClient clients)
    : IDeploymentExecutor, IDeploymentDiscoveryExecutor, IDeploymentRecoveryExecutor
{
    // 雷池以平台证书和完整链读回一致为成功依据，业务 HTTPS 观察失败仅补充提示。
    private const string TlsObservationWarning = "业务 HTTPS 生效检查未通过，仅作提示，不影响证书部署成功。";

    public DeploymentExecutorDescriptor Descriptor => new("safeline.ce.9.x", "雷池社区版 9.x.x",
        "SafeLine", "", "HTTPS", SupportedProductVersions: "9.x.x（已只读验证 9.3.9）",
        AuthenticationModes: ["Password", "ApiToken"], MaterialFormats: ["FullChain", "PrivateKey"]);

    public async Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct)
    {
        var discovery = await DiscoverAsync(target, ct);
        return discovery.Success && discovery.Data is not null
            ? ApiResult<DeploymentConnectionTest>.Ok(new(discovery.Data.ProductVersion,
                $"连接与读取成功，发现 {discovery.Data.Certificates.Count} 张证书、{discovery.Data.Sites.Count} 个站点；未执行写操作。",
                ["CertificateRead", "SiteRead", "PasswordAesLogin"]))
            : Fail<DeploymentConnectionTest, DeploymentDiscovery>(discovery);
    }

    public async Task<ApiResult<DeploymentDiscovery>> DiscoverAsync(DeploymentTargetContext target, CancellationToken ct)
    {
        var opened = await clients.OpenAsync(target, ct);
        if (!opened.Success || opened.Data is null) return Fail<DeploymentDiscovery, SafeLineCe9Session>(opened);
        using var session = opened.Data;
        var state = await ReadStateAsync(session, ct);
        if (!state.Success || state.Data is null) return Fail<DeploymentDiscovery, RemoteState>(state);
        var sites = state.Data.Sites.Select(site => new DeploymentRemoteSite(
            Id(site, "id"), string.Join(", ", Strings(site, "server_names")),
            Strings(site, "server_names"), Id(site, "cert_id"))).ToArray();
        var certs = state.Data.Certificates.Select(cert => new DeploymentRemoteCertificate(
            Id(cert, "id"), string.Join(", ", Strings(cert, "domains")), Strings(cert, "domains"),
            RelatedSiteIds: sites.Where(site => site.CertificateId == Id(cert, "id")).Select(site => site.Id).ToArray())).ToArray();
        return ApiResult<DeploymentDiscovery>.Ok(new(certs, sites, session.ProductVersion));
    }

    public async Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target,
        CertificateMaterialMetadata material, DeploymentSelection selection, CancellationToken ct)
    {
        var opened = await clients.OpenAsync(target, ct);
        if (!opened.Success || opened.Data is null) return Fail<DeploymentTargetPlan, SafeLineCe9Session>(opened);
        using var session = opened.Data;
        var read = await ReadStateAsync(session, ct);
        if (!read.Success || read.Data is null) return Fail<DeploymentTargetPlan, RemoteState>(read);
        var state = read.Data;
        var config = target.Configuration;
        var selected = config.BindSites ? (selection.SiteIds ?? config.SiteIds).Distinct().Order().ToArray() : [];
        if (config.BindSites && selected.Length == 0)
            return ApiResult<DeploymentTargetPlan>.Fail("VALIDATION", "请选择需要绑定证书的已有站点。");
        foreach (var siteId in selected)
        {
            var site = state.Sites.FirstOrDefault(value => Id(value, "id") == siteId);
            if (site.ValueKind == JsonValueKind.Undefined)
                return ApiResult<DeploymentTargetPlan>.Fail("RESOURCE_CHANGED", "所选雷池站点已不存在。");
            if (!Covers(material.Domains, Strings(site, "server_names")))
                return ApiResult<DeploymentTargetPlan>.Fail("DOMAIN_MISMATCH", "证书 SAN 不覆盖所选站点的全部域名。");
        }
        var remoteId = selection.UseConfiguredRemoteCertificateId && string.IsNullOrEmpty(selection.RemoteCertificateId)
            ? config.RemoteCertificateId : selection.RemoteCertificateId;
        var candidates = state.Certificates.Where(cert => !string.IsNullOrEmpty(remoteId)
            ? Id(cert, "id") == remoteId
            : Strings(cert, "domains").Any(domain => Normalize(domain) == Normalize(material.Domain))).ToArray();
        if (candidates.Length > 1)
            return ApiResult<DeploymentTargetPlan>.Fail("RESOURCE_AMBIGUOUS", "同域名存在多个证书资源，请先明确远端证书 ID。");
        if (!string.IsNullOrEmpty(remoteId) && candidates.Length == 0)
            return ApiResult<DeploymentTargetPlan>.Fail("RESOURCE_CHANGED", "指定的远端证书已不存在。");
        var action = "Create";
        var previousFingerprint = "";
        var previousDigest = "";
        string[] relatedIds = [];
        var siteConditions = new List<SiteCondition>();
        if (candidates.Length == 1)
        {
            var cert = candidates[0];
            remoteId = Id(cert, "id");
            if (!cert.TryGetProperty("type", out var type) || type.GetInt32() != 2)
                return ApiResult<DeploymentTargetPlan>.Fail("MANAGED_CERTIFICATE", "不直接接管雷池 ACME 或其他自动管理的证书。");
            var detail = await ReadCertificateAsync(session, remoteId, ct);
            if (!detail.Success || detail.Data is null) return Fail<DeploymentTargetPlan, RemoteCertificate>(detail);
            previousFingerprint = detail.Data.Fingerprint;
            previousDigest = detail.Data.Digest;
            var related = state.Sites.Where(site => Id(site, "cert_id") == remoteId).ToArray();
            relatedIds = related.Select(site => Id(site, "id")).Order().ToArray();
            if (related.Length > 0 && !Covers(material.Domains, related.SelectMany(site => Strings(site, "server_names"))))
                return ApiResult<DeploymentTargetPlan>.Fail("DOMAIN_MISMATCH",
                    "更新此证书会影响其他关联站点，新证书未覆盖全部域名；请新建证书资源或调整站点范围。");
            action = previousDigest == material.MaterialDigest &&
                selected.All(siteId => state.Sites.Any(site => Id(site, "id") == siteId && Id(site, "cert_id") == remoteId))
                ? "Skip" : "Update";
            selected = selected.Distinct().Order().ToArray();
            foreach (var siteId in related.Select(site => Id(site, "id")).Concat(selected).Distinct().Order())
            {
                var condition = await ReadSiteConditionAsync(session, siteId, ct);
                if (!condition.Success || condition.Data is null) return Fail<DeploymentTargetPlan, SiteCondition>(condition);
                siteConditions.Add(condition.Data);
            }
        }
        else
        {
            remoteId = "";
            foreach (var siteId in selected)
            {
                var condition = await ReadSiteConditionAsync(session, siteId, ct);
                if (!condition.Success || condition.Data is null) return Fail<DeploymentTargetPlan, SiteCondition>(condition);
                siteConditions.Add(condition.Data);
            }
        }
        var preconditions = new Preconditions(remoteId, previousFingerprint, previousDigest, material.Domain,
            state.Certificates.Where(cert => Strings(cert, "domains").Any(domain => Normalize(domain) == Normalize(material.Domain)))
                .Select(cert => Id(cert, "id")).Order().ToArray(), relatedIds, siteConditions.ToArray());
        var summary = action switch
        {
            "Skip" => "远端材料和指定站点关联一致，将核对后跳过。",
            "Update" => $"更新证书 ID {remoteId}，影响 {siteConditions.Count} 个已有站点。",
            _ => selected.Length == 0 ? "新增证书资源，不自动创建或绑定站点。" : $"新增证书，并绑定 {selected.Length} 个已有站点。"
        };
        // 同一 WAF 实例采用保守串行，包含通过不同目标配置访问同一实例的情况。
        return ApiResult<DeploymentTargetPlan>.Ok(new("safeline:" + SafeLineCe9ApiClient.BaseUri(target).Authority.ToLowerInvariant(),
            action, summary, JsonSerializer.Serialize(preconditions), remoteId, selected,
            Warnings: ["雷池不返回旧私钥，不支持完整证书材料回滚；本次不会删除旧证书或创建新站点。"]));
    }

    public async Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct)
    {
        var opened = await clients.OpenAsync(context.Target, ct);
        if (!opened.Success || opened.Data is null) return Fail<DeploymentExecutionResult, SafeLineCe9Session>(opened);
        using var session = opened.Data;
        var checkpoint = PlatformDeploymentCheckpoint.Read(context.ReceiptJson);
        if (checkpoint.Corrupt || checkpoint.SchemaVersion is < 0 or > 1)
            return ApiResult<DeploymentExecutionResult>.Fail("RECOVERY_RECEIPT_INVALID", "平台回执已损坏或版本不支持，不能推断尚未提交。");
        if (!context.IsRecovery)
        {
            checkpoint = PlatformDeploymentCheckpoint.Prepared(context.Plan);
            await checkpoint.SaveAsync(context, "Prepared", ct);
        }
        var remoteId = string.IsNullOrEmpty(checkpoint.RemoteId) ? context.Plan.RemoteResourceId : checkpoint.RemoteId;
        var alreadyUploaded = false;
        if (context.IsRecovery)
        {
            // 新增请求失去响应时只凭唯一指纹找回原资源，绝不通过再次新增代替核对。
            if (string.IsNullOrEmpty(remoteId))
            {
                var found = await FindCertificateAsync(session, context.Material.Metadata, ct);
                if (found.Success && !string.IsNullOrEmpty(found.Data)) remoteId = found.Data;
                else if (checkpoint.UploadStarted)
                    return ApiResult<DeploymentExecutionResult>.Fail("REMOTE_RESULT_UNKNOWN", "原新增请求结果尚未查明，继续查询同一证书，不重复新增。");
            }
            if (!string.IsNullOrEmpty(remoteId))
            {
                var existing = await ReadCertificateAsync(session, remoteId, ct);
                alreadyUploaded = existing.Success && existing.Data?.Fingerprint == context.Material.Metadata.Fingerprint && existing.Data.Digest == context.Material.Metadata.MaterialDigest;
                if (!existing.Success) return Fail<DeploymentExecutionResult, RemoteCertificate>(existing);
            }
        }
        if (!alreadyUploaded)
        {
            if (context.IsRecovery && !checkpoint.CanStart)
                return ApiResult<DeploymentExecutionResult>.Fail(checkpoint.UploadStarted ? "REMOTE_RESULT_UNKNOWN" : "RECOVERY_EVIDENCE_MISSING",
                    "原写入缺少尚未提交的明确证明，只继续查询原资源，不重复提交。");
            var checkedPlan = await CheckPreconditionsAsync(session, context.Plan, ct);
            if (!checkedPlan.Success) return Fail<DeploymentExecutionResult, bool>(checkedPlan);
        }
        if (context.Plan.Action == "Skip")
        {
            if (context.IsRecovery)
            {
                var proof = await InspectWithSessionAsync(session, new(context.Target, context.Plan, context.Material.Metadata), ct);
                if (!proof.Success || proof.Data?.MatchesExpected != true)
                    return ApiResult<DeploymentExecutionResult>.Fail("PLAN_STALE", "原跳过计划的站点关联已变化，不能仅凭证书相同认定完成。");
            }
            var skippedLevel = "PlatformReadback";
            var skippedMessage = "远端证书材料和站点关联已核对，无需重复上传。";
            if (!string.IsNullOrWhiteSpace(context.Target.Configuration.VerificationHost))
            {
                var tls = await DeploymentTlsVerification.VerifyAsync(context.Target.Configuration, context.Material.Metadata, ct);
                if (tls.Success) skippedLevel = "TlsObserved";
                else skippedMessage += TlsObservationWarning;
            }
            return ApiResult<DeploymentExecutionResult>.Ok(new(skippedMessage,
                context.Plan.RemoteResourceId, context.Material.Metadata.Fingerprint, skippedLevel, Skipped: true));
        }
        var acknowledgedSites = checkpoint.AcknowledgedSites;
        ApiResult<DeploymentExecutionResult> AfterWriteFailure(string code, string message, string level = "None") =>
            new(false, code, message, new(message, remoteId, context.Material.Metadata.Fingerprint, level,
                ReceiptJson: checkpoint.Serialize()));
        if (!alreadyUploaded)
        {
            checkpoint.RemoteId = remoteId; checkpoint.Action = context.Plan.Action; checkpoint.UploadStarted = true; checkpoint.SubmissionState = "Submitting";
            await checkpoint.SaveAsync(context, "UploadIntent", ct);
            await context.ReportProgressAsync("Uploading", context.Plan.Action == "Update" ? "正在更新雷池证书资源。" : "正在新增雷池证书资源。", ct);
            object body = context.Plan.Action == "Update"
                ? new { manual = new { crt = context.Material.FullChainPem, key = context.Material.PrivateKeyPem }, type = 2, id = long.Parse(remoteId) }
                : new { manual = new { crt = context.Material.FullChainPem, key = context.Material.PrivateKeyPem }, type = 2 };
            if (context.BeforeExternalMutationAsync is not null) await context.BeforeExternalMutationAsync(ct);
            var write = await session.SendAsync(HttpMethod.Post, "api/open/cert", body, true, ct);
            if (!write.Success) return AfterWriteFailure(write.Code, write.Message);
            if (string.IsNullOrEmpty(remoteId))
            {
                remoteId = write.Data.ValueKind == JsonValueKind.Object ? Id(write.Data, "id") :
                    write.Data.ValueKind == JsonValueKind.Number ? write.Data.ToString() : "";
                if (string.IsNullOrEmpty(remoteId))
                {
                    var found = await FindCertificateAsync(session, context.Material.Metadata, ct);
                    if (!found.Success || string.IsNullOrEmpty(found.Data))
                        return AfterWriteFailure("REMOTE_RESULT_UNKNOWN", "雷池已接收证书，无法唯一核对新增资源，请人工核对后再继续。");
                    remoteId = found.Data;
                }
            }
        }
        checkpoint.RemoteId = remoteId;
        var after = await ReadCertificateAsync(session, remoteId, ct);
        if (!after.Success || after.Data?.Fingerprint != context.Material.Metadata.Fingerprint ||
            after.Data?.Digest != context.Material.Metadata.MaterialDigest)
            return AfterWriteFailure("REMOTE_RESULT_UNKNOWN", "雷池已接收上传，但证书读回未确认一致，请先核对远端结果。");
        checkpoint.SchemaVersion = 1; checkpoint.UploadStarted = true; checkpoint.UploadCompleted = true; checkpoint.SubmissionState = "Completed";
        await checkpoint.SaveAsync(context, "Uploaded", ct);
        foreach (var siteId in context.Plan.SiteIds ?? [])
        {
            await context.ReportProgressAsync("Binding", $"正在核对并更新站点 {siteId} 的证书关联。", ct);
            var detail = await session.SendAsync(HttpMethod.Get, "api/open/site/" + Uri.EscapeDataString(siteId), null, false, ct);
            if (!detail.Success || detail.Data.ValueKind != JsonValueKind.Object)
                return AfterWriteFailure("REMOTE_RESULT_UNKNOWN", "证书已写入，但读取站点失败，请核对证书和站点绑定。");
            var original = JsonSerializer.Deserialize<Preconditions>(context.Plan.PreconditionsJson)!
                .Sites.SingleOrDefault(site => site.Id == siteId);
            if (!Covers(context.Material.Metadata.Domains, Strings(detail.Data, "server_names")))
                return AfterWriteFailure(context.IsRecovery ? "RECOVERY_CONFLICT" : "REMOTE_RESULT_UNKNOWN", "站点当前域名不再被本轮证书覆盖，已停止恢复。");
            if (Id(detail.Data, "cert_id") == remoteId)
            {
                if (original is null || (original.ConfigurationDigest.Length > 0 ? SiteConfigurationDigest(detail.Data) != original.ConfigurationDigest : SiteDigest(detail.Data) != original.Digest))
                    return AfterWriteFailure(context.IsRecovery ? "RECOVERY_CONFLICT" : "REMOTE_RESULT_UNKNOWN", "已绑定站点的配置与原计划不一致，不能直接认定完成。");
                continue;
            }
            if (original is null || SiteDigest(detail.Data) != original.Digest)
                return AfterWriteFailure(context.IsRecovery ? "RECOVERY_CONFLICT" : "REMOTE_RESULT_UNKNOWN", "证书已写入，但站点配置在绑定前发生变化，请核对后重新计划。");
            if (!CertificateMaterialHelper.CoversDomains(context.Material.CertificatePem, Strings(detail.Data, "server_names")))
                return AfterWriteFailure(context.IsRecovery ? "RECOVERY_CONFLICT" : "REMOTE_RESULT_UNKNOWN", "证书已写入，但站点域名发生变化，请核对后重新计划。");
            // 整体更新前保留原对象所有字段，只替换证书 ID，避免覆盖上游、端口等设置。
            var updated = JsonNode.Parse(detail.Data.GetRawText())!.AsObject();
            updated["id"] = long.Parse(siteId);
            updated["cert_id"] = long.Parse(remoteId);
            checkpoint.PendingSiteId = siteId;
            await checkpoint.SaveAsync(context, "BindingIntent", ct);
            if (context.BeforeExternalMutationAsync is not null) await context.BeforeExternalMutationAsync(ct);
            var bind = await session.SendAsync(HttpMethod.Put, "api/open/site", updated, true, ct);
            if (!bind.Success) return AfterWriteFailure("REMOTE_RESULT_UNKNOWN", "证书已写入，站点绑定未完全确认，请先核对已应用范围。");
            acknowledgedSites.Add(siteId);
            checkpoint.PendingSiteId = "";
            await checkpoint.SaveAsync(context, "Bound", ct);
        }
        await context.ReportProgressAsync("Verifying", "读取雷池证书指纹和站点绑定，核对本次部署结果。", ct);
        var inspection = await InspectWithSessionAsync(session,
            new(context.Target, context.Plan with { RemoteResourceId = remoteId }, context.Material.Metadata), ct);
        if (!inspection.Success || inspection.Data?.MatchesExpected != true)
            return AfterWriteFailure("REMOTE_RESULT_UNKNOWN", "证书写入后的平台读回验证未通过，请核对当前状态。");
        var verification = "PlatformReadback";
        var message = "雷池证书资源与指定站点绑定已核对。";
        if (!string.IsNullOrWhiteSpace(context.Target.Configuration.VerificationHost))
        {
            var tls = await DeploymentTlsVerification.VerifyAsync(context.Target.Configuration, context.Material.Metadata, ct);
            if (tls.Success) verification = "TlsObserved";
            else message += TlsObservationWarning;
        }
        return ApiResult<DeploymentExecutionResult>.Ok(new(message,
            remoteId, context.Material.Metadata.Fingerprint, verification,
            ReceiptJson: checkpoint.Serialize()));
    }

    public async Task<ApiResult<DeploymentRecoveryResult>> RecoverAsync(DeploymentExecutionContext context, CancellationToken ct) =>
        PlatformDeploymentRecovery.FromExecution(await ExecuteAsync(context, ct));

    public async Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct)
    {
        var opened = await clients.OpenAsync(context.Target, ct);
        if (!opened.Success || opened.Data is null) return Fail<DeploymentInspection, SafeLineCe9Session>(opened);
        using var session = opened.Data;
        var inspected = await InspectWithSessionAsync(session, context, ct);
        if (!inspected.Success || inspected.Data?.MatchesExpected != true || string.IsNullOrWhiteSpace(context.Target.Configuration.VerificationHost))
            return inspected;
        var tls = await DeploymentTlsVerification.VerifyAsync(context.Target.Configuration, context.Material, ct);
        return tls.Success
            ? ApiResult<DeploymentInspection>.Ok(inspected.Data with { VerificationLevel = "TlsObserved", Message = "雷池证书、站点关联与业务 HTTPS 生效均已核对。" })
            : ApiResult<DeploymentInspection>.Ok(inspected.Data with { Message = inspected.Data.Message + TlsObservationWarning });
    }

    private static async Task<ApiResult<DeploymentInspection>> InspectWithSessionAsync(SafeLineCe9Session session,
        DeploymentInspectionContext context, CancellationToken ct)
    {
        var remoteId = context.Plan.RemoteResourceId;
        if (string.IsNullOrEmpty(remoteId))
        {
            var found = await FindCertificateAsync(session, context.Material, ct);
            if (!found.Success || string.IsNullOrEmpty(found.Data)) return Fail<DeploymentInspection, string>(found);
            remoteId = found.Data;
        }
        var cert = await ReadCertificateAsync(session, remoteId, ct);
        if (!cert.Success || cert.Data is null) return Fail<DeploymentInspection, RemoteCertificate>(cert);
        if (cert.Data.Fingerprint != context.Material.Fingerprint || cert.Data.Digest != context.Material.MaterialDigest)
            return ApiResult<DeploymentInspection>.Ok(new(false, "远端证书或证书链与本次材料不一致。", cert.Data.Fingerprint));
        foreach (var siteId in context.Plan.SiteIds ?? [])
        {
            var site = await session.SendAsync(HttpMethod.Get, "api/open/site/" + Uri.EscapeDataString(siteId), null, false, ct);
            if (!site.Success) return Fail<DeploymentInspection, JsonElement>(site);
            if (Id(site.Data, "cert_id") != remoteId)
                return ApiResult<DeploymentInspection>.Ok(new(false, "至少一个指定站点尚未绑定本次证书。", cert.Data.Fingerprint));
            var original = JsonSerializer.Deserialize<Preconditions>(context.Plan.PreconditionsJson)?.Sites.SingleOrDefault(item => item.Id == siteId);
            if (!Covers(context.Material.Domains, Strings(site.Data, "server_names")) || original is null ||
                (original.ConfigurationDigest.Length > 0 ? SiteConfigurationDigest(site.Data) != original.ConfigurationDigest : SiteDigest(site.Data) != original.Digest))
                return ApiResult<DeploymentInspection>.Ok(new(false, "站点域名或配置与本轮证书及原计划不一致。", cert.Data.Fingerprint));
        }
        return ApiResult<DeploymentInspection>.Ok(new(true, "平台证书材料和指定站点关联一致。",
            cert.Data.Fingerprint, "PlatformReadback"));
    }

    private static async Task<ApiResult<bool>> CheckPreconditionsAsync(SafeLineCe9Session session, DeploymentTargetPlan plan, CancellationToken ct)
    {
        var expected = JsonSerializer.Deserialize<Preconditions>(plan.PreconditionsJson);
        if (expected is null) return ApiResult<bool>.Fail("PLAN_STALE", "部署计划无效，请重新生成。");
        if (!string.IsNullOrEmpty(expected.CertificateId))
        {
            var cert = await ReadCertificateAsync(session, expected.CertificateId, ct);
            if (!cert.Success || cert.Data?.Fingerprint != expected.Fingerprint || cert.Data?.Digest != expected.Digest)
                return ApiResult<bool>.Fail("PLAN_STALE", "远端证书已变化，请重新生成计划。");
        }
        var state = await ReadStateAsync(session, ct);
        if (!state.Success || state.Data is null) return Fail<bool, RemoteState>(state);
        var candidates = state.Data.Certificates.Where(cert =>
            Strings(cert, "domains").Any(domain => Normalize(domain) == Normalize(expected.Domain))).Select(cert => Id(cert, "id")).Order().ToArray();
        if (!candidates.SequenceEqual(expected.CandidateIds))
            return ApiResult<bool>.Fail("PLAN_STALE", "远端同域名证书集合已变化，请重新生成计划。");
        var related = string.IsNullOrEmpty(expected.CertificateId) ? [] :
            state.Data.Sites.Where(site => Id(site, "cert_id") == expected.CertificateId)
                .Select(site => Id(site, "id")).Order().ToArray();
        if (!related.SequenceEqual(expected.RelatedSiteIds))
            return ApiResult<bool>.Fail("PLAN_STALE", "远端证书的关联站点范围已变化，请重新生成计划。");
        foreach (var site in expected.Sites)
        {
            var current = await ReadSiteConditionAsync(session, site.Id, ct);
            if (!current.Success || current.Data?.Digest != site.Digest)
                return ApiResult<bool>.Fail("PLAN_STALE", "远端站点配置已变化，请重新生成计划。");
        }
        return ApiResult<bool>.Ok(true);
    }

    private static async Task<ApiResult<RemoteState>> ReadStateAsync(SafeLineCe9Session session, CancellationToken ct)
    {
        var certs = await session.SendAsync(HttpMethod.Get, "api/open/cert", null, false, ct);
        if (!certs.Success) return Fail<RemoteState, JsonElement>(certs);
        if (certs.Data.ValueKind != JsonValueKind.Object ||
            !certs.Data.TryGetProperty("nodes", out var nodes) || nodes.ValueKind != JsonValueKind.Array)
            return Protocol<RemoteState>();
        var certificates = nodes.EnumerateArray().Select(value => value.Clone()).ToArray();
        if (certs.Data.TryGetProperty("total", out var total) && total.GetInt32() != certificates.Length)
            return ApiResult<RemoteState>.Fail("INCOMPLETE_RESPONSE", "雷池证书列表未完整返回，已停止匹配。");
        var sites = new List<JsonElement>();
        var siteTotal = int.MaxValue;
        for (var page = 1; sites.Count < siteTotal && page <= 100; page++)
        {
            var response = await session.SendAsync(HttpMethod.Get, $"api/open/site?page={page}&page_size=200", null, false, ct);
            if (!response.Success) return Fail<RemoteState, JsonElement>(response);
            if (response.Data.ValueKind != JsonValueKind.Object ||
                !response.Data.TryGetProperty("data", out var rows) || rows.ValueKind != JsonValueKind.Array ||
                !response.Data.TryGetProperty("total", out var count)) return Protocol<RemoteState>();
            siteTotal = count.GetInt32();
            var values = rows.EnumerateArray().Select(value => value.Clone()).ToArray();
            if (values.Length == 0 && sites.Count < siteTotal) return Protocol<RemoteState>();
            sites.AddRange(values);
        }
        if (sites.Count != siteTotal || sites.Select(site => Id(site, "id")).Distinct().Count() != sites.Count)
            return ApiResult<RemoteState>.Fail("INCOMPLETE_RESPONSE", "雷池站点分页不完整，已停止匹配。");
        if (certificates.Any(cert => !long.TryParse(Id(cert, "id"), out _) ||
            !cert.TryGetProperty("domains", out var domains) || domains.ValueKind != JsonValueKind.Array ||
            domains.GetArrayLength() == 0 || domains.EnumerateArray().Any(domain => domain.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(domain.GetString())) ||
            !cert.TryGetProperty("type", out var type) || type.ValueKind != JsonValueKind.Number) ||
            sites.Any(site => !long.TryParse(Id(site, "id"), out _) ||
                !site.TryGetProperty("server_names", out var names) || names.ValueKind != JsonValueKind.Array ||
                names.EnumerateArray().Any(name => name.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(name.GetString()))))
            return Protocol<RemoteState>();
        return ApiResult<RemoteState>.Ok(new(certificates, sites.ToArray()));
    }

    private static async Task<ApiResult<RemoteCertificate>> ReadCertificateAsync(SafeLineCe9Session session, string id, CancellationToken ct)
    {
        var response = await session.SendAsync(HttpMethod.Get, "api/open/cert/" + Uri.EscapeDataString(id), null, false, ct);
        if (!response.Success) return Fail<RemoteCertificate, JsonElement>(response);
        try
        {
            var pem = response.Data.GetProperty("manual").GetProperty("crt").GetString()!;
            var certs = new X509Certificate2Collection();
            certs.ImportFromPem(pem);
            try
            {
                if (certs.Count == 0) return Protocol<RemoteCertificate>();
                var normalized = string.Concat(certs.Cast<X509Certificate2>().Select(cert => cert.ExportCertificatePem() + "\n"));
                return ApiResult<RemoteCertificate>.Ok(new(certs[0].GetCertHashString(HashAlgorithmName.SHA256),
                    Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(normalized)))));
            }
            finally { foreach (var cert in certs) cert.Dispose(); }
        }
        catch (Exception ex) when (ex is CryptographicException or InvalidOperationException or KeyNotFoundException or ArgumentException)
        { return Protocol<RemoteCertificate>(); }
    }

    private static async Task<ApiResult<string>> FindCertificateAsync(SafeLineCe9Session session, CertificateMaterialMetadata material, CancellationToken ct)
    {
        var state = await ReadStateAsync(session, ct);
        if (!state.Success || state.Data is null) return Fail<string, RemoteState>(state);
        var ids = new List<string>();
        foreach (var candidate in state.Data.Certificates.Where(cert =>
            Strings(cert, "domains").Any(domain => Normalize(domain) == Normalize(material.Domain))))
        {
            var read = await ReadCertificateAsync(session, Id(candidate, "id"), ct);
            if (!read.Success) return Fail<string, RemoteCertificate>(read);
            if (read.Data?.Fingerprint == material.Fingerprint && read.Data.Digest == material.MaterialDigest) ids.Add(Id(candidate, "id"));
        }
        return ids.Count == 1 ? ApiResult<string>.Ok(ids[0]) :
            ApiResult<string>.Fail("RESOURCE_AMBIGUOUS", "无法唯一定位本次证书资源，请核对雷池后台。");
    }

    private static async Task<ApiResult<SiteCondition>> ReadSiteConditionAsync(SafeLineCe9Session session, string id, CancellationToken ct)
    {
        var read = await session.SendAsync(HttpMethod.Get, "api/open/site/" + Uri.EscapeDataString(id), null, false, ct);
        if (!read.Success) return Fail<SiteCondition, JsonElement>(read);
        if (read.Data.ValueKind != JsonValueKind.Object) return Protocol<SiteCondition>();
        // 健康检查实时状态不属于可写配置，排除后再按字段排序生成前置条件摘要。
        return ApiResult<SiteCondition>.Ok(new(id, SiteDigest(read.Data), SiteConfigurationDigest(read.Data)));
    }

    private static string SiteDigest(JsonElement site)
    {
        var properties = site.EnumerateObject().Where(property => property.Name != "health_state")
            .OrderBy(property => property.Name).ToDictionary(property => property.Name, property => property.Value.Clone());
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(properties)));
    }
    private static string SiteConfigurationDigest(JsonElement site)
    {
        var properties = site.EnumerateObject().Where(property => property.Name is not ("health_state" or "cert_id" or "id"))
            .OrderBy(property => property.Name).ToDictionary(property => property.Name, property => property.Value.Clone());
        return Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(properties)));
    }

    private static bool Covers(IEnumerable<string> certificateDomains, IEnumerable<string> names)
    {
        var sans = certificateDomains.Select(Normalize).ToArray();
        var requested = names.ToArray();
        return sans.Length > 0 && requested.Length > 0 && requested.All(name =>
        {
            var value = Normalize(name);
            return value.Length > 0 && value != "*" && sans.Any(san => san == value ||
                (!value.StartsWith("*.", StringComparison.Ordinal) && san.StartsWith("*.", StringComparison.Ordinal) &&
                 value.EndsWith(san[1..], StringComparison.Ordinal) &&
                 value.Count(character => character == '.') == san.Count(character => character == '.')));
        });
    }
    private static string Normalize(string value) => value.Trim().TrimEnd('.').ToLowerInvariant();
    private static string Id(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var id) && id.ValueKind is JsonValueKind.Number or JsonValueKind.String
            ? id.ToString() : "";
    private static string[] Strings(JsonElement value, string name) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(name, out var array) && array.ValueKind == JsonValueKind.Array
            ? array.EnumerateArray().Where(item => item.ValueKind == JsonValueKind.String).Select(item => item.GetString()!).ToArray() : [];
    private static ApiResult<T> Fail<T, TSource>(ApiResult<TSource> result) => ApiResult<T>.Fail(result.Code, result.Message);
    private static ApiResult<T> Protocol<T>() => ApiResult<T>.Fail("SAFELINE_PROTOCOL_UNSUPPORTED", "雷池接口数据格式不兼容，已停止操作。");
    private sealed record RemoteState(JsonElement[] Certificates, JsonElement[] Sites);
    private sealed record RemoteCertificate(string Fingerprint, string Digest);
    private sealed record SiteCondition(string Id, string Digest, string ConfigurationDigest = "");
    private sealed record Preconditions(string CertificateId, string Fingerprint, string Digest, string Domain,
        string[] CandidateIds, string[] RelatedSiteIds, SiteCondition[] Sites);
}
