using System.Text.Json;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>腾讯云免费证书与 DNSPod 适配；申请和吊销挑战独立返回，由对应编排阶段处理。</summary>
public sealed class TencentCloudService(TencentCloudApiClient api, IHttpClientFactory clients) : ICloudCertificateService, IDnsProvider
{
    // CertificateStatus 是腾讯云的可选状态过滤项。为兼容不同租户/控制台的默认筛选行为，
    // 这里防御式传入全部已知状态，确保过期、吊销等历史证书也进入本次云端全量快照。
    private static readonly int[] AllCertificateStatuses = Enumerable.Range(0, 16).ToArray();
    // 腾讯云租户实际列表中最容易被默认筛选掉的终态是已过期和已吊销；缺失时单独补查这两个状态。
    private static readonly int[] HistoricalCertificateStatuses = [3, 10];

    public string Provider => "TencentCloud";
    public async Task<ApiResult<CloudConnectionTest>> TestAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        var r = await api.CallAsync(account, "ssl", "DescribeCertificates", new { Offset = 0, Limit = 1 }, false, ct);
        return r.Success ? ApiResult<CloudConnectionTest>.Ok(new(Provider, RequestId(r.Data), "SSL 查询权限验证通过。")) : CloudJson.Fail<CloudConnectionTest, JsonElement>(r);
    }
    public async Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        var r = await api.CallAsync(account, "dnspod", "DescribeDomainList", new { Type = "ALL", Offset = 0, Limit = 1 }, false, ct);
        return r.Success ? ApiResult<CloudConnectionTest>.Ok(new(Provider, RequestId(r.Data), "DNS 查询权限验证通过，未写入记录。")) : CloudJson.Fail<CloudConnectionTest, JsonElement>(r);
    }

    public async Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        var all = await Pages(account, "ssl", "DescribeCertificates", "Certificates", "CertificateId", null, "TotalCount",
            new() { ["CertificateStatus"] = AllCertificateStatuses }, ct);
        if (!all.Success) return CloudJson.Fail<IReadOnlyList<CloudCertificate>, IReadOnlyList<JsonElement>>(all);
        var rows = all.Data!.ToList();
        // 个别租户的默认证书列表仍可能只返回已签发/处理中记录。对主快照中缺失的历史状态
        // 再按状态过滤查询一次，避免过期、吊销证书因平台侧默认筛选而永远无法同步到本地。
        var missingHistoricalStatuses = HistoricalCertificateStatuses
            .Where(status => !rows.Any(row => CloudJson.Text(row, "Status") == status.ToString()))
            .ToArray();
        if (missingHistoricalStatuses.Length > 0)
        {
            var historical = await Pages(account, "ssl", "DescribeCertificates", "Certificates", "CertificateId", null, "TotalCount",
                new() { ["CertificateStatus"] = missingHistoricalStatuses }, ct);
            if (!historical.Success) return CloudJson.Fail<IReadOnlyList<CloudCertificate>, IReadOnlyList<JsonElement>>(historical);
            var knownIds = rows.Select(row => CloudJson.Text(row, "CertificateId")).ToHashSet(StringComparer.Ordinal);
            rows.AddRange(historical.Data!.Where(row => knownIds.Add(CloudJson.Text(row, "CertificateId"))));
        }
        return ApiResult<IReadOnlyList<CloudCertificate>>.Ok(rows.Select(x => ParseCertificate(x, "", RequestId(x))).ToArray());
    }
    public async Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
    {
        if (!CloudJson.Id(reference.CertificateId)) return CloudJson.Invalid<CloudCertificateDetail>("证书 ID 无效。");
        var r = await api.CallAsync(account, "ssl", "DescribeCertificate", new { reference.CertificateId }, false, ct);
        if (!r.Success) return CloudJson.Fail<CloudCertificateDetail, JsonElement>(r);
        var id = CloudJson.Text(r.Data, "CertificateId");
        if (id.Length > 0 && id != reference.CertificateId) return ApiResult<CloudCertificateDetail>.Fail("CloudIdentityMismatch", "云端证书 ID 与请求不一致。");
        var certificate = ParseCertificate(r.Data, reference.CertificateId, RequestId(r.Data));
        var challenges = new List<DnsChallenge>();
        var auth = CloudJson.Object(r.Data, "DvAuthDetail");
        if (CloudJson.Array(auth, "DvAuths", out var rows))
            foreach (var row in rows.EnumerateArray()) challenges.Add(Challenge(row, certificate.Domain));
        else if (CloudJson.Text(auth, "DvAuthKey").Length > 0) challenges.Add(Challenge(auth, certificate.Domain));
        // 吊销挑战必须来自专用字段；其 DvAuthVerifyType 明确区分 TXT/CNAME/FILE。
        // 缺失类型保持为空，交给编排层拒绝自动写入，不能沿用申请挑战或猜测 TXT。
        var revocationChallenges = new List<DnsChallenge>();
        if (CloudJson.Array(r.Data, "DvRevokeAuthDetail", out var revocationRows))
            foreach (var row in revocationRows.EnumerateArray()) revocationChallenges.Add(Challenge(row, certificate.Domain));
        return ApiResult<CloudCertificateDetail>.Ok(new(certificate, challenges.Distinct().ToArray(),
            certificate.Status == "Failed" ? "腾讯云审核失败，请在官方控制台核对原因。" : null,
            revocationChallenges.Distinct().ToArray()));
    }
    public async Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default)
    {
        if (!CloudJson.Domain(request.Domain) || request.Alias is null || request.Alias.Length > 100) return CloudJson.Invalid<CloudCertificateDetail>("免费证书需要有效单域名，备注最多 100 字。");
        var mode = request.ValidationMode switch { "NativeAutoDns" => "DNS_AUTO", "ManagedDns" or "ManualDns" => "DNS", "File" => "FILE", _ => "" };
        if (mode.Length == 0) return CloudJson.Invalid<CloudCertificateDetail>("不支持的验证方式。");
        var p = new Dictionary<string, object> { ["DomainName"] = request.Domain.ToLowerInvariant(), ["DvAuthMethod"] = mode,
            ["PackageType"] = "83", ["ValidityPeriod"] = "3", ["Alias"] = request.Alias,
            ["CsrEncryptAlgo"] = "RSA", ["CsrKeyParameter"] = "2048" };
        if (mode == "DNS_AUTO") p["DeleteDnsAutoRecord"] = request.AutoCleanup;
        var r = await api.CallAsync(account, "ssl", "ApplyCertificate", p, true, ct);
        if (!r.Success) return CloudJson.Fail<CloudCertificateDetail, JsonElement>(r);
        var id = CloudJson.Text(r.Data, "CertificateId");
        if (!CloudJson.Id(id)) return ApiResult<CloudCertificateDetail>.Fail("OutcomeUnknown", "云端已响应但未提供证书 ID，请核对云端，勿重复申请。");
        var reference = new CloudCertificateReference(id);
        var detail = await GetAsync(account, reference, ct);
        // 提交成功后查询失败仍保留资源 ID，避免上层将查询失败误当申请失败而重复下单。
        return detail.Success ? detail : ApiResult<CloudCertificateDetail>.Ok(new(new(reference, request.Domain, request.Alias,
            "Pending", "Submitted", true, "83", null, null, mode, RequestId(r.Data)), [], "申请已提交，验证详情等待后续同步。"));
    }
    public async Task<ApiResult<CloudOperation>> RevokeAsync(CloudAccountCredentials account, CloudCertificateReference reference, string reason, CancellationToken ct = default)
    {
        if (reason is null || reason.Length > 200) return CloudJson.Invalid<CloudOperation>("吊销原因最多 200 字。");
        var detail = await GetAsync(account, reference, ct);
        if (!detail.Success) return CloudJson.Fail<CloudOperation, CloudCertificateDetail>(detail);
        if (detail.Data!.Certificate.IsFree != true) return ApiResult<CloudOperation>.Fail("FreeCertificateRequired", "此平台仅允许吊销已精确识别的免费证书。");
        var r = await api.CallAsync(account, "ssl", "RevokeCertificate", new { reference.CertificateId, Reason = reason }, true, ct);
        if (!r.Success) return CloudJson.Fail<CloudOperation, JsonElement>(r);
        var challenges = new List<DnsChallenge>();
        if (CloudJson.Array(r.Data, "RevokeDomainValidateAuths", out var rows))
            foreach (var row in rows.EnumerateArray()) challenges.Add(new(CloudJson.Text(row, "DomainValidateAuthDomain"),
                CloudJson.Text(row, "DomainValidateAuthKey"), "", CloudJson.Text(row, "DomainValidateAuthValue")));
        return ApiResult<CloudOperation>.Ok(new(RequestId(r.Data), "Revoking", challenges));
    }

    public async Task<ApiResult<CloudOperation>> CancelAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
    {
        if (!CloudJson.Id(reference.CertificateId)) return CloudJson.Invalid<CloudOperation>("取消审核需要有效的腾讯云证书 ID。");
        // 腾讯云对待验证/审核中的申请使用 CancelAuditCertificate；取消审核后才允许删除待验证证书。
        var r = await api.CallAsync(account, "ssl", "CancelAuditCertificate", new { reference.CertificateId }, true, ct);
        if (!r.Success) return CloudJson.Fail<CloudOperation, JsonElement>(r);
        var success = r.Data.TryGetProperty("Result", out var value) && value.ValueKind == JsonValueKind.True;
        return success
            ? ApiResult<CloudOperation>.Ok(new(RequestId(r.Data), "Cancelled"), "腾讯云证书审核已取消")
            : ApiResult<CloudOperation>.Fail("CANCEL_AUDIT_FAILED", "腾讯云未确认取消审核，请刷新后重试。");
    }

    public async Task<ApiResult<CloudOperation>> DeleteAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
    {
        if (!CloudJson.Id(reference.CertificateId)) return CloudJson.Invalid<CloudOperation>("删除需要有效的腾讯云证书 ID。");
        // 删除前由编排层校验证书必须已过期；这里仍只按明确的证书 ID 调用官方删除接口。
        // 开启关联资源检查，避免删除仍绑定 CLB 等云资源的证书；返回 TaskId 时由上层保留本地快照。
        var r = await api.CallAsync(account, "ssl", "DeleteCertificate", new { reference.CertificateId, IsCheckResource = true }, true, ct);
        if (!r.Success) return CloudJson.Fail<CloudOperation, JsonElement>(r);
        var deleted = r.Data.TryGetProperty("DeleteResult", out var value) && value.ValueKind == JsonValueKind.True;
        if (deleted) return ApiResult<CloudOperation>.Ok(new(RequestId(r.Data), "Deleted"), "腾讯云证书已删除");
        var taskId = CloudJson.Text(r.Data, "TaskId");
        return taskId.Length > 0
            ? ApiResult<CloudOperation>.Ok(new(RequestId(r.Data), "Deleting", TaskId: taskId), $"腾讯云已创建异步删除任务，请稍后同步确认（TaskId：{taskId}）")
            : ApiResult<CloudOperation>.Fail("OutcomeUnknown", "腾讯云删除响应未确认结果，请核对云端状态。");
    }

    public async Task<ApiResult<CertificateDownload>> DownloadAsync(CloudAccountCredentials account, CloudCertificateReference reference, string format, CancellationToken ct = default)
    {
        if (!CloudJson.Id(reference.CertificateId)) return CloudJson.Invalid<CertificateDownload>("证书 ID 无效。");
        format = format?.ToLowerInvariant() ?? "";
        if (format is not ("nginx" or "apache" or "iis" or "tomcat")) return ApiResult<CertificateDownload>.Fail("UnsupportedDownloadFormat", "腾讯云支持 Nginx、Apache、IIS、Tomcat 证书包。");
        var r = await api.CallAsync(account, "ssl", "DescribeDownloadCertificateUrl", new { reference.CertificateId, ServiceType = format }, false, ct);
        if (!r.Success) return CloudJson.Fail<CertificateDownload, JsonElement>(r);
        return await CertificateDownloadHelper.DownloadTencentAsync(clients, CloudJson.Text(r.Data, "DownloadCertificateUrl"), reference.CertificateId, format, RequestId(r.Data), ct);
    }

    public async Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        var all = await Pages(account, "dnspod", "DescribeDomainList", "DomainList", "DomainId", "DomainCountInfo", "DomainTotal", new() { ["Type"] = "ALL" }, ct);
        if (!all.Success) return CloudJson.Fail<IReadOnlyList<DnsZone>, IReadOnlyList<JsonElement>>(all);
        return ApiResult<IReadOnlyList<DnsZone>>.Ok(all.Data!.Select(x => new DnsZone(CloudJson.Text(x, "DomainId"), CloudJson.Text(x, "Name"), CloudJson.Text(x, "Status"), [], RequestId(x))).ToArray());
    }
    public async Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default)
    {
        if (!CloudJson.Domain(zone)) return CloudJson.Invalid<IReadOnlyList<DnsRecord>>("DNS 区域名称无效。");
        var all = await Pages(account, "dnspod", "DescribeRecordList", "RecordList", "RecordId", "RecordCountInfo", "TotalCount", new() { ["Domain"] = zone, ["ErrorOnEmpty"] = "no" }, ct);
        if (!all.Success) return CloudJson.Fail<IReadOnlyList<DnsRecord>, IReadOnlyList<JsonElement>>(all);
        return ApiResult<IReadOnlyList<DnsRecord>>.Ok(all.Data!.Select(x => ParseRecord(x, zone)).ToArray());
    }
    public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default)
        => WriteRecord(account, zone, "", request, ct);
    public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string recordId, DnsRecordRequest request, CancellationToken ct = default)
        => CloudJson.NumericId(recordId) ? WriteRecord(account, zone, recordId, request, ct) : Task.FromResult(CloudJson.Invalid<DnsRecord>("DNS 记录 ID 无效。"));
    private async Task<ApiResult<DnsRecord>> WriteRecord(CloudAccountCredentials account, string zone, string id, DnsRecordRequest request, CancellationToken ct)
    {
        if (!CloudJson.RecordInput(zone, request) || (id.Length > 0 && !CloudJson.NumericId(id)) || (request.Type == "MX" && request.Mx is not (>= 1 and <= 50)))
            return CloudJson.Invalid<DnsRecord>("DNS 记录参数无效，MX 记录需要 1 至 50 的优先级。");
        var recordStatus = "Enabled";
        if (id.Length > 0)
        {
            var check = await CheckRecord(account, zone, id, ct);
            if (!check.Success) return CloudJson.Fail<DnsRecord, DnsRecord>(check);
            recordStatus = check.Data!.Status;
        }
        var p = new Dictionary<string, object> { ["Domain"] = zone, ["SubDomain"] = request.Name, ["RecordType"] = request.Type,
            ["Value"] = request.Value, ["TTL"] = request.Ttl, ["RecordLine"] = request.Line == "default" ? "默认" : request.Line };
        if (id.Length > 0) p["RecordId"] = long.Parse(id);
        if (request.Mx.HasValue) p["MX"] = request.Mx.Value;
        var r = await api.CallAsync(account, "dnspod", id.Length == 0 ? "CreateRecord" : "ModifyRecord", p, true, ct);
        if (!r.Success) return CloudJson.Fail<DnsRecord, JsonElement>(r);
        var resultId = CloudJson.Text(r.Data, "RecordId");
        if (resultId.Length == 0) resultId = id;
        if (!CloudJson.NumericId(resultId)) return ApiResult<DnsRecord>.Fail("OutcomeUnknown", "DNS 写入响应缺少记录 ID，请核对云端状态。");
        var record = new DnsRecord(resultId, zone, request.Name, request.Type, request.Value, request.Ttl, recordStatus, request.Line, RequestId(r.Data), request.Mx);
        // DNSPod 写入成功后，解析索引可能仍在传播。接口在返回成功前确认新记录已经出现在
        // 一个可信全量快照中，避免前端紧接着刷新时把短暂的不一致暴露成分页错误。
        if (id.Length == 0)
        {
            var visible = await WaitForRecordVisibilityAsync(account, zone, resultId, ct);
            if (!visible.Success)
                return ApiResult<DnsRecord>.Fail("OutcomeUnknown", "DNS 记录已提交，但云端索引尚未确认，请稍后刷新核对，勿重复提交。");
        }
        return ApiResult<DnsRecord>.Ok(record);
    }
    public async Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string recordId, bool enabled, CancellationToken ct = default)
    {
        var check = await CheckRecord(account, zone, recordId, ct);
        if (!check.Success) return CloudJson.Fail<CloudOperation, DnsRecord>(check);
        var r = await api.CallAsync(account, "dnspod", "ModifyRecordStatus", new { Domain = zone, RecordId = long.Parse(recordId), Status = enabled ? "ENABLE" : "DISABLE" }, true, ct);
        return r.Success ? ApiResult<CloudOperation>.Ok(new(RequestId(r.Data), enabled ? "Enabled" : "Disabled")) : CloudJson.Fail<CloudOperation, JsonElement>(r);
    }
    public async Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string recordId, CancellationToken ct = default)
    {
        var check = await CheckRecord(account, zone, recordId, ct);
        if (!check.Success) return CloudJson.Fail<CloudOperation, DnsRecord>(check);
        var r = await api.CallAsync(account, "dnspod", "DeleteRecord", new { Domain = zone, RecordId = long.Parse(recordId) }, true, ct);
        return r.Success ? ApiResult<CloudOperation>.Ok(new(RequestId(r.Data), "Deleted")) : CloudJson.Fail<CloudOperation, JsonElement>(r);
    }
    private async Task<ApiResult<DnsRecord>> CheckRecord(CloudAccountCredentials account, string zone, string id, CancellationToken ct)
    {
        if (!CloudJson.NumericId(id)) return CloudJson.Invalid<DnsRecord>("DNS 记录 ID 无效。");
        var records = await ListRecordsAsync(account, zone, ct);
        if (!records.Success) return CloudJson.Fail<DnsRecord, IReadOnlyList<DnsRecord>>(records);
        var record = records.Data!.FirstOrDefault(x => x.Id == id);
        return record is null ? ApiResult<DnsRecord>.Fail("DnsRecordNotFound", "指定 DNS 区域中找不到该记录。") : ApiResult<DnsRecord>.Ok(record);
    }

    private async Task<ApiResult<IReadOnlyList<JsonElement>>> Pages(CloudAccountCredentials account, string service, string action,
        string arrayName, string idName, string? countObject, string countName, Dictionary<string, object> parameters, CancellationToken ct)
    {
        // 云端列表可能在翻页期间发生变化（DNSPod 文档也说明索引存在短暂延迟）。
        // 这里不能把 TotalCount/ListCount 当成强一致游标：删除记录后，云端可能先更新列表再更新计数，
        // 也可能先更新计数再更新列表。以实际返回数组推进 Offset，并继续探测下一页，才能得到当前云端的全量结果。
        // 每一页仍然必须是对象且带唯一 ID；遇到重复且没有任何新增时才放弃本轮并从第一页重试，绝不返回部分结果。
        // 云端写入后索引存在短暂最终一致性。重试必须留出传播时间，且每次都从第一页
        // 重新读取；否则连续的即时请求可能重复命中同一个中间快照，最终错误地返回失败。
        // DNSPod 新增/删除解析后的索引传播时间可能接近 30 秒；记录列表使用更长的
        // 退避窗口，证书和托管域列表仍采用较短窗口，避免普通查询无谓等待。
        var maxAttempts = action == "DescribeRecordList" ? 8 : 6;
        IReadOnlyList<JsonElement>? previousCandidate = null;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            if (attempt > 1)
                await Task.Delay(PaginationRetryDelay(action, attempt), ct);

            var result = new List<JsonElement>();
            var ids = new HashSet<string>(StringComparer.Ordinal);
            int? reportedTotal = null;
            var pageMetadataConsistent = true;
            var duplicateDetected = false;
            var pageOffset = 0;
            // DNSPod 的域名和解析列表都支持单次最多 3000 条。使用最大页大小可以
            // 在通常账号规模下只读取一个稳定快照，避免 100 条分页期间云端列表
            // 发生排序/数量变化而把同一域名拆到不同页面，进而误报“分页不稳定”。
            // SSL 证书接口最大页大小为 1000，其他列表继续使用保守的 100。
            var pageSize = action switch
            {
                "DescribeDomainList" or "DescribeRecordList" => 3000,
                "DescribeCertificates" => 1000,
                _ => 100
            };
            var candidateReady = false;
            var retryAttempt = false;
            for (var page = 0; page < 1000; page++)
            {
                parameters["Offset"] = pageOffset;
                parameters["Limit"] = pageSize;
                var r = await api.CallAsync(account, service, action, parameters, false, ct);
                if (!r.Success) return CloudJson.Fail<IReadOnlyList<JsonElement>, JsonElement>(r);
                var count = CloudJson.Number(countObject is null ? r.Data : CloudJson.Object(r.Data, countObject), countName);
                if (count is >= 0)
                {
                    reportedTotal = count;
                }
                if (!CloudJson.Array(r.Data, arrayName, out var rows))
                {
                    // 某些账号在空列表或刚删除记录的短暂窗口中会省略数组字段；只有明确总数为 0
                    // 且本轮尚未收集记录时，才能把它解释成空快照，否则视为无效响应并重试。
                    if (result.Count == 0 && count == 0) return ApiResult<IReadOnlyList<JsonElement>>.Ok([]);
                    return CloudJson.Incomplete<IReadOnlyList<JsonElement>>();
                }
                var rowCount = rows.GetArrayLength();
                if (rowCount == 0)
                {
                    // 空页是当前快照的结束标记。若 TotalCount 仍是删除前的旧值，先记为候选，
                    // 后续通过连续两次相同快照确认，而不是把可能的部分结果直接返回。
                    candidateReady = true;
                    break;
                }
                var added = 0;
                foreach (var row in rows.EnumerateArray())
                {
                    if (row.ValueKind != JsonValueKind.Object)
                        return CloudJson.Incomplete<IReadOnlyList<JsonElement>>();
                    var id = CloudJson.Text(row, idName);
                    if (id.Length == 0)
                        return CloudJson.Incomplete<IReadOnlyList<JsonElement>>();
                    if (!ids.Add(id))
                    {
                        duplicateDetected = true;
                        continue;
                    }
                    var values = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(row.GetRawText())!;
                    values["RequestId"] = JsonSerializer.SerializeToElement(RequestId(r.Data));
                    result.Add(JsonSerializer.SerializeToElement(values));
                    added++;
                }
                if (retryAttempt) break;
                if (action == "DescribeRecordList")
                {
                    var listCount = CloudJson.Number(CloudJson.Object(r.Data, "RecordCountInfo"), "ListCount");
                    if (listCount is null || listCount != rowCount) pageMetadataConsistent = false;
                }
                // 总数是提示而不是一致性凭证；当本轮已收齐它时可以直接结束，即使当前页因索引延迟
                // 与上一页重叠。此判断必须早于“重复页”判断，以兼容云端返回完整重叠页的情况。
                if (reportedTotal is >= 0 && result.Count >= reportedTotal)
                {
                    candidateReady = true;
                    break;
                }
                if (added == 0)
                {
                    retryAttempt = true;
                    break;
                }

                // 依据实际返回条数推进，而不是 result.Count。分页重叠时后者不会增长，继续请求会卡在同一页。
                pageOffset += rowCount;
                // 短页通常意味着已到末页，但若云端计数仍大于已收集条数，再探测一次：
                // 这同时兼容服务端实际页大小小于请求 Limit 的情况和删除后的旧 TotalCount。
            }
            // 返回结构异常、重复页或保护页数耗尽时，丢弃本轮结果并从第一页重新抓取。
            if (retryAttempt || !candidateReady)
            {
                previousCandidate = null;
                continue;
            }

            var stronglyConsistent = pageMetadataConsistent
                && reportedTotal is >= 0 && result.Count == reportedTotal;
            if (stronglyConsistent) return ApiResult<IReadOnlyList<JsonElement>>.Ok(result);

            // 有重复 ID 且总数仍大于已收集数量时，无法证明缺失记录已经补齐；即使连续读到同样的
            // 部分集合，也不能把它当作完整快照返回。
            if (duplicateDetected && (reportedTotal is null || result.Count < reportedTotal))
            {
                previousCandidate = null;
                continue;
            }

            // 删除后的云端索引可能让计数和数组暂时不同步。只有连续两次读取的完整集合与内容一致，
            // 才接受当前集合；否则继续从第一页重试，避免把中间页当成完整快照。
            if (previousCandidate is not null && SnapshotEquals(previousCandidate, result, idName))
                return ApiResult<IReadOnlyList<JsonElement>>.Ok(result);
            previousCandidate = result;
        }
        return CloudJson.Incomplete<IReadOnlyList<JsonElement>>();
    }

    private async Task<ApiResult<bool>> WaitForRecordVisibilityAsync(CloudAccountCredentials account, string zone,
        string recordId, CancellationToken ct)
    {
        const int maxAttempts = 5;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            var records = await ListRecordsAsync(account, zone, ct);
            if (records.Success && records.Data?.Any(x => x.Id == recordId) == true)
                return ApiResult<bool>.Ok(true);

            // 新记录尚未进入索引，或本次读取仍处于云端最终一致性窗口；下一轮重新抓取。
            // 其他查询失败也不能把写入当作已确认，继续等待到上限后由调用方返回
            // OutcomeUnknown，避免用户重复创建同一条记录。
            if (attempt < maxAttempts)
                await Task.Delay(PaginationRetryDelay("DescribeRecordList", attempt + 1), ct);
        }

        return ApiResult<bool>.Fail("CloudRecordVisibilityPending", "云端尚未确认新 DNS 记录已进入解析索引。");
    }

    private static TimeSpan PaginationRetryDelay(string action, int attempt)
    {
        if (action == "DescribeRecordList")
            return attempt switch
            {
                2 => TimeSpan.FromMilliseconds(500),
                3 => TimeSpan.FromSeconds(1),
                4 => TimeSpan.FromSeconds(2),
                5 => TimeSpan.FromSeconds(4),
                6 => TimeSpan.FromSeconds(6),
                7 => TimeSpan.FromSeconds(8),
                _ => TimeSpan.FromSeconds(8)
            };

        return attempt switch
        {
            2 => TimeSpan.FromMilliseconds(250),
            3 => TimeSpan.FromMilliseconds(500),
            4 => TimeSpan.FromMilliseconds(1000),
            5 => TimeSpan.FromMilliseconds(2000),
            _ => TimeSpan.FromMilliseconds(3000)
        };
    }

    private static bool SnapshotEquals(IReadOnlyList<JsonElement> left, IReadOnlyList<JsonElement> right, string idName)
    {
        if (left.Count != right.Count) return false;
        var first = left.ToDictionary(x => CloudJson.Text(x, idName), SnapshotFingerprint, StringComparer.Ordinal);
        var second = right.ToDictionary(x => CloudJson.Text(x, idName), SnapshotFingerprint, StringComparer.Ordinal);
        return first.Count == second.Count && first.All(pair => second.TryGetValue(pair.Key, out var value) && value == pair.Value);
    }

    private static string SnapshotFingerprint(JsonElement row)
    {
        var values = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var property in row.EnumerateObject())
            if (!property.NameEquals("RequestId")) values[property.Name] = property.Value.GetRawText();
        return JsonSerializer.Serialize(values);
    }
    private static CloudCertificate ParseCertificate(JsonElement x, string fallbackId, string requestId)
    {
        var id = CloudJson.Text(x, "CertificateId"); if (id.Length == 0) id = fallbackId;
        var raw = CloudJson.Text(x, "Status");
        var state = raw switch { "0" => "Pending", "1" => "Issued", "2" => "Failed", "3" => "Expired", "4" => "Validating",
            "5" or "8" or "12" or "13" => "Pending", "6" => "Cancelling", "7" => "Cancelled", "9" => "Revoking", "10" => "Revoked", "11" => "Pending", "14" => "Refunded", _ => "Unknown" };
        var product = CloudJson.Text(x, "PackageType");
        bool? free = product == "83" ? true : product.Length == 0 ? null : false;
        return new(new(id, CloudJson.Text(x, "OrderId")), CloudJson.Text(x, "Domain"), CloudJson.Text(x, "Alias"), state, raw, free, product,
            CloudJson.ChinaTime(CloudJson.Text(x, "CertBeginTime")), CloudJson.ChinaTime(CloudJson.Text(x, "CertEndTime")), CloudJson.Text(x, "VerifyType"), requestId);
    }
    // DNS 挑战的 DvAuthKey 是完整记录名；DvAuthSubDomain 是相对子域，不能再拼一次证书域名。
    private static DnsChallenge Challenge(JsonElement x, string domain) => new(CloudJson.Text(x, "DvAuthDomain") is { Length: > 0 } d ? d : domain,
        CloudJson.Text(x, "DvAuthKey"), CloudJson.Text(x, "DvAuthVerifyType").ToUpperInvariant(), CloudJson.Text(x, "DvAuthValue"));
    private static DnsRecord ParseRecord(JsonElement x, string zone) => new(CloudJson.Text(x, "RecordId"), zone, CloudJson.Text(x, "Name"), CloudJson.Text(x, "Type"),
        CloudJson.Text(x, "Value"), CloudJson.Number(x, "TTL") ?? 600, CloudJson.Text(x, "Status") switch { "ENABLE" => "Enabled", "DISABLE" => "Disabled", _ => "Unknown" },
        CloudJson.Text(x, "Line"), RequestId(x), CloudJson.Number(x, "MX"));
    private static string RequestId(JsonElement x) => CloudJson.Token(CloudJson.Text(x, "RequestId"));
}
