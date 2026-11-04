using System.Text.Json;
using System.Text.RegularExpressions;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>Cloudflare 权威 DNS 托管区域与记录适配；公网证书由腾讯云或 ACME 签发。</summary>
public sealed class CloudflareCloudService(CloudflareApiClient api) : IDnsProvider
{
    public string Provider => "Cloudflare";

    public async Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        var result = await ListZonesAsync(account, ct);
        return result.Success ? ApiResult<CloudConnectionTest>.Ok(new(Provider, "", "Cloudflare 区域查询通过，未写入 DNS。"))
            : CloudJson.Fail<CloudConnectionTest, IReadOnlyList<DnsZone>>(result);
    }

    public async Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        if (account.AccessKeyId.Length > 0 && !HexId(account.AccessKeyId))
            return CloudJson.Invalid<IReadOnlyList<DnsZone>>("Cloudflare Account ID 应为 32 位十六进制标识，可留空。");
        var filter = account.AccessKeyId.Length == 0 ? "" : "account.id=" + Uri.EscapeDataString(account.AccessKeyId);
        var result = await PagesAsync(account, "/zones", filter, ct);
        if (!result.Success) return CloudJson.Fail<IReadOnlyList<DnsZone>, IReadOnlyList<JsonElement>>(result);
        var zones = new List<DnsZone>();
        foreach (var row in result.Data!)
        {
            var id = CloudJson.Text(row, "id"); var name = Normalize(CloudJson.Text(row, "name"));
            if (!HexId(id) || !CloudJson.Domain(name)) return InvalidResponse<IReadOnlyList<DnsZone>>();
            zones.Add(new(id, name, CloudJson.Text(row, "status"), Strings(row, "name_servers"), ""));
        }
        return ApiResult<IReadOnlyList<DnsZone>>.Ok(zones);
    }

    public async Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default)
    {
        var resolved = await ResolveZoneAsync(account, zone, ct);
        if (!resolved.Success || resolved.Data is null) return CloudJson.Fail<IReadOnlyList<DnsRecord>, DnsZone>(resolved);
        var result = await PagesAsync(account, $"/zones/{resolved.Data.Id}/dns_records", "", ct);
        if (!result.Success) return CloudJson.Fail<IReadOnlyList<DnsRecord>, IReadOnlyList<JsonElement>>(result);
        var records = new List<DnsRecord>();
        foreach (var row in result.Data!)
        {
            var record = ParseRecord(row, resolved.Data.Name);
            if (record is null) return InvalidResponse<IReadOnlyList<DnsRecord>>();
            records.Add(record);
        }
        return ApiResult<IReadOnlyList<DnsRecord>>.Ok(records);
    }

    public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default)
        => WriteRecordAsync(account, zone, null, request, ct);

    public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string recordId, DnsRecordRequest request, CancellationToken ct = default)
        => WriteRecordAsync(account, zone, recordId, request, ct);

    private async Task<ApiResult<DnsRecord>> WriteRecordAsync(CloudAccountCredentials account, string zone, string? recordId, DnsRecordRequest request, CancellationToken ct)
    {
        if (!CloudJson.RecordInput(zone, request) || recordId is not null && !HexId(recordId))
            return CloudJson.Invalid<DnsRecord>("DNS 区域、记录 ID 或记录参数无效。");
        if (request.Type is "CAA" or "SRV")
            return ApiResult<DnsRecord>.Fail("DNS_STRUCTURED_RECORD_UNSUPPORTED", "Cloudflare CAA/SRV 需要独立结构字段，当前可同步查看，请在 Cloudflare 控制台编辑。");
        if (request.Line != "default") return CloudJson.Invalid<DnsRecord>("Cloudflare 不支持此 DNS 线路参数。");
        if (request.Type == "MX" && request.Mx is not (>= 0 and <= 65535))
            return CloudJson.Invalid<DnsRecord>("MX 记录需要 0 至 65535 的优先级。");
        var name = AbsoluteName(request.Name, zone);
        if (name.Length > 253 || !BelongsTo(name, zone) || !ValidRecordName(name))
            return CloudJson.Invalid<DnsRecord>("DNS 记录名称必须属于当前托管区域。");
        var resolved = await ResolveZoneAsync(account, zone, ct);
        if (!resolved.Success || resolved.Data is null) return CloudJson.Fail<DnsRecord, DnsZone>(resolved);
        var expectedProxy = false;
        if (recordId is not null)
        {
            var found = await api.CallAsync(account, HttpMethod.Get, $"/zones/{resolved.Data.Id}/dns_records/{recordId}", null, false, ct);
            if (!found.Success) return CloudJson.Fail<DnsRecord, JsonElement>(found);
            var original = ParseRecord(Result(found.Data), resolved.Data.Name);
            if (original is null || original.Id != recordId) return InvalidResponse<DnsRecord>();
            // 普通记录编辑保留代理状态，避免改 TTL 或地址时意外切换流量；验证编排只创建 DNS only 记录。
            expectedProxy = request.Type is "A" or "AAAA" or "CNAME" &&
                Result(found.Data).TryGetProperty("proxied", out var originalProxy) && originalProxy.ValueKind == JsonValueKind.True;
        }
        var body = new Dictionary<string, object> { ["type"] = request.Type, ["name"] = name,
            ["content"] = request.Value, ["ttl"] = request.Ttl };
        // DNS-01 与腾讯验证 CNAME 必须为 DNS only；代理不能被当成记录启用状态。
        if (request.Type is "A" or "AAAA" or "CNAME") body["proxied"] = expectedProxy;
        if (request.Type == "MX") body["priority"] = request.Mx!.Value;
        var path = $"/zones/{resolved.Data.Id}/dns_records" + (recordId is null ? "" : "/" + recordId);
        var response = await api.CallAsync(account, recordId is null ? HttpMethod.Post : HttpMethod.Patch, path, body, true, ct);
        if (!response.Success) return CloudJson.Fail<DnsRecord, JsonElement>(response);
        var written = ParseRecord(Result(response.Data), resolved.Data.Name);
        if (written is null || recordId is not null && written.Id != recordId ||
            AbsoluteName(written.Name, zone) != name || !SameRecordValue(written, request) ||
            (Result(response.Data).TryGetProperty("proxied", out var proxied) && proxied.ValueKind == JsonValueKind.True) != expectedProxy)
            return ApiResult<DnsRecord>.Fail("OutcomeUnknown", "Cloudflare 写入回执与请求不一致，请只读核对原记录，勿重复创建。");
        return ApiResult<DnsRecord>.Ok(written);
    }

    public Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string recordId, bool enabled, CancellationToken ct = default)
        => Task.FromResult(ApiResult<CloudOperation>.Fail("DNS_STATUS_UNSUPPORTED", "Cloudflare 没有记录启用/停用接口；代理开关不等于启用/停用，未修改记录。"));

    public async Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string recordId, CancellationToken ct = default)
    {
        if (!HexId(recordId)) return CloudJson.Invalid<CloudOperation>("DNS 记录 ID 无效。");
        var resolved = await ResolveZoneAsync(account, zone, ct);
        if (!resolved.Success || resolved.Data is null) return CloudJson.Fail<CloudOperation, DnsZone>(resolved);
        var found = await ReadRecordAsync(account, resolved.Data, recordId, ct);
        if (!found.Success) return CloudJson.Fail<CloudOperation, DnsRecord>(found);
        var response = await api.CallAsync(account, HttpMethod.Delete, $"/zones/{resolved.Data.Id}/dns_records/{recordId}", null, true, ct);
        if (!response.Success) return CloudJson.Fail<CloudOperation, JsonElement>(response);
        return CloudJson.Text(Result(response.Data), "id") == recordId
            ? ApiResult<CloudOperation>.Ok(new("", "Deleted"))
            : ApiResult<CloudOperation>.Fail("OutcomeUnknown", "Cloudflare 删除回执缺少匹配的记录 ID，请只读核对原记录。");
    }

    private async Task<ApiResult<DnsZone>> ResolveZoneAsync(CloudAccountCredentials account, string zone, CancellationToken ct)
    {
        if (!CloudJson.Domain(zone)) return CloudJson.Invalid<DnsZone>("DNS 区域名称无效。");
        var zones = await ListZonesAsync(account, ct);
        if (!zones.Success || zones.Data is null) return CloudJson.Fail<DnsZone, IReadOnlyList<DnsZone>>(zones);
        var matching = zones.Data.Where(value => value.Name == Normalize(zone)).ToArray();
        return matching.Length == 1 ? ApiResult<DnsZone>.Ok(matching[0])
            : ApiResult<DnsZone>.Fail("DNS_ZONE_NOT_FOUND", "Cloudflare Token 可访问的区域中不存在唯一匹配项。");
    }

    private async Task<ApiResult<DnsRecord>> ReadRecordAsync(CloudAccountCredentials account, DnsZone zone, string recordId, CancellationToken ct)
    {
        var result = await api.CallAsync(account, HttpMethod.Get, $"/zones/{zone.Id}/dns_records/{recordId}", null, false, ct);
        if (!result.Success) return CloudJson.Fail<DnsRecord, JsonElement>(result);
        var record = ParseRecord(Result(result.Data), zone.Name);
        return record is null || record.Id != recordId ? InvalidResponse<DnsRecord>() : ApiResult<DnsRecord>.Ok(record);
    }

    /// <summary>只有完整连续、标识唯一且总数稳定的分页才返回；任何失败都不泄漏部分快照。</summary>
    private async Task<ApiResult<IReadOnlyList<JsonElement>>> PagesAsync(CloudAccountCredentials account, string path, string filter, CancellationToken ct)
    {
        const int pageSize = 50;
        var rows = new List<JsonElement>(); var ids = new HashSet<string>(StringComparer.Ordinal);
        int? total = null; int? pages = null;
        for (var page = 1; page <= 2000; page++)
        {
            var query = (filter.Length == 0 ? "" : filter + "&") + $"page={page}&per_page={pageSize}";
            var result = await api.CallAsync(account, HttpMethod.Get, path + "?" + query, null, false, ct);
            if (!result.Success) return CloudJson.Fail<IReadOnlyList<JsonElement>, JsonElement>(result);
            if (!CloudJson.Array(result.Data, "result", out var data)) return InvalidResponse<IReadOnlyList<JsonElement>>();
            var current = data.EnumerateArray().ToArray(); var info = CloudJson.Object(result.Data, "result_info");
            var currentTotal = CloudJson.Number(info, "total_count"); var currentPages = CloudJson.Number(info, "total_pages");
            if (CloudJson.Number(info, "page") is { } reported && reported != page ||
                CloudJson.Number(info, "count") is { } count && count != current.Length ||
                currentTotal is < 0 || currentPages is < 0 || total is not null && currentTotal != total || pages is not null && currentPages != pages)
                return CloudJson.Incomplete<IReadOnlyList<JsonElement>>();
            total ??= currentTotal; pages ??= currentPages;
            foreach (var row in current)
            {
                var id = CloudJson.Text(row, "id");
                if (!CloudJson.Id(id) || !ids.Add(id)) return CloudJson.Incomplete<IReadOnlyList<JsonElement>>();
                rows.Add(row.Clone());
            }
            if (rows.Count > 100000 || total is not null && rows.Count > total) return CloudJson.Incomplete<IReadOnlyList<JsonElement>>();
            var last = pages is not null ? page >= Math.Max(1, pages.Value) : total is not null ? rows.Count >= total : current.Length < pageSize;
            if (last)
                return total is not null && rows.Count != total ? CloudJson.Incomplete<IReadOnlyList<JsonElement>>()
                    : ApiResult<IReadOnlyList<JsonElement>>.Ok(rows);
            if (current.Length == 0) return CloudJson.Incomplete<IReadOnlyList<JsonElement>>();
        }
        return CloudJson.Incomplete<IReadOnlyList<JsonElement>>();
    }

    private static DnsRecord? ParseRecord(JsonElement row, string zone)
    {
        var id = CloudJson.Text(row, "id"); var name = Normalize(CloudJson.Text(row, "name"));
        var type = CloudJson.Text(row, "type").ToUpperInvariant(); var content = CloudJson.Text(row, "content");
        if (!HexId(id) || !BelongsTo(name, zone) || type.Length == 0 || CloudJson.Number(row, "ttl") is not { } ttl || ttl < 1)
            return null;
        return new(id, zone, name == Normalize(zone) ? "@" : name[..^(Normalize(zone).Length + 1)], type, content,
            ttl, "Enabled", "default", "", CloudJson.Number(row, "priority"),
            row.TryGetProperty("proxied", out var proxy) && proxy.ValueKind == JsonValueKind.True);
    }

    private static bool SameRecordValue(DnsRecord record, DnsRecordRequest request) => record.Type == request.Type &&
        (request.Type is "CNAME" or "NS" ? Normalize(record.Value) == Normalize(request.Value) : record.Value == request.Value) &&
        (request.Type != "MX" || record.Mx == request.Mx);
    private static JsonElement Result(JsonElement envelope) => envelope.ValueKind == JsonValueKind.Object && envelope.TryGetProperty("result", out var result) ? result : default;
    private static string[] Strings(JsonElement row, string key) => CloudJson.Array(row, key, out var values)
        ? values.EnumerateArray().Where(value => value.ValueKind == JsonValueKind.String).Select(value => value.GetString()!).ToArray() : [];
    private static bool HexId(string value) => Regex.IsMatch(value, "^[a-fA-F0-9]{32}$", RegexOptions.CultureInvariant);
    private static string Normalize(string value) => value.Trim().TrimEnd('.').ToLowerInvariant();
    private static bool BelongsTo(string name, string zone) => Normalize(name) == Normalize(zone) || Normalize(name).EndsWith("." + Normalize(zone), StringComparison.Ordinal);
    private static string AbsoluteName(string name, string zone) => name == "@" ? Normalize(zone) : BelongsTo(name, zone) ? Normalize(name) : Normalize(name) + "." + Normalize(zone);
    private static bool ValidRecordName(string value) => Regex.IsMatch(value, @"^(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]*$", RegexOptions.CultureInvariant);
    private static ApiResult<T> InvalidResponse<T>() => ApiResult<T>.Fail("CloudInvalidResponse", "Cloudflare 响应的资源身份或字段无效，未使用不完整结果。");
}
