using System.Globalization;
using System.Text.Json;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>阿里云 CAS V2 证书实例适配；历史 V1 订单仅用于同步和兼容查询，不再接受 V1 申请。</summary>
public sealed class AliyunCloudService(AliyunApiClient api) : ICloudCertificateService, IDnsProvider
{
    public const string FreeProduct = "digicert-free-1-free";
    public string Provider => "Aliyun";
    public async Task<ApiResult<CloudConnectionTest>> TestAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        var r = await Call(account, "cas", "ListInstances", new() { ["InstanceType"] = "TEST", ["CurrentPage"] = "1", ["ShowSize"] = "1" }, false, ct);
        return r.Success ? ApiResult<CloudConnectionTest>.Ok(new(Provider, RequestId(r.Data), "CAS 查询权限验证通过；未领取或申请证书。")) : CloudJson.Fail<CloudConnectionTest, JsonElement>(r);
    }
    public async Task<ApiResult<CloudConnectionTest>> TestDnsAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        var r = await Call(account, "alidns", "DescribeDomains", new() { ["PageNumber"] = "1", ["PageSize"] = "1" }, false, ct);
        return r.Success ? ApiResult<CloudConnectionTest>.Ok(new(Provider, RequestId(r.Data), "DNS 查询权限验证通过，未写入记录。")) : CloudJson.Fail<CloudConnectionTest, JsonElement>(r);
    }

    public async Task<ApiResult<IReadOnlyList<AliyunContact>>> ListContactsAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        var all = await Pages(account, "cas", "ListContact", "ContactList", null, "ContactId", "CurrentPage", "ShowSize", [], ct);
        if (!all.Success) return CloudJson.Fail<IReadOnlyList<AliyunContact>, IReadOnlyList<JsonElement>>(all);
        var contacts = all.Data!.Select(x => new AliyunContact(
            CloudJson.Text(x, "ContactId"), CloudJson.Text(x, "Name"), CloudJson.Text(x, "Mobile"),
            CloudJson.Number(x, "MobileStatus") == 1, CloudJson.Text(x, "Email"),
            CloudJson.Number(x, "EmailStatus") == 1)).Where(x => CloudJson.NumericId(x.Id)).ToArray();
        return ApiResult<IReadOnlyList<AliyunContact>>.Ok(contacts);
    }

    public async Task<ApiResult<IReadOnlyList<AliyunCertificateInstanceOption>>> ListAliyunInstancesAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        var all = await Pages(account, "cas", "ListInstances", "InstanceList", null, "InstanceId", "CurrentPage", "ShowSize",
            new() { ["InstanceType"] = "TEST" }, ct);
        if (!all.Success) return CloudJson.Fail<IReadOnlyList<AliyunCertificateInstanceOption>, IReadOnlyList<JsonElement>>(all);
        // “未使用”按云端是否已绑定证书/域名判断；只返回已确认的基础免费规格，避免下拉框出现收费或未知实例。
        var result = all.Data!
            .Where(IsUnusedFreeTestInstance)
            .Select(x => new AliyunCertificateInstanceOption(
                CloudJson.Text(x, "InstanceId"),
                FirstText(x, "CertificateName", "InstanceName", "Name"),
                CloudJson.Text(x, "Domain"),
                FirstText(x, "Status", "CertificateStatus", "InstanceStatus"),
                CloudJson.Text(x, "Spec")))
            .Where(x => CloudJson.Id(x.InstanceId))
            .ToArray();
        return ApiResult<IReadOnlyList<AliyunCertificateInstanceOption>>.Ok(result);
    }

    /// <summary>列表选择与实际提交前共用未使用判定，防止期间被控制台或其他调用方占用后覆盖。</summary>
    private static bool IsUnusedFreeTestInstance(JsonElement instance) => Free(CloudJson.Text(instance, "Spec")) == true &&
        IsEmptyRemoteId(CloudJson.Text(instance, "CertificateId")) && string.IsNullOrWhiteSpace(CloudJson.Text(instance, "Domain")) &&
        (FirstText(instance, "Status", "CertificateStatus", "InstanceStatus").Length == 0 ||
         FirstText(instance, "Status", "CertificateStatus", "InstanceStatus").Equals("inactive", StringComparison.OrdinalIgnoreCase));

    public async Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        var old = await ListV1(account, ct);
        if (!old.Success) return CloudJson.Fail<IReadOnlyList<CloudCertificate>, IReadOnlyList<CloudCertificate>>(old);
        var instances = await Pages(account, "cas", "ListInstances", "InstanceList", null, "InstanceId", "CurrentPage", "ShowSize", new() { ["InstanceType"] = "TEST" }, ct);
        if (!instances.Success) return CloudJson.Fail<IReadOnlyList<CloudCertificate>, IReadOnlyList<JsonElement>>(instances);
        var certificates = await Pages(account, "cas", "ListCertificates", "CertificateList", null, "CertificateId", "CurrentPage", "ShowSize", new() { ["CertificateSource"] = "TEST" }, ct);
        if (!certificates.Success) return CloudJson.Fail<IReadOnlyList<CloudCertificate>, IReadOnlyList<JsonElement>>(certificates);
        var result = new Dictionary<string, CloudCertificate>(StringComparer.Ordinal);
        var instanceById = instances.Data!.ToDictionary(x => CloudJson.Text(x, "InstanceId"), StringComparer.Ordinal);
        var certificateIds = certificates.Data!.Select(x => CloudJson.Text(x, "CertificateId")).ToHashSet(StringComparer.Ordinal);
        foreach (var row in instances.Data!)
        {
            // 删除证书文件后，阿里云仍可能保留 closed 实例及其旧证书 ID。
            // 只有完整证书列表也包含该证书时才导入这种实例，避免已删除证书被同步“复活”。
            var certificateId = CloudJson.Text(row, "CertificateId");
            if (CloudJson.Text(row, "Status").Equals("closed", StringComparison.OrdinalIgnoreCase) &&
                CloudJson.NumericId(certificateId) && !certificateIds.Contains(certificateId)) continue;
            var item = ParseV2(row, true);
            result[Key(item.Reference)] = item;
        }
        foreach (var row in certificates.Data!)
        {
            var item = ParseV2(row, false);
            if (instanceById.TryGetValue(item.Reference.InstanceId, out var instance))
                item = item with { ProductCode = CloudJson.Text(instance, "Spec"), IsFree = Free(CloudJson.Text(instance, "Spec")) };
            result[Key(item.Reference)] = item;
        }
        // 已确认删除的 V2 证书也参与版本去重，防止旧订单残留再次将同一证书导入。
        var v2Ids = instances.Data.Select(x => CloudJson.Text(x, "CertificateId"))
            .Concat(certificateIds).Where(x => x.Length > 0).ToHashSet(StringComparer.Ordinal);
        // 同一张证书若同时出现在旧列表和新列表，保留 V2 引用，不混用旧订单操作。
        foreach (var item in old.Data!) if (item.Reference.CertificateId.Length == 0 || !v2Ids.Contains(item.Reference.CertificateId)) result[Key(item.Reference)] = item;
        return ApiResult<IReadOnlyList<CloudCertificate>>.Ok(result.Values.ToArray());
    }
    private async Task<ApiResult<IReadOnlyList<CloudCertificate>>> ListV1(CloudAccountCredentials account, CancellationToken ct)
    {
        var all = await Pages(account, "cas", "ListUserCertificateOrder", "CertificateOrderList", null, "OrderId", "CurrentPage", "ShowSize", new() { ["OrderType"] = "CPACK" }, ct);
        return all.Success ? ApiResult<IReadOnlyList<CloudCertificate>>.Ok(all.Data!.Select(ParseV1).ToArray()) : CloudJson.Fail<IReadOnlyList<CloudCertificate>, IReadOnlyList<JsonElement>>(all);
    }

    public async Task<ApiResult<CloudCertificateDetail>> GetAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
    {
        if (reference.ApiVersion == "V2")
        {
            if (!CloudJson.Id(reference.InstanceId) && !CloudJson.NumericId(reference.CertificateId)) return CloudJson.Invalid<CloudCertificateDetail>("V2 需要实例 ID 或证书 ID。");
            var hasInstance = CloudJson.Id(reference.InstanceId);
            var r = await Call(account, "cas", hasInstance ? "GetInstanceDetail" : "GetCertificateDetail",
                new() { [hasInstance ? "InstanceId" : "CertificateId"] = hasInstance ? reference.InstanceId : reference.CertificateId }, false, ct);
            if (!r.Success) return CloudJson.Fail<CloudCertificateDetail, JsonElement>(r);
            var cert = ParseV2(r.Data, hasInstance);
            if (hasInstance && cert.Reference.InstanceId != reference.InstanceId) return ApiResult<CloudCertificateDetail>.Fail("CloudIdentityMismatch", "阿里云返回实例 ID 不一致。");
            if (!hasInstance && !string.IsNullOrEmpty(reference.CertificateId) && cert.Reference.CertificateId != reference.CertificateId)
                return ApiResult<CloudCertificateDetail>.Fail("CloudIdentityMismatch", "阿里云返回证书 ID 与查询条件不一致。");
            if (hasInstance && CloudJson.NumericId(reference.CertificateId))
            {
                // 实例关闭后仍保留旧证书字段；精确查询证书确认存在，不能仅凭实例残留返回成功。
                var exact = await GetAsync(account, reference with { InstanceId = "" }, ct);
                if (!exact.Success) return exact;
                if (exact.Data!.Certificate.Reference.InstanceId != reference.InstanceId)
                    return ApiResult<CloudCertificateDetail>.Fail("CloudIdentityMismatch", "历史证书不属于指定实例，已阻止混用。");
                var verified = exact.Data.Certificate with { Reference = reference, IsFree = cert.IsFree, ProductCode = cert.ProductCode };
                // 查询历史证书时保留精确证书详情，当前证书仍需使用实例返回的域名验证材料。
                if (cert.Reference.CertificateId != reference.CertificateId)
                    return ApiResult<CloudCertificateDetail>.Ok(exact.Data with { Certificate = verified });
                cert = verified;
            }
            var challenges = new List<DnsChallenge>();
            if (CloudJson.Array(r.Data, "DomainValidationList", out var rows))
                foreach (var row in rows.EnumerateArray())
                {
                    var domain = CloudJson.Text(row, "Domain"); var root = CloudJson.Text(row, "RootDomain");
                    var key = CloudJson.Text(row, "ValidationKey");
                    var type = CloudJson.Text(row, "ValidationType").ToUpperInvariant();
                    if (key.Length > 0) challenges.Add(new(domain, FullName(key, root.Length > 0 ? root : domain), type, CloudJson.Text(row, "ValidationValue")));
                    var cnameKey = CloudJson.Text(row, "CnameKey"); var cname = CloudJson.Text(row, "Cname");
                    if (cnameKey.Length > 0 && cname.Length > 0) challenges.Add(new(domain, FullName(cnameKey, root.Length > 0 ? root : domain), "CNAME", cname, true));
                }
            // 同一记录若同时用于长期免验证授权，优先保留长期标记，避免临时清理误删。
            var unique = challenges.GroupBy(x => (x.Domain, x.Name, x.Type, x.Value))
                .Select(group => group.First() with { IsPersistent = group.Any(x => x.IsPersistent) }).ToArray();
            return ApiResult<CloudCertificateDetail>.Ok(new(cert, unique));
        }
        if (reference.ApiVersion != "V1") return CloudJson.Invalid<CloudCertificateDetail>("阿里云 API 版本无效。");
        if (!CloudJson.NumericId(reference.OrderId)) return CloudJson.Invalid<CloudCertificateDetail>("V1 详情需要订单 ID。");
        var orders = await ListV1(account, ct);
        if (!orders.Success) return CloudJson.Fail<CloudCertificateDetail, IReadOnlyList<CloudCertificate>>(orders);
        var order = orders.Data!.FirstOrDefault(x => x.Reference.OrderId == reference.OrderId);
        if (order is null) return ApiResult<CloudCertificateDetail>.Fail("CloudOrderNotFound", "当前账号的完整订单列表中找不到此 V1 订单。");
        var state = await Call(account, "cas", "DescribeCertificateState", new() { ["OrderId"] = reference.OrderId }, false, ct);
        if (!state.Success) return CloudJson.Fail<CloudCertificateDetail, JsonElement>(state);
        var raw = CloudJson.Text(state.Data, "Type"); var domainName = CloudJson.Text(state.Data, "Domain");
        if (domainName.Length == 0) domainName = order.Domain;
        var certId = CloudJson.Text(state.Data, "CertId");
        var resultReference = reference with { CertificateId = certId.Length > 0 ? certId : reference.CertificateId };
        var details = new List<DnsChallenge>();
        if (raw == "domain_verify")
        {
            var type = CloudJson.Text(state.Data, "RecordType");
            if (CloudJson.Text(state.Data, "ValidateType") == "DNS")
            {
                var name = CloudJson.Text(state.Data, "RecordDomain");
                var absolute = name.EndsWith('.') || name.TrimEnd('.').Equals(domainName, StringComparison.OrdinalIgnoreCase)
                    || name.TrimEnd('.').EndsWith('.' + domainName, StringComparison.OrdinalIgnoreCase);
                details.Add(new(domainName, name, type, CloudJson.Text(state.Data, "RecordValue"), IsRelative: !absolute));
            }
            else details.Add(new(domainName, CloudJson.Text(state.Data, "Uri"), "FILE", CloudJson.Text(state.Data, "Content")));
        }
        // DescribeCertificateState 在已签发时包含私钥，仅提取白名单元数据返回，绝不序列化原文。
        var certificate = order with { Reference = resultReference, Domain = domainName, Status = V1State(raw), RawStatus = raw,
            ValidationMode = CloudJson.Text(state.Data, "ValidateType"), RequestId = RequestId(state.Data) };
        return ApiResult<CloudCertificateDetail>.Ok(new(certificate, details));
    }

    public async Task<ApiResult<CloudCertificateDetail>> ApplyAsync(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct = default)
    {
        if (!CloudJson.Domain(request.Domain) || request.Alias is null || request.Alias.Length > 100) return CloudJson.Invalid<CloudCertificateDetail>("免费证书需要有效单域名，备注最多 100 字。");
        if (request.ApiVersion != "V2") return CloudJson.Invalid<CloudCertificateDetail>("阿里云免费证书申请已统一使用 V2 接口，请选择已领取的免费证书实例。");
        if (request.ValidationMode is not ("NativeAutoDns" or "ManagedDns" or "ManualDns" or "File"))
            return ApiResult<CloudCertificateDetail>.Fail("ValidationModeNotSupported", "阿里云 V2 申请请使用平台托管 DNS、手动 DNS 或文件验证。");
        // 阿里云申请统一走已领取的 V2 测试实例；V1 资源包接口已停用，避免错误扣费或参数漂移。
        return await ApplyV2(account, request, ct);
    }
    private async Task<ApiResult<CloudCertificateDetail>> ApplyV2(CloudAccountCredentials account, CloudCertificateApplyRequest request, CancellationToken ct)
    {
        if (!CloudJson.Id(request.InstanceId)) return CloudJson.Invalid<CloudCertificateDetail>("V2 申请需选择已在官方控制台领取的测试证书实例；平台不自动购买。");
        var read = await Call(account, "cas", "GetInstanceDetail", new() { ["InstanceId"] = request.InstanceId! }, false, ct);
        if (!read.Success) return CloudJson.Fail<CloudCertificateDetail, JsonElement>(read);
        if (CloudJson.Text(read.Data, "InstanceId") != request.InstanceId || CloudJson.Text(read.Data, "InstanceType") != "TEST")
            return ApiResult<CloudCertificateDetail>.Fail("TestInstanceRequired", "只支持当前账户已有的测试证书实例，不申请正式收费证书。");
        if (Free(CloudJson.Text(read.Data, "Spec")) != true)
            return ApiResult<CloudCertificateDetail>.Fail("FREE_PRODUCT_UNCONFIRMED", "该 V2 实例的免费规格尚未确认，请在阿里云控制台确认免费实例；平台未提交申请且不会使用 pro 或未知规格。");
        if (!IsUnusedFreeTestInstance(read.Data))
            return ApiResult<CloudCertificateDetail>.Fail("TEST_INSTANCE_ALREADY_USED", "此免费测试实例已绑定域名、证书或不再处于未使用状态，请重新读取可用实例；未更新或提交申请。");
        var reference = new CloudCertificateReference(InstanceId: request.InstanceId!, ApiVersion: "V2");
        // 配置中明确选择的联系人优先于实例历史联系人，确保每次申请都使用管理员保存的选择。
        var contactIds = CloudJson.NumericId(account.AliyunContactId)
            ? [account.AliyunContactId]
            : ReadContactIds(read.Data);
        if (contactIds.Count == 0)
        {
            var contact = await ResolveContactIdAsync(account, ct);
            if (!contact.Success || contact.Data is null) return ApiResult<CloudCertificateDetail>.Fail(contact.Code, contact.Message);
            contactIds = [contact.Data];
        }
        var updateParameters = new Dictionary<string, string>
        {
            ["InstanceId"] = request.InstanceId!, ["Domain"] = request.Domain,
            ["GenerateCsrMethod"] = "online", ["KeyAlgorithm"] = "RSA_2048",
            ["ValidationMethod"] = request.ValidationMode == "File" ? "HTTP" : "DNS", ["AutoReissue"] = "disable"
        };
        if (!string.IsNullOrWhiteSpace(request.Alias)) updateParameters["CertificateName"] = request.Alias;
        for (var i = 0; i < contactIds.Count; i++) updateParameters[$"ContactIdList.{i + 1}"] = contactIds[i];
        var update = await Call(account, "cas", "UpdateInstance", updateParameters, true, ct);
        if (!update.Success) return CloudJson.Fail<CloudCertificateDetail, JsonElement>(update);
        var apply = await Call(account, "cas", "ApplyCertificate", new() { ["InstanceId"] = request.InstanceId! }, true, ct);
        if (!apply.Success) return CloudJson.Fail<CloudCertificateDetail, JsonElement>(apply);
        var submitted = await Call(account, "cas", "GetTaskAttribute", new() { ["TaskType"] = "ApplyCertificate", ["TaskId"] = request.InstanceId! }, false, ct);
        // 异步失败要保留实例引用，编排层不会因此重新创建/购买实例。
        if (submitted.Success && CloudJson.Text(submitted.Data, "TaskStatus") == "failed")
            return ApiResult<CloudCertificateDetail>.Ok(new(new(reference, request.Domain, request.Alias, "Failed", "failed", Free(CloudJson.Text(read.Data, "Spec")),
                CloudJson.Text(read.Data, "Spec"), null, null, request.ValidationMode, RequestId(apply.Data)), [], "阿里云异步提交失败，请在控制台核对信息。"));
        var detail = await GetAsync(account, reference, ct);
        return detail.Success ? detail : Submitted(reference, request, RequestId(apply.Data), Free(CloudJson.Text(read.Data, "Spec")), CloudJson.Text(read.Data, "Spec"));
    }

    private async Task<ApiResult<string>> ResolveContactIdAsync(CloudAccountCredentials account, CancellationToken ct)
    {
        if (CloudJson.NumericId(account.AliyunContactId)) return ApiResult<string>.Ok(account.AliyunContactId);
        if (string.IsNullOrWhiteSpace(account.ContactName) || string.IsNullOrWhiteSpace(account.ContactPhone))
            return ApiResult<string>.Fail("ALIYUN_CONTACT_REQUIRED", "阿里云 V2 申请需要联系人姓名和手机号。请在配置管理填写联系人，或先在阿里云证书控制台创建并验证联系人。");
        var contacts = await Pages(account, "cas", "ListContact", "ContactList", null, "ContactId", "CurrentPage", "ShowSize", [], ct);
        if (!contacts.Success || contacts.Data is null) return CloudJson.Fail<string, IReadOnlyList<JsonElement>>(contacts);
        var candidates = contacts.Data
            .Where(x => CloudJson.Text(x, "Name").Equals(account.ContactName, StringComparison.OrdinalIgnoreCase)
                && CloudJson.Number(x, "MobileStatus") == 1
                && (string.IsNullOrWhiteSpace(account.ContactEmail)
                    || (CloudJson.Text(x, "Email").Equals(account.ContactEmail, StringComparison.OrdinalIgnoreCase) && CloudJson.Number(x, "EmailStatus") == 1)))
            .Select(x => CloudJson.Text(x, "ContactId"))
            .Where(CloudJson.NumericId)
            .Distinct(StringComparer.Ordinal)
            .ToArray();
        return candidates.Length == 1
            ? ApiResult<string>.Ok(candidates[0])
            : ApiResult<string>.Fail(candidates.Length == 0 ? "ALIYUN_CONTACT_REQUIRED" : "ALIYUN_CONTACT_AMBIGUOUS",
                candidates.Length == 0 ? "未找到已验证的阿里云证书申请联系人，请检查配置中的姓名、邮箱和手机号，或先在阿里云控制台创建并验证联系人。" : "匹配到多个阿里云证书申请联系人，请在阿里云控制台保留唯一匹配联系人后重试。");
    }

    private static List<string> ReadContactIds(JsonElement data)
    {
        if (!CloudJson.Array(data, "ContactIdList", out var values)) return [];
        return values.EnumerateArray().Select(x => x.ValueKind is JsonValueKind.Number or JsonValueKind.String ? x.ToString() : "")
            .Where(CloudJson.NumericId).Distinct(StringComparer.Ordinal).ToList();
    }

    public async Task<ApiResult<CloudOperation>> RevokeAsync(CloudAccountCredentials account, CloudCertificateReference reference, string reason, CancellationToken ct = default)
    {
        if (reason is null || reason.Length > 200) return CloudJson.Invalid<CloudOperation>("吊销原因最多 200 字。");
        if (reference.ApiVersion == "V2")
        {
            if (!CloudJson.Id(reference.InstanceId) || !CloudJson.NumericId(reference.CertificateId)) return CloudJson.Invalid<CloudOperation>("V2 吊销必须提供实例 ID 和精确证书 ID。");
            var detail = await GetAsync(account, reference, ct);
            if (!detail.Success) return CloudJson.Fail<CloudOperation, CloudCertificateDetail>(detail);
            if (detail.Data!.Certificate.Reference.InstanceId != reference.InstanceId) return ApiResult<CloudOperation>.Fail("CloudIdentityMismatch", "证书与实例不匹配。");
            if (detail.Data.Certificate.IsFree != true) return ApiResult<CloudOperation>.Fail("FREE_PRODUCT_UNCONFIRMED", "V2 证书的免费规格尚未确认，已阻止吊销未知规格证书。");
            var r = await Call(account, "cas", "RevokeCertificate", new() { ["InstanceId"] = reference.InstanceId, ["CertificateId"] = reference.CertificateId }, true, ct);
            return r.Success ? ApiResult<CloudOperation>.Ok(new(RequestId(r.Data), "Revoking")) : CloudJson.Fail<CloudOperation, JsonElement>(r);
        }
        if (reference.ApiVersion != "V1" || !CloudJson.NumericId(reference.OrderId)) return CloudJson.Invalid<CloudOperation>("V1 吊销需要有效订单 ID。");
        var all = await ListV1(account, ct);
        if (!all.Success) return CloudJson.Fail<CloudOperation, IReadOnlyList<CloudCertificate>>(all);
        var order = all.Data!.FirstOrDefault(x => x.Reference.OrderId == reference.OrderId);
        if (order?.IsFree != true) return ApiResult<CloudOperation>.Fail("FreeCertificateRequired", "未精确识别为免费证书，已阻止吊销。");
        if (order.Status is not ("Issued" or "Expiring")) return ApiResult<CloudOperation>.Fail("CertificateNotIssued", "仅已签发的证书可以吊销，未申请订单不可通过吊销接口取消。");
        var revoke = await Call(account, "cas", "CancelCertificateForPackageRequest", new() { ["OrderId"] = reference.OrderId }, true, ct);
        return revoke.Success ? ApiResult<CloudOperation>.Ok(new(RequestId(revoke.Data), "Revoking")) : CloudJson.Fail<CloudOperation, JsonElement>(revoke);
    }

    public async Task<ApiResult<CloudOperation>> CancelAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
    {
        if (reference.ApiVersion == "V2")
        {
            // V2 使用实例 ID 撤回待审核申请，不能复用 V1 的订单接口。
            if (!CloudJson.Id(reference.InstanceId))
                return ApiResult<CloudOperation>.Fail("CANCEL_UNSUPPORTED", "阿里云 V2 取消申请需要有效实例 ID。");
            var pending = await Call(account, "cas", "CancelPendingCertificate", new() { ["InstanceId"] = reference.InstanceId }, true, ct);
            return pending.Success
                ? ApiResult<CloudOperation>.Ok(new(RequestId(pending.Data), "Cancelled"), "阿里云证书申请已取消")
                : CloudJson.Fail<CloudOperation, JsonElement>(pending);
        }
        // 阿里云 V1 的 CancelOrderRequest 专门用于撤回待验证、审核中的申请订单。
        if (reference.ApiVersion != "V1" || !CloudJson.NumericId(reference.OrderId))
            return ApiResult<CloudOperation>.Fail("CANCEL_UNSUPPORTED", "阿里云 V1 取消申请需要有效订单 ID。");
        var result = await Call(account, "cas", "CancelOrderRequest", new() { ["OrderId"] = reference.OrderId }, true, ct);
        return result.Success
            ? ApiResult<CloudOperation>.Ok(new(RequestId(result.Data), "Cancelled"), "阿里云证书申请已取消")
            : CloudJson.Fail<CloudOperation, JsonElement>(result);
    }

    public async Task<ApiResult<CloudOperation>> DeleteAsync(CloudAccountCredentials account, CloudCertificateReference reference, CancellationToken ct = default)
    {
        if (reference.ApiVersion == "V2" && !CloudJson.NumericId(reference.CertificateId))
        {
            // V2 取消申请后尚未生成证书 ID，删除对应实例；已签发/已吊销实例仍走证书删除接口。
            if (!CloudJson.Id(reference.InstanceId))
                return CloudJson.Invalid<CloudOperation>("阿里云 V2 删除需要有效实例 ID。");
            var instance = await Call(account, "cas", "DeleteInstance", new() { ["InstanceId"] = reference.InstanceId }, true, ct);
            return instance.Success
                ? ApiResult<CloudOperation>.Ok(new(RequestId(instance.Data), "Deleted"), "阿里云证书实例已删除")
                : CloudJson.Fail<CloudOperation, JsonElement>(instance);
        }
        // DeleteUserCertificate 只允许删除已过期、已吊销或上传的证书；业务编排层先验证本地状态。
        var certificateId = reference.CertificateId;
        if (!CloudJson.NumericId(certificateId))
        {
            if (reference.ApiVersion is not ("V1" or "V2")) return CloudJson.Invalid<CloudOperation>("阿里云证书版本无效。");
            var detail = await GetAsync(account, reference, ct);
            if (!detail.Success || detail.Data is null) return CloudJson.Fail<CloudOperation, CloudCertificateDetail>(detail);
            certificateId = detail.Data.Certificate.Reference.CertificateId;
        }
        if (!CloudJson.NumericId(certificateId))
            return ApiResult<CloudOperation>.Fail("DELETE_UNSUPPORTED", "阿里云返回的证书 ID 不支持删除，已保留本地记录。");
        var r = await Call(account, "cas", "DeleteUserCertificate", new() { ["CertId"] = certificateId }, true, ct);
        return r.Success
            ? ApiResult<CloudOperation>.Ok(new(RequestId(r.Data), "Deleted"), "阿里云证书已删除")
            : CloudJson.Fail<CloudOperation, JsonElement>(r);
    }

    public async Task<ApiResult<CertificateDownload>> DownloadAsync(CloudAccountCredentials account, CloudCertificateReference reference, string format, CancellationToken ct = default)
    {
        var id = reference.CertificateId;
        if (!CloudJson.NumericId(id) && reference.ApiVersion == "V1")
        {
            var detail = await GetAsync(account, reference, ct);
            if (!detail.Success) return CloudJson.Fail<CertificateDownload, CloudCertificateDetail>(detail);
            id = detail.Data!.Certificate.Reference.CertificateId;
        }
        if (!CloudJson.NumericId(id)) return CloudJson.Invalid<CertificateDownload>("下载需要已签发的证书 ID。");
        var r = await Call(account, "cas", "GetUserCertificateDetail", new() { ["CertId"] = id, ["CertFilter"] = "false" }, false, ct);
        if (!r.Success) return CloudJson.Fail<CertificateDownload, JsonElement>(r);
        if (CloudJson.Text(r.Data, "Id") is { Length: > 0 } returnedId && returnedId != id)
            return ApiResult<CertificateDownload>.Fail("CloudIdentityMismatch", "下载证书 ID 不一致。");
        return CertificateDownloadHelper.FromPem(CloudJson.Text(r.Data, "Cert"), CloudJson.Text(r.Data, "Key"), id, format?.ToLowerInvariant() ?? "", RequestId(r.Data));
    }

    public async Task<ApiResult<IReadOnlyList<DnsZone>>> ListZonesAsync(CloudAccountCredentials account, CancellationToken ct = default)
    {
        var all = await Pages(account, "alidns", "DescribeDomains", "Domain", "Domains", "DomainId", "PageNumber", "PageSize", [], ct);
        if (!all.Success) return CloudJson.Fail<IReadOnlyList<DnsZone>, IReadOnlyList<JsonElement>>(all);
        return ApiResult<IReadOnlyList<DnsZone>>.Ok(all.Data!.Select(x => new DnsZone(CloudJson.Text(x, "DomainId"), CloudJson.Text(x, "DomainName"), "Unknown",
            CloudJson.Array(CloudJson.Object(x, "DnsServers"), "DnsServer", out var servers) ? servers.EnumerateArray().Where(s => s.ValueKind == JsonValueKind.String).Select(s => s.GetString()!).ToArray() : [], RequestId(x))).ToArray());
    }
    public async Task<ApiResult<IReadOnlyList<DnsRecord>>> ListRecordsAsync(CloudAccountCredentials account, string zone, CancellationToken ct = default)
    {
        if (!CloudJson.Domain(zone)) return CloudJson.Invalid<IReadOnlyList<DnsRecord>>("DNS 区域名称无效。");
        var all = await Pages(account, "alidns", "DescribeDomainRecords", "Record", "DomainRecords", "RecordId", "PageNumber", "PageSize", new() { ["DomainName"] = zone }, ct);
        if (!all.Success) return CloudJson.Fail<IReadOnlyList<DnsRecord>, IReadOnlyList<JsonElement>>(all);
        return ApiResult<IReadOnlyList<DnsRecord>>.Ok(all.Data!.Select(x => ParseRecord(x, zone)).ToArray());
    }
    public Task<ApiResult<DnsRecord>> CreateRecordAsync(CloudAccountCredentials account, string zone, DnsRecordRequest request, CancellationToken ct = default) => WriteRecord(account, zone, "", request, ct);
    public Task<ApiResult<DnsRecord>> UpdateRecordAsync(CloudAccountCredentials account, string zone, string recordId, DnsRecordRequest request, CancellationToken ct = default)
        => CloudJson.Id(recordId) ? WriteRecord(account, zone, recordId, request, ct) : Task.FromResult(CloudJson.Invalid<DnsRecord>("DNS 记录 ID 无效。"));
    private async Task<ApiResult<DnsRecord>> WriteRecord(CloudAccountCredentials account, string zone, string id, DnsRecordRequest request, CancellationToken ct)
    {
        if (!CloudJson.RecordInput(zone, request) || (id.Length > 0 && !CloudJson.Id(id)) || (request.Type == "MX" && request.Mx is not (>= 1 and <= 50)))
            return CloudJson.Invalid<DnsRecord>("DNS 参数无效，MX 记录需要 1 至 50 的优先级。");
        var recordStatus = "Enabled";
        if (id.Length > 0) { var check = await CheckRecord(account, zone, id, ct); if (!check.Success) return check; recordStatus = check.Data!.Status; }
        var p = new Dictionary<string, string> { ["RR"] = request.Name, ["Type"] = request.Type, ["Value"] = request.Value,
            ["TTL"] = request.Ttl.ToString(CultureInfo.InvariantCulture), ["Line"] = request.Line };
        if (id.Length == 0) p["DomainName"] = zone; else p["RecordId"] = id;
        if (request.Mx.HasValue) p["Priority"] = request.Mx.Value.ToString(CultureInfo.InvariantCulture);
        var r = await Call(account, "alidns", id.Length == 0 ? "AddDomainRecord" : "UpdateDomainRecord", p, true, ct);
        if (!r.Success) return CloudJson.Fail<DnsRecord, JsonElement>(r);
        var resultId = CloudJson.Text(r.Data, "RecordId");
        if (!CloudJson.Id(resultId) || (id.Length > 0 && resultId != id)) return ApiResult<DnsRecord>.Fail("OutcomeUnknown", "DNS 写入响应记录 ID 缺失或不一致，请核对云端。");
        return ApiResult<DnsRecord>.Ok(new(resultId, zone, request.Name, request.Type, request.Value, request.Ttl, recordStatus, request.Line, RequestId(r.Data), request.Mx));
    }
    public async Task<ApiResult<CloudOperation>> SetRecordStatusAsync(CloudAccountCredentials account, string zone, string recordId, bool enabled, CancellationToken ct = default)
    {
        var check = await CheckRecord(account, zone, recordId, ct);
        if (!check.Success) return CloudJson.Fail<CloudOperation, DnsRecord>(check);
        var r = await Call(account, "alidns", "SetDomainRecordStatus", new() { ["RecordId"] = recordId, ["Status"] = enabled ? "Enable" : "Disable" }, true, ct);
        return r.Success ? ApiResult<CloudOperation>.Ok(new(RequestId(r.Data), enabled ? "Enabled" : "Disabled")) : CloudJson.Fail<CloudOperation, JsonElement>(r);
    }
    public async Task<ApiResult<CloudOperation>> DeleteRecordAsync(CloudAccountCredentials account, string zone, string recordId, CancellationToken ct = default)
    {
        var check = await CheckRecord(account, zone, recordId, ct);
        if (!check.Success) return CloudJson.Fail<CloudOperation, DnsRecord>(check);
        var r = await Call(account, "alidns", "DeleteDomainRecord", new() { ["RecordId"] = recordId }, true, ct);
        return r.Success ? ApiResult<CloudOperation>.Ok(new(RequestId(r.Data), "Deleted")) : CloudJson.Fail<CloudOperation, JsonElement>(r);
    }
    private async Task<ApiResult<DnsRecord>> CheckRecord(CloudAccountCredentials account, string zone, string id, CancellationToken ct)
    {
        if (!CloudJson.Id(id)) return CloudJson.Invalid<DnsRecord>("DNS 记录 ID 无效。");
        var all = await ListRecordsAsync(account, zone, ct);
        if (!all.Success) return CloudJson.Fail<DnsRecord, IReadOnlyList<DnsRecord>>(all);
        var item = all.Data!.FirstOrDefault(x => x.Id == id);
        return item is null ? ApiResult<DnsRecord>.Fail("DnsRecordNotFound", "指定区域中找不到该 DNS 记录。") : ApiResult<DnsRecord>.Ok(item);
    }

    private async Task<ApiResult<IReadOnlyList<JsonElement>>> Pages(CloudAccountCredentials account, string service, string action,
        string array, string? container, string idName, string pageKey, string sizeKey, Dictionary<string, string> p, CancellationToken ct)
    {
        // 云端列表可能在翻页期间发生变化。每次不完整都从第一页重新抓取，只有确认总数、记录 ID 和每页数量一致后才返回结果。
        const int maxAttempts = 3;
        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            var result = new List<JsonElement>();
            var ids = new HashSet<string>(StringComparer.Ordinal);
            int? total = null;
            var incomplete = false;
            var retryable = false;
            for (var page = 1; page <= 1000; page++)
            {
                p[pageKey] = page.ToString(CultureInfo.InvariantCulture);
                p[sizeKey] = "100";
                var r = await Call(account, service, action, p, false, ct);
                if (!r.Success) return CloudJson.Fail<IReadOnlyList<JsonElement>, JsonElement>(r);
                var count = CloudJson.Number(r.Data, "TotalCount");
                if (count is null or < 0) { incomplete = true; break; }
                if (total.HasValue && total != count) { incomplete = true; retryable = true; break; }
                total = count;
                if (!CloudJson.Array(container is null ? r.Data : CloudJson.Object(r.Data, container), array, out var rows))
                {
                    if (count == 0 && result.Count == 0) return ApiResult<IReadOnlyList<JsonElement>>.Ok([]);
                    incomplete = true;
                    break;
                }
                foreach (var row in rows.EnumerateArray())
                {
                    if (row.ValueKind != JsonValueKind.Object) { incomplete = true; break; }
                    var id = CloudJson.Text(row, idName);
                    if (id.Length == 0) { incomplete = true; break; }
                    if (!ids.Add(id)) { incomplete = true; retryable = true; break; }
                    var values = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(row.GetRawText())!;
                    values["RequestId"] = JsonSerializer.SerializeToElement(RequestId(r.Data));
                    result.Add(JsonSerializer.SerializeToElement(values));
                }
                if (incomplete) break;
                if (result.Count == total) return ApiResult<IReadOnlyList<JsonElement>>.Ok(result);
                if (rows.GetArrayLength() == 0 || result.Count > total || rows.GetArrayLength() < 100)
                { incomplete = true; retryable = true; break; }
            }
            if (!incomplete || !retryable) return CloudJson.Incomplete<IReadOnlyList<JsonElement>>();
        }
        return CloudJson.Incomplete<IReadOnlyList<JsonElement>>();
    }
    private Task<ApiResult<JsonElement>> Call(CloudAccountCredentials a, string service, string action, Dictionary<string, string> p, bool mutation, CancellationToken ct) => api.CallAsync(a, service, action, p, mutation, ct);
    private static string Key(CloudCertificateReference r) => r.ApiVersion + ":" + (r.CertificateId.Length > 0 ? "cert:" + r.CertificateId : r.OrderId.Length > 0 ? "order:" + r.OrderId : "instance:" + r.InstanceId);
    private static CloudCertificate ParseV1(JsonElement x)
    {
        var raw = CloudJson.Text(x, "Status"); var product = CloudJson.Text(x, "ProductCode");
        return new(new(CloudJson.Text(x, "CertificateId"), CloudJson.Text(x, "OrderId"), CloudJson.Text(x, "InstanceId")), CloudJson.Text(x, "Domain"),
            CloudJson.Text(x, "Name"), V1State(raw), raw, Free(product), product, CloudJson.UnixTime(CloudJson.Text(x, "CertStartTime")),
            CloudJson.UnixTime(CloudJson.Text(x, "CertEndTime")), "", RequestId(x));
    }
    private static CloudCertificate ParseV2(JsonElement x, bool instance)
    {
        var raw = CloudJson.Text(x, "CertificateStatus"); if (raw.Length == 0) raw = CloudJson.Text(x, "Status");
        var product = CloudJson.Text(x, "Spec");
        // CAS 部分接口会把主域名和默认 www 别名拼成逗号/换行字符串。免费单域名申请的本地模型只保留用户实际提交的主域名，避免列表显示两行。
        var domain = NormalizeSingleDomain(CloudJson.Text(x, "Domain"));
        var alias = FirstText(x, "CertificateName", "InstanceName", "Name");
        return new(new(CloudJson.Text(x, "CertificateId"), "", CloudJson.Text(x, "InstanceId"), "V2"), domain, alias,
            V2State(raw), raw, Free(product), product, CloudJson.UnixTime(CloudJson.Text(x, instance ? "CertificateNotBefore" : "NotBefore")),
            CloudJson.UnixTime(CloudJson.Text(x, instance ? "CertificateNotAfter" : "NotAfter")), CloudJson.Text(x, "ValidationMethod"), RequestId(x));
    }
    // V2 个人测试证书（截图中的“基础版 20 张”）返回 Spec=ss.dv.t；V1 资源包则返回 digicert-free-1-free。
    // Pro 规格和未知规格继续保持拦截，避免误提交付费或无法确认的实例。
    private static bool? Free(string product) => product.Trim().ToLowerInvariant() switch
    {
        FreeProduct or "ss.dv.t" => true,
        "symantec-free-1-free" => false,
        _ => null,
    };
    private static string V1State(string s) => s switch { "PAYED" or "payed" => "Pending", "CHECKING" or "process" => "Pending", "domain_verify" => "Validating",
        "CHECKED_FAIL" or "verify_fail" => "Failed", "ISSUED" or "certificate" => "Issued", "WILLEXPIRED" => "Expiring", "EXPIRED" => "Expired", "REVOKED" => "Revoked", "NOTACTIVATED" => "Pending", _ => "Unknown" };
    private static string V2State(string s) => s switch { "issued" or "normal" => "Issued", "revoked" => "Revoked", "willExpire" => "Expiring", "expired" => "Expired",
        "inactive" or "pending" => "Pending", "refund" => "Refunded", "closed" => "Cancelled", _ => "Unknown" };
    private static DnsRecord ParseRecord(JsonElement x, string zone) => new(CloudJson.Text(x, "RecordId"), zone, CloudJson.Text(x, "RR"), CloudJson.Text(x, "Type"),
        CloudJson.Text(x, "Value"), CloudJson.Number(x, "TTL") ?? 600, CloudJson.Text(x, "Status") switch { "Enable" => "Enabled", "Disable" => "Disabled", _ => "Unknown" },
        CloudJson.Text(x, "Line"), RequestId(x), CloudJson.Number(x, "Priority"));
    private static string RequestId(JsonElement x) => CloudJson.Token(CloudJson.Text(x, "RequestId"));
    private static string FirstText(JsonElement x, params string[] keys)
    {
        foreach (var key in keys)
        {
            var value = CloudJson.Text(x, key).Trim();
            if (value.Length > 0) return value;
        }
        return "";
    }
    private static bool IsEmptyRemoteId(string value) => string.IsNullOrWhiteSpace(value) || value == "0";
    private static string NormalizeSingleDomain(string value)
    {
        var domains = value.Split([',', ';', '\r', '\n', ' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(CloudJson.Domain).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (domains.Length == 0) return "";
        // 阿里云基础版可能回传主域名和其 www 别名，申请接口是单域名时以主域名为准。
        var primary = domains.FirstOrDefault(x => !x.StartsWith("www.", StringComparison.OrdinalIgnoreCase));
        return primary ?? domains[0];
    }
    private static string FullName(string key, string zone) => key == "@" ? zone : key.TrimEnd('.').Equals(zone, StringComparison.OrdinalIgnoreCase)
        || key.TrimEnd('.').EndsWith('.' + zone, StringComparison.OrdinalIgnoreCase) ? key.TrimEnd('.') : key.TrimEnd('.') + "." + zone;
    private static ApiResult<CloudCertificateDetail> Submitted(CloudCertificateReference reference, CloudCertificateApplyRequest request, string requestId, bool? free, string product)
        => ApiResult<CloudCertificateDetail>.Ok(new(new(reference, request.Domain, request.Alias, "Pending", "Submitted", free, product, null, null, request.ValidationMode, requestId), [], "申请已提交，验证详情等待后续同步。"));
}
