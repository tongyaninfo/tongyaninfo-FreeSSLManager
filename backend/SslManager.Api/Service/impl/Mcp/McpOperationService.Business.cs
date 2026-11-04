using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Service.impl.Mcp;

public sealed partial class McpOperationService
{
    // 整块输入加密，DNS记录值及未来账号/目标凭据均不落入明文操作台账。
    private sealed record BusinessArguments(string InputDigest, string ProtectedInput, string ResourceDigest, string ResourceId,
        string SourceRecordDigest = "", string BindingDigest = "");
    private sealed record BusinessSnapshot(McpResourceScope[] Resources, string ResourceDigest, string ResourceId,
        string SummaryJson, string CertificateId = "", bool AllDomainsRequired = false, string SourceRecordDigest = "", string BindingDigest = "");
    private sealed record BusinessExecution(bool Success, string Code, string Status = "Succeeded", object? PublicResult = null);

    public async Task<ApiResult<McpOperationView>> InvokeBusinessAsync(McpCallerContext caller, string toolName, JsonElement input,
        string idempotencyKey, string? operationId, CancellationToken ct)
    {
        if (businessProtection is null) return Fail("MCP_SERVICE_UNAVAILABLE", "受控业务输入保护服务不可用。");
        var normalized = NormalizeBusinessInput(input);
        var inputDigest = Digest(normalized.GetRawText());
        var existing = string.IsNullOrEmpty(operationId)
            ? await db.McpOperations.SingleOrDefaultAsync(row => row.ClientId == caller.ClientId && row.IdempotencyKey == idempotencyKey, ct)
            : await db.McpOperations.SingleOrDefaultAsync(row => row.Id == operationId, ct);
        if (existing is not null)
        {
            BusinessArguments? envelope;
            try { envelope = JsonSerializer.Deserialize<BusinessArguments>(existing.ArgumentsJson, Json); }
            catch (JsonException) { return Fail("IDEMPOTENCY_CONFLICT", "幂等键已绑定其他业务操作。"); }
            if (!SameCaller(existing, caller) || existing.Kind != "Business" || existing.ToolName != toolName
                || envelope?.InputDigest != inputDigest || existing.IdempotencyKey != idempotencyKey)
                return Fail("IDEMPOTENCY_CONFLICT", "原操作身份、工具或业务输入不一致。");
            var valid = await ValidateConsumptionAsync(existing, caller, idempotencyKey, ct);
            if (existing.ConsumedAtUtc is not null) return valid ?? await BusinessResultAsync(existing, ct);
            if (string.IsNullOrEmpty(operationId))
            {
                var permission = await AuthorizeResourcesAsync(caller, toolName, ReadResources(existing).Resources, false, ct);
                return permission.Success ? await BusinessResultAsync(existing, ct) : Fail(permission.Code, permission.Message);
            }
            if (valid is not null) return valid;
            return await ConsumeBusinessAsync(existing, envelope, ct);
        }
        if (!string.IsNullOrEmpty(operationId)) return Fail("NOT_FOUND", "原操作不存在。");
        var snapshot = await BuildBusinessSnapshotAsync(caller, toolName, normalized, ct);
        if (!snapshot.Success || snapshot.Data is null) return Fail(snapshot.Code, snapshot.Message);
        var broad = await CheckBusinessScopeAsync(caller, toolName, snapshot.Data, false, ct);
        if (!broad.Success) return Fail(broad.Code, broad.Message);
        var protector = businessProtection.CreateProtector("SslManager.Mcp.BusinessInput.v1");
        var arguments = new BusinessArguments(inputDigest, protector.Protect(normalized.GetRawText()), snapshot.Data.ResourceDigest, snapshot.Data.ResourceId,
            snapshot.Data.SourceRecordDigest, snapshot.Data.BindingDigest);
        var prepared = await PrepareAsync(caller, "Business", toolName, arguments, snapshot.Data.Resources, snapshot.Data.SummaryJson,
            idempotencyKey, ct, allDomainsRequired: snapshot.Data.AllDomainsRequired);
        if (!prepared.Success && prepared.Code == "IDEMPOTENCY_CONFLICT")
        {
            // DataProtection每次保护的密文不同；并发相同输入仍返回原操作，不能把随机密文误判为用户改参。
            var raced = await db.McpOperations.SingleOrDefaultAsync(x => x.ClientId == caller.ClientId && x.IdempotencyKey == idempotencyKey, ct);
            if (raced is not null && SameCaller(raced, caller) && raced.Kind == "Business" && raced.ToolName == toolName)
            {
                var original = JsonSerializer.Deserialize<BusinessArguments>(raced.ArgumentsJson, Json);
                if (original?.InputDigest == inputDigest) return await BusinessResultAsync(raced, ct);
            }
        }
        if (prepared.Success && prepared.Data is not null && snapshot.Data.CertificateId.Length > 0)
        {
            var row = await db.McpOperations.SingleAsync(x => x.Id == prepared.Data.Id, ct);
            row.CertificateId = snapshot.Data.CertificateId; await db.SaveChangesAsync(ct);
            return await BusinessResultAsync(row, ct);
        }
        // 首次调用只生成可审查操作；即使规则允许预授权，也须携原 operationId 再次消费。
        return prepared;
    }

    private async Task<ApiResult<McpOperationView>> ConsumeBusinessAsync(McpOperation operation, BusinessArguments arguments, CancellationToken ct)
    {
        JsonElement input;
        try
        {
            var plaintext = businessProtection!.CreateProtector("SslManager.Mcp.BusinessInput.v1").Unprotect(arguments.ProtectedInput);
            if (Digest(plaintext) != arguments.InputDigest) return Fail("MCP_SNAPSHOT_INVALID", "原业务输入摘要不一致。");
            input = JsonSerializer.Deserialize<JsonElement>(plaintext, Json);
        }
        catch (Exception exception) when (exception is CryptographicException or JsonException)
        { return Fail("MCP_SNAPSHOT_INVALID", "原业务输入无法核对，请重新准备。"); }
        var snapshot = await BuildBusinessSnapshotAsync(Caller(operation), operation.ToolName, input, ct);
        if (!snapshot.Success || snapshot.Data is null) return Fail(snapshot.Code, snapshot.Message);
        if (snapshot.Data.ResourceDigest != arguments.ResourceDigest || snapshot.Data.ResourceId != arguments.ResourceId)
            return Fail("MCP_RESOURCE_CHANGED", "原业务资源或配置已变化，请重新准备并审批。");
        var permission = await CheckBusinessScopeAsync(Caller(operation), operation.ToolName, snapshot.Data, false, ct);
        if (!permission.Success) return Fail(permission.Code, permission.Message);
        var now = DateTime.UtcNow; var lease = ids.NewId();
        var claimed = await db.McpOperations.Where(row => row.Id == operation.Id && row.Version == operation.Version
            && row.Status == "Approved" && row.ConsumedAtUtc == null).ExecuteUpdateAsync(update => update
                .SetProperty(row => row.ConsumedAtUtc, now).SetProperty(row => row.Status, "Dispatching")
                .SetProperty(row => row.LeaseToken, lease).SetProperty(row => row.LeaseUntilUtc, now.AddMinutes(5))
                .SetProperty(row => row.UpdatedAtUtc, now).SetProperty(row => row.Version, row => row.Version + 1), ct);
        await db.Entry(operation).ReloadAsync(ct);
        if (claimed != 1) return await BusinessResultAsync(operation, ct);
        BusinessExecution result;
        try
        {
            using var remoteWrites = McpCloudMutationGuard.Enter(async token =>
            {
                var current = await RecheckBusinessAuthorizationAsync(operation, token);
                if (!current.Success) throw new McpExecutionDeniedException(current.Code, "原 MCP 授权已失效，未发送云端写入。");
            }, operation.Id);
            var gate = await RecheckBusinessAuthorizationAsync(operation, ct);
            result = !gate.Success ? new(false, gate.Code, "Blocked") : await ExecuteBusinessCoreAsync(operation, operation.ToolName, input, ct);
        }
        catch (McpExecutionDeniedException exception) { result = new(false, exception.Code, "Blocked"); }
        catch (Exception) { result = new(false, "RESULT_UNKNOWN", "Unknown"); }
        // 一旦消费，不论取消、超时或云端未知，重试只能查询原操作，绝不再次发送。
        var summary = ReadResources(operation);
        if (result.PublicResult is not null)
            summary = summary with { SummaryJson = JsonSerializer.Serialize(new { request = JsonSerializer.Deserialize<JsonElement>(summary.SummaryJson), result = result.PublicResult }, Json) };
        var resourceJson = JsonSerializer.Serialize(summary, Json);
        var state = !result.Success && result.Status == "Succeeded" ? "Failed" : result.Status; var code = result.Code;
        await db.McpOperations.Where(row => row.Id == operation.Id && row.LeaseToken == lease).ExecuteUpdateAsync(update => update
            .SetProperty(row => row.Status, state).SetProperty(row => row.Code, code)
            .SetProperty(row => row.ResourceJson, resourceJson).SetProperty(row => row.Message, "受控业务操作已更新，请按公开状态核对。")
            .SetProperty(row => row.LeaseUntilUtc, (DateTime?)null).SetProperty(row => row.UpdatedAtUtc, DateTime.UtcNow)
            .SetProperty(row => row.Version, row => row.Version + 1), CancellationToken.None);
        await db.Entry(operation).ReloadAsync(CancellationToken.None);
        return await BusinessResultAsync(operation, CancellationToken.None);
    }

    private async Task<ApiResult<bool>> CheckBusinessScopeAsync(McpCallerContext caller, string tool, BusinessSnapshot snapshot, bool worker, CancellationToken ct)
    {
        foreach (var resource in snapshot.Resources)
        {
            var allowed = await authorization.AuthorizeAsync(caller, tool, resource, worker, ct);
            if (!allowed.Success) return ApiResult<bool>.Fail(allowed.Code, allowed.Message);
            if (snapshot.AllDomainsRequired && allowed.Data?.Rules.Any(rule => rule.AllDomains) != true)
                return ApiResult<bool>.Fail("FORBIDDEN", "账号级操作必须明确授权全部域名。");
        }
        return ApiResult<bool>.Ok(true);
    }
    private async Task<ApiResult<bool>> RecheckBusinessAuthorizationAsync(McpOperation operation, CancellationToken ct)
    {
        var snapshot = ReadResources(operation);
        return await CheckBusinessScopeAsync(Caller(operation), operation.ToolName,
            new(snapshot.Resources, "", "", snapshot.SummaryJson, operation.CertificateId, snapshot.AllDomainsRequired), true, ct);
    }
    private async Task<ApiResult<McpOperationView>> BusinessResultAsync(McpOperation operation, CancellationToken ct)
    {
        var view = await ViewAsync(operation, ct);
        return view.Status is "Failed" or "Unknown" or "Blocked" or "Rejected" or "Expired"
            ? new(false, string.IsNullOrEmpty(view.Code) ? "BUSINESS_FAILED" : view.Code, view.Message, view)
            : ApiResult<McpOperationView>.Ok(view);
    }
    private static JsonElement NormalizeBusinessInput(JsonElement input)
    {
        JsonNode? Canonical(JsonElement element, bool root = false) => element.ValueKind switch
        {
            JsonValueKind.Object => new JsonObject(element.EnumerateObject().Where(x => !root || x.Name is not ("operationId" or "idempotencyKey" or "systemInstanceId"))
                .OrderBy(x => x.Name, StringComparer.Ordinal).Select(x => new KeyValuePair<string, JsonNode?>(x.Name, Canonical(x.Value)))),
            JsonValueKind.Array => new JsonArray(element.EnumerateArray().Select(x => Canonical(x)).ToArray()),
            _ => JsonNode.Parse(element.GetRawText())
        };
        return JsonSerializer.SerializeToElement(Canonical(input, true), Json);
    }
    private static string BusinessHash(object value) => Digest(JsonSerializer.Serialize(value, Json));
    private static string BusinessText(JsonElement input, string name, string fallback = "") => input.TryGetProperty(name, out var value) ? value.GetString() ?? fallback : fallback;
    private static int BusinessNumber(JsonElement input, string name, int fallback) => input.TryGetProperty(name, out var value) ? value.GetInt32() : fallback;
    private static ApiResult<BusinessSnapshot> BusinessSnapshotDenied(string code = "NOT_FOUND") => ApiResult<BusinessSnapshot>.Fail(code, "业务资源不存在、状态不支持或不在允许范围内。");
}
