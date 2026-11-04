using System.Text.Json;
using System.Text.Json.Serialization;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl.Deployment;

/// <summary>只保存平台写入意图和精确回执，不保存材料正文或平台会话。</summary>
internal sealed class PlatformDeploymentCheckpoint
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public int SchemaVersion { get; set; }
    public string SubmissionState { get; set; } = "";
    public string RemoteId { get; set; } = "";
    public string Action { get; set; } = "";
    public bool UploadStarted { get; set; }
    public bool UploadCompleted { get; set; }
    public List<string> AcknowledgedSites { get; set; } = [];
    public string PendingSiteId { get; set; } = "";
    [JsonIgnore] public bool Corrupt { get; private set; }
    [JsonIgnore] public bool CanStart => SchemaVersion == 1 && SubmissionState == "NotStarted" && !UploadStarted && !UploadCompleted;
    public string Serialize() => JsonSerializer.Serialize(this, Json);
    public static PlatformDeploymentCheckpoint Read(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind != JsonValueKind.Object ||
                document.RootElement.TryGetProperty("schemaVersion", out var version) && version.ValueKind != JsonValueKind.Number)
                return new() { Corrupt = true };
            var result = JsonSerializer.Deserialize<PlatformDeploymentCheckpoint>(json, Json) ?? new() { Corrupt = true };
            if (result.RemoteId is null || result.Action is null || result.SubmissionState is null || result.AcknowledgedSites is null || result.PendingSiteId is null ||
                result.SchemaVersion == 1 && result.SubmissionState is not ("NotStarted" or "Submitting" or "Completed") ||
                result.UploadCompleted && !result.UploadStarted)
                result.Corrupt = true;
            return result;
        }
        catch (JsonException) { return new() { Corrupt = true }; }
    }
    public static PlatformDeploymentCheckpoint Prepared(DeploymentTargetPlan plan) => new()
        { SchemaVersion = 1, SubmissionState = "NotStarted", Action = plan.Action, RemoteId = plan.RemoteResourceId };
    public Task SaveAsync(DeploymentExecutionContext context, string phase, CancellationToken ct) =>
        context.SaveCheckpointAsync?.Invoke(phase, Serialize(), ct) ?? Task.CompletedTask;
}

internal static class PlatformDeploymentRecovery
{
    public static ApiResult<DeploymentRecoveryResult> FromExecution(ApiResult<DeploymentExecutionResult> result)
    {
        if (result.Success && result.Data is not null)
            return ApiResult<DeploymentRecoveryResult>.Ok(new("Completed", result.Data.Message, result.Data));
        var blocked = result.Code is "PLAN_STALE" or "RECOVERY_CONFLICT" or "RECOVERY_EVIDENCE_MISSING" or "RECOVERY_RECEIPT_INVALID" or "RESOURCE_AMBIGUOUS" or "DOMAIN_MISMATCH" or "CONFIGURATION_INVALID"
            or "AUTH_FAILED" or "AUTHENTICATION_FAILED" or "AUTHENTICATION_UNSUPPORTED" or "PERMISSION_DENIED" or "FORBIDDEN" or "PRODUCT_VERSION_UNSUPPORTED";
        return new(false, result.Code, result.Message, new(blocked ? "Blocked" : "Retry", result.Message, result.Data));
    }
}
