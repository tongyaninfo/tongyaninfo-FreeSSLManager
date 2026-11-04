using SslManager.Api.Common;
using SslManager.Api.Models;
namespace SslManager.Api.Service;
public interface IDeploymentService
{
    Task<ApiResult<DeploymentPlanView>> PlanAsync(string certificateId, DeploymentPlanRequest request, string userId, CancellationToken ct);
    /// <summary>周期任务必须与新批次同次保存关联；不支持此原子约束的实现拒绝自动部署。</summary>
    Task<ApiResult<DeploymentPlanView>> PlanForScheduleAsync(string certificateId, DeploymentPlanRequest request,
        string userId, string scheduleRunId, string leaseToken, CancellationToken ct) =>
        Task.FromResult(ApiResult<DeploymentPlanView>.Fail("SCHEDULE_DEPLOYMENT_UNSUPPORTED", "此部署服务尚未实现周期任务的原子批次关联。"));
    Task<ApiResult<DeploymentBatchView>> SubmitAsync(string batchId, DeploymentSubmitRequest request, string userId, CancellationToken ct);
    /// <summary>只恢复已关联的同轮次、同证书批次，不重新申请证书或创建替代批次。</summary>
    Task<ApiResult<DeploymentBatchView>> RecoverForScheduleAsync(string batchId, string runId, string leaseToken, CancellationToken ct) =>
        GetAsync(batchId, ct);
    Task<ApiResult<PageResult<DeploymentBatchView>>> ListAsync(int page, int pageSize, string? search, CancellationToken ct);
    Task<ApiResult<DeploymentBatchView>> GetAsync(string batchId, CancellationToken ct);
    Task<ApiResult<DeploymentTaskView>> GetTaskAsync(string taskId, CancellationToken ct);
    Task<ApiResult<DeploymentTaskView>> CancelAsync(string taskId, CancellationToken ct);
    Task<ApiResult<DeploymentInspection>> InspectAsync(string taskId, CancellationToken ct);
    Task<ApiResult<DeploymentTaskView>> ResolveAsync(string taskId, string note, string userId, string username, CancellationToken ct);
    Task<ApiResult<DeploymentPlanView>> RollbackPlanAsync(string taskId, string userId, CancellationToken ct);
    Task<bool> ProcessNextAsync(CancellationToken ct);
}
