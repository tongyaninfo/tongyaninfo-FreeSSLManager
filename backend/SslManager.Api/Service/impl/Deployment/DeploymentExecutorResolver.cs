using SslManager.Api.Common;
using SslManager.Api.Models;
namespace SslManager.Api.Service.impl.Deployment;

/// <summary>通过依赖注入收集执行器，禁止注册冲突和静默降级版本。</summary>
public sealed class DeploymentExecutorResolver : IDeploymentExecutorResolver
{
    private readonly IReadOnlyDictionary<string, IDeploymentExecutor> executors;
    public DeploymentExecutorResolver(IEnumerable<IDeploymentExecutor> implementations)
    {
        executors = implementations.ToDictionary(x => x.Descriptor.Key, StringComparer.OrdinalIgnoreCase);
    }
    public IReadOnlyList<DeploymentExecutorDescriptor> List() => executors.Values.Select(x => x.Descriptor).ToArray();
    public ApiResult<IDeploymentExecutor> Resolve(string key) => executors.TryGetValue(key, out var executor)
        ? executor.Descriptor.Available ? ApiResult<IDeploymentExecutor>.Ok(executor)
            : ApiResult<IDeploymentExecutor>.Fail("EXECUTOR_UNSUPPORTED", executor.Descriptor.UnavailableReason)
        : ApiResult<IDeploymentExecutor>.Fail("EXECUTOR_UNSUPPORTED", "部署执行器未注册。");
}
