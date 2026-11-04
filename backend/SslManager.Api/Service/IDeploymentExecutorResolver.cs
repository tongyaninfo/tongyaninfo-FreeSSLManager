using SslManager.Api.Common;
using SslManager.Api.Models;
namespace SslManager.Api.Service;
public interface IDeploymentExecutorResolver
{
    IReadOnlyList<DeploymentExecutorDescriptor> List();
    ApiResult<IDeploymentExecutor> Resolve(string key);
}
