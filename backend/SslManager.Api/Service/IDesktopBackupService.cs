using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service;

/// <summary>在线快照只写入新目录，原数据库和密钥文件始终保留。</summary>
public interface IDesktopBackupService
{
    Task<ApiResult<DesktopSnapshot>> CreateAsync(string? destination, CancellationToken ct);
}
