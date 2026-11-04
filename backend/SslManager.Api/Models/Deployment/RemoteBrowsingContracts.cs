using System.ComponentModel.DataAnnotations;

namespace SslManager.Api.Models;

/// <summary>仅用于当前表单的只读浏览连接，不保存凭据或目标配置。</summary>
public sealed class RemoteBrowseRequest
{
    [StringLength(80)] public string? TargetId { get; set; }
    public int? ConfigRevision { get; set; }
    [Required] public string ExecutorKey { get; set; } = "linux.files.ssh.v1";
    [Required, StringLength(2048)] public string Endpoint { get; set; } = "";
    public int Port { get; set; }
    [Required, StringLength(200)] public string Username { get; set; } = "";
    [StringLength(40)] public string AuthenticationMode { get; set; } = "Password";
    [StringLength(16384)] public string Password { get; set; } = "";
    [StringLength(65536)] public string PrivateKey { get; set; } = "";
    [StringLength(4096)] public string PrivateKeyPassphrase { get; set; } = "";
    [StringLength(256)] public string HostKeyFingerprint { get; set; } = "";
    [Required, StringLength(2048)] public string Path { get; set; } = "/";
    public int ConnectionTimeoutSeconds { get; set; } = 30;
    public int OperationTimeoutSeconds { get; set; } = 30;

    public override string ToString() => "[Remote directory browse request]";
}

/// <summary>只返回目录元数据，不包含证书或私钥正文；特殊文件和符号链接不能选择。</summary>
public sealed record RemoteDirectoryEntry(string Name, string Path, bool IsDirectory, bool IsSymbolicLink,
    bool IsRegularFile, long Size, DateTime? ModifiedAtUtc, bool CanSelect);

/// <summary>身份未信任时也可以返回观察到的指纹，必须由用户确认后重试。</summary>
public sealed record RemoteDirectoryListing(string Path, string ParentPath, IReadOnlyList<RemoteDirectoryEntry> Entries,
    bool Truncated = false, string ObservedFingerprint = "");
