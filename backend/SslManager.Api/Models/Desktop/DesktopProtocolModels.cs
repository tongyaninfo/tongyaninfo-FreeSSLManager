namespace SslManager.Api.Models;

/// <summary>仅从 Electron 控制管道读取，启动凭证不进入命令行、配置文件或普通日志。</summary>
public sealed class DesktopInitializeRequest
{
    public string Type { get; set; } = "";
    public int Protocol { get; set; }
    public string Token { get; set; } = "";
    public string InstanceId { get; set; } = "";
    public string DataDirectory { get; set; } = "";
    public string? WebRoot { get; set; }
}

/// <summary>控制命令只通过父进程标准输入接收，不提供可被网页调用的控制 HTTP 接口。</summary>
public sealed class DesktopControlRequest
{
    public string Type { get; set; } = "";
    public string RequestId { get; set; } = "";
    public string? Destination { get; set; }
}

/// <summary>备份目录沿业务目录的相对布局保存，可在停止后端后整体恢复。</summary>
public sealed record DesktopSnapshot(string SnapshotDirectory, string DatabasePath, string KeysDirectory);

/// <summary>只标记本程序创建的桌面数据目录，不属于数据库模型或表结构。</summary>
public sealed class DesktopStorageManifest
{
    public string Application { get; set; } = "SslManager.Desktop";
    public int Protocol { get; set; } = 1;
    public string State { get; set; } = "Initializing";
}
