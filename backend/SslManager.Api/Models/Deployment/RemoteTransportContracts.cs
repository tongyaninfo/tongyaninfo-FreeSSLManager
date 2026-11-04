namespace SslManager.Api.Models;

/// <summary>只包含文件状态；证书正文通过有界读取方法获取，不进入普通日志。</summary>
public sealed record RemoteFileInfo(bool Exists, bool IsDirectory = false, bool IsSymbolicLink = false,
    long Length = 0, short? Permissions = null);

/// <summary>断连、取消或超时不能被推断为成功；输出只在内存内有界保留。</summary>
public sealed record RemoteCommandResult(int? ExitCode, bool OutcomeKnown, string Output = "", string Error = "");
