namespace SslManager.Api.Common;

/// <summary>桌面启动失败仅向父进程返回脱敏原因，不泄漏输入凭证或原始异常。</summary>
public sealed class DesktopStartupException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}
