using System.Reflection;

namespace SslManager.Api.Common;

/// <summary>统一读取当前后端编译版本，构建元数据不参与对外版本展示。</summary>
public static class ApplicationVersion
{
    public static string Current { get; } = typeof(ApplicationVersion).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? throw new InvalidOperationException("后端程序集缺少应用版本信息。");
}
