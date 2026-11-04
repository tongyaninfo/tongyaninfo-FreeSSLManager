using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using SslManager.Api.Models;

namespace SslManager.Api.Common;

/// <summary>桌面进程持有独立数据目录与内存凭证，控制管道关闭即停止本地服务。</summary>
public sealed class DesktopRuntime : IDisposable
{
    public const string TokenHeader = "X-SslManager-Desktop-Token";
    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private readonly byte[] token;
    private readonly object outputLock = new();
    private FileStream? directoryLock;
    public string InstanceId { get; }
    public string DataDirectory { get; }
    public string DatabasePath => Path.Combine(DataDirectory, "data", "ssl-manager.db");
    public string KeysDirectory => Path.Combine(DataDirectory, "keys");
    public string ManifestPath => Path.Combine(DataDirectory, "desktop-storage.json");
    public string WebRootDirectory { get; }
    public string? Origin { get; private set; }

    private DesktopRuntime(DesktopInitializeRequest input)
    {
        if (input.Type != "initialize" || input.Protocol != 1 || input.Token.Length != 64 || !input.Token.All(char.IsAsciiHexDigit) ||
            input.InstanceId.Length is 0 or > 80 || input.InstanceId.Any(value => !char.IsAsciiLetterOrDigit(value) && value is not ('-' or '_')))
            throw new DesktopStartupException("DESKTOP_INITIALIZATION_INVALID", "桌面启动协议、实例身份或通信凭证无效。");
        token = Encoding.ASCII.GetBytes(input.Token);
        InstanceId = input.InstanceId;
        DataDirectory = RequireAbsoluteDirectory(input.DataDirectory);
        WebRootDirectory = RequireAbsoluteDirectory(input.WebRoot ?? Path.Combine(AppContext.BaseDirectory, "wwwroot"));
        if (!File.Exists(Path.Combine(WebRootDirectory, "index.html")))
            throw new DesktopStartupException("DESKTOP_UI_MISSING", "安装包缺少前端资源，请重新安装完整客户端。");
        Directory.CreateDirectory(DataDirectory);
        RequireOrdinaryDirectory(DataDirectory);
        try
        {
            // 文件锁跨进程保持，不按进程名称结束已有 .NET 进程。
            directoryLock = new(Path.Combine(DataDirectory, ".backend.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException)
        { throw new DesktopStartupException("DESKTOP_DATA_BUSY", "此桌面数据目录已被另一个后端进程使用。"); }
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
            Directory.CreateDirectory(KeysDirectory);
            Directory.CreateDirectory(Path.Combine(DataDirectory, "logs"));
            RequireOrdinaryDirectory(Path.GetDirectoryName(DatabasePath)!);
            RequireOrdinaryDirectory(KeysDirectory);
            if (File.Exists(DatabasePath) && (File.GetAttributes(DatabasePath) & FileAttributes.ReparsePoint) != 0)
                throw new DesktopStartupException("DESKTOP_DATA_INVALID", "桌面数据库不能是符号链接。");
            if (!OperatingSystem.IsWindows())
            {
                foreach (var directory in new[] { DataDirectory, Path.GetDirectoryName(DatabasePath)!, KeysDirectory })
                    File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            }
        }
        catch { Dispose(); throw; }
    }

    /// <summary>仅 --desktop 使用控制协议，Web 服务原启动方式保持不变。</summary>
    public static async Task<DesktopRuntime?> InitializeAsync(string[] args)
    {
        if (!args.Contains("--desktop", StringComparer.Ordinal)) return null;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        var line = await Console.In.ReadLineAsync(timeout.Token);
        if (string.IsNullOrEmpty(line) || line.Length > 16384)
            throw new DesktopStartupException("DESKTOP_INITIALIZATION_INVALID", "未收到有效的桌面初始化消息。");
        DesktopInitializeRequest input;
        try { input = JsonSerializer.Deserialize<DesktopInitializeRequest>(line, Json) ?? throw new JsonException(); }
        catch (JsonException) { throw new DesktopStartupException("DESKTOP_INITIALIZATION_INVALID", "桌面初始化消息格式不正确。"); }
        return new(input);
    }

    /// <summary>供隔离测试和集成启动验证使用，与管道初始化采用相同校验。</summary>
    public static DesktopRuntime Create(DesktopInitializeRequest input) => new(input);

    public bool MatchesToken(string? supplied)
    {
        if (supplied is null || supplied.Length != token.Length) return false;
        return CryptographicOperations.FixedTimeEquals(token, Encoding.ASCII.GetBytes(supplied));
    }

    public void AnnounceReady(IServer server)
    {
        var addresses = server.Features.Get<IServerAddressesFeature>()?.Addresses.ToArray() ?? [];
        if (addresses.Length != 1 || !Uri.TryCreate(addresses[0], UriKind.Absolute, out var uri) ||
            uri.Scheme != "http" || uri.Host != "127.0.0.1" || uri.Port <= 0)
            throw new DesktopStartupException("DESKTOP_BINDING_INVALID", "本地服务未绑定到唯一的回环地址。");
        Origin = uri.GetLeftPart(UriPartial.Authority);
        Emit(new { type = "ready", protocol = 1, instanceId = InstanceId, origin = Origin, pid = Environment.ProcessId });
    }

    /// <summary>拒绝不带父进程凭证、跨站 Origin 或错误 Host 的本地请求，防止网页访问本机 API。</summary>
    public bool Allows(HttpContext context)
    {
        if (context.Request.Scheme != "http" || context.Request.Host.Host != "127.0.0.1" ||
            context.Connection.RemoteIpAddress is not { } remote || !IPAddress.IsLoopback(remote) ||
            context.Request.Headers[TokenHeader].Count != 1 || !MatchesToken(context.Request.Headers[TokenHeader])) return false;
        var expected = Origin;
        if (expected is null) return false;
        if (context.Request.Host.Value != new Uri(expected).Authority) return false;
        if (context.Request.Headers.TryGetValue("Origin", out var origin) && (origin.Count != 1 || origin[0] != expected)) return false;
        if (context.Request.Headers.TryGetValue("Referer", out var referer) &&
            (referer.Count != 1 || !Uri.TryCreate(referer[0], UriKind.Absolute, out var source) || source.GetLeftPart(UriPartial.Authority) != expected)) return false;
        return true;
    }

    public void Emit(object message)
    {
        lock (outputLock) { Console.Out.WriteLine(JsonSerializer.Serialize(message, Json)); Console.Out.Flush(); }
    }

    public static string RequireAbsoluteDirectory(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 4096 || !Path.IsPathFullyQualified(path) || path.Any(char.IsControl))
            throw new DesktopStartupException("DESKTOP_PATH_INVALID", "桌面目录必须是有效的绝对路径。");
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
    }

    public static void RequireOrdinaryDirectory(string path)
    {
        var info = new DirectoryInfo(path);
        if (!info.Exists || info.LinkTarget is not null || (info.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new DesktopStartupException("DESKTOP_PATH_INVALID", "桌面数据目录不能是符号链接或特殊目录。");
    }

    /// <summary>比较路径时解析已有父目录链接，防止外部备份路径通过父目录链接绕回业务目录。</summary>
    public static string PhysicalPath(string path)
    {
        var full = Path.GetFullPath(path);
        for (var pass = 0; pass < 32; pass++)
        {
            var current = new DirectoryInfo(full);
            var changed = false;
            while (current is not null)
            {
                if (current.Exists && current.LinkTarget is not null)
                {
                    var target = current.ResolveLinkTarget(true) ?? throw new IOException("无法解析目录链接。");
                    var relative = Path.GetRelativePath(current.FullName, full);
                    full = Path.GetFullPath(Path.Combine(target.FullName, relative));
                    changed = true; break;
                }
                current = current.Parent;
            }
            if (!changed) return full;
        }
        throw new IOException("目录链接层级过多。");
    }

    public void Dispose()
    {
        directoryLock?.Dispose(); directoryLock = null;
        CryptographicOperations.ZeroMemory(token);
    }
}
