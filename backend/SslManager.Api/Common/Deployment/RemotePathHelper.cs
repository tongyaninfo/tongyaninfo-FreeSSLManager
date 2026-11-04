using System.Text.RegularExpressions;

namespace SslManager.Api.Common;

/// <summary>目标路径独立于管理平台操作系统解析，防止 Windows 路径被本机 Unix Path 规则误处理。</summary>
public static partial class RemotePathHelper
{
    private static readonly HashSet<string> DeviceNames = new(StringComparer.OrdinalIgnoreCase)
    { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
      "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };

    public static ApiResult<string> Resolve(string directory, string fileName, bool windows,
        IReadOnlyDictionary<string, string> variables)
    {
        var expandedDirectory = Expand(directory, variables);
        var expandedFile = Expand(fileName, variables);
        if (!expandedDirectory.Success) return expandedDirectory;
        if (!expandedFile.Success) return expandedFile;
        var root = ValidateAbsolute(expandedDirectory.Data!, windows);
        if (!root.Success) return root;
        var relative = expandedFile.Data!.Replace('\\', '/');
        if (string.IsNullOrWhiteSpace(relative) || relative.StartsWith('/') || relative.Contains(':'))
            return Invalid("输出文件名必须是根目录下的相对文件名或子路径。");
        var segments = relative.Split('/');
        if (segments.Any(segment => !ValidSegment(segment, windows))) return Invalid("输出文件名包含不允许的路径片段。");
        var separator = windows ? "\\" : "/";
        return ApiResult<string>.Ok(root.Data!.TrimEnd('/', '\\') + separator + string.Join(separator, segments));
    }

    public static ApiResult<string> Expand(string template, IReadOnlyDictionary<string, string> variables)
    {
        if (template.Length > 2048 || template.Any(char.IsControl)) return Invalid("路径或模板过长，或包含控制字符。");
        var missing = false;
        var result = Variable().Replace(template, match =>
        {
            if (!variables.TryGetValue(match.Groups[1].Value, out var value)) { missing = true; return ""; }
            return value;
        });
        return missing || result.Contains('{') || result.Contains('}')
            ? Invalid("路径模板包含不支持的变量。")
            : ApiResult<string>.Ok(result);
    }

    public static ApiResult<string> ValidateAbsolute(string path, bool windows)
    {
        if (string.IsNullOrWhiteSpace(path) || path.Length > 2048 || path.Any(char.IsControl))
            return Invalid("请输入有效的绝对路径。");
        var normalized = path.Replace('\\', '/');
        var prefixLength = windows ? 3 : 1;
        if (windows ? !WindowsDrive().IsMatch(normalized) : !normalized.StartsWith('/'))
            return Invalid(windows ? "Windows 输出目录需要盘符绝对路径，例如 D:\\nginx\\ssl。" : "Linux 输出目录需要以 / 开始的绝对路径。");
        var rest = normalized[prefixLength..].TrimEnd('/');
        if (rest.Length > 0 && rest.Split('/').Any(segment => !ValidSegment(segment, windows)))
            return Invalid("路径中不允许出现目录穿越、保留名称或空路径片段。");
        return ApiResult<string>.Ok(windows ? normalized.Replace('/', '\\') : normalized);
    }

    public static string ToSftp(string path) => path.Replace('\\', '/');
    public static string Parent(string path)
    {
        var normalized = path.Replace('\\', '/').TrimEnd('/');
        if (normalized.Length == 2 && normalized[1] == ':') return normalized + "/";
        var index = normalized.LastIndexOf('/');
        if (index == 2 && normalized[1] == ':') return normalized[..3];
        return index <= 0 ? "/" : normalized[..index];
    }

    public static IReadOnlyDictionary<string, string> MaterialVariables(Models.CertificateMaterialMetadata material)
    {
        var domain = material.Domain.Trim().ToLowerInvariant();
        if (domain.StartsWith("*.", StringComparison.Ordinal)) domain = "_wildcard_." + domain[2..];
        if (!SafePart().IsMatch(domain)) throw new ArgumentException("证书域名不能安全用于文件名模板。");
        var fingerprint = material.Fingerprint.Replace("SHA256:", "", StringComparison.OrdinalIgnoreCase).Replace(":", "").ToLowerInvariant();
        return new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["domain"] = domain, ["certificateId"] = SafePart().IsMatch(material.CertificateId) ? material.CertificateId : "certificate",
            ["fingerprintShort"] = fingerprint[..Math.Min(16, fingerprint.Length)]
        };
    }

    private static bool ValidSegment(string value, bool windows) =>
        value.Length is > 0 and <= 255 && value is not ("." or "..") && !value.Any(char.IsControl) &&
        (!windows || (!value.Any(character => "<>:\"|?*".Contains(character)) && !value.EndsWith('.') &&
            !value.EndsWith(' ') && !DeviceNames.Contains(value.Split('.')[0])));

    private static ApiResult<string> Invalid(string message) => ApiResult<string>.Fail("CONFIGURATION_INVALID", message);
    [GeneratedRegex(@"\{([A-Za-z][A-Za-z0-9]*)\}", RegexOptions.CultureInvariant)]
    private static partial Regex Variable();
    [GeneratedRegex(@"^[A-Za-z]:/", RegexOptions.CultureInvariant)]
    private static partial Regex WindowsDrive();
    [GeneratedRegex(@"^[A-Za-z0-9_.-]{1,180}$", RegexOptions.CultureInvariant)]
    private static partial Regex SafePart();
}
