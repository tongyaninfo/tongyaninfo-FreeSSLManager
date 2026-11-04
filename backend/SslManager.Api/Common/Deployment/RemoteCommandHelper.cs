using System.Text;
using System.Text.RegularExpressions;
using SslManager.Api.Models;

namespace SslManager.Api.Common;

/// <summary>管理员命令在远端执行；模板变量按目标 shell 引用，绝不传给管理平台本地 shell。</summary>
public static partial class RemoteCommandHelper
{
    public static ApiResult<string> Build(DeploymentCommand command, string defaultShell, bool windows,
        IReadOnlyDictionary<string, string> variables)
    {
        if (string.IsNullOrWhiteSpace(command.Command) || command.Command.Length > 16384 || command.Command.Contains('\0'))
            return Invalid("命令为空、过长或包含 NUL 字符。");
        if (command.TimeoutSeconds is < 1 or > 3600 || command.ExecutionMode is not ("WaitForExit" or "ExpectDisconnect"))
            return Invalid("命令超时或执行模式不正确。");
        var shell = string.IsNullOrWhiteSpace(defaultShell) ? (windows ? "powershell" : "sh") : defaultShell.ToLowerInvariant();
        if (windows ? shell is not ("powershell" or "cmd") : shell is not ("sh" or "bash"))
            return Invalid("当前执行器不支持此命令 shell。");
        var unsupported = false;
        var rendered = Variable().Replace(command.Command, match =>
        {
            if (!variables.TryGetValue(match.Groups[1].Value, out var value)) { unsupported = true; return ""; }
            if (shell == "cmd" && value.Any(character => "%!^&|<>\"".Contains(character))) { unsupported = true; return ""; }
            return shell switch { "powershell" => PowerShellQuote(value), "cmd" => "\"" + value + "\"", _ => PosixQuote(value) };
        });
        if (unsupported) return Invalid("命令含不支持的模板变量，或该变量不能安全传给 cmd；可改用 PowerShell。");
        var working = RemotePathHelper.Expand(command.WorkingDirectory, variables);
        if (!working.Success) return working;
        if (!string.IsNullOrWhiteSpace(working.Data))
        {
            var directory = RemotePathHelper.ValidateAbsolute(working.Data, windows);
            if (!directory.Success) return directory;
        }
        if (!windows)
        {
            var script = "set -e\n" + (string.IsNullOrWhiteSpace(working.Data) ? "" : "cd " + PosixQuote(working.Data!) + "\n") + rendered;
            return ApiResult<string>.Ok((shell == "bash" ? "bash" : "sh") + " -c " + PosixQuote(script));
        }
        var body = shell == "cmd" ? "& $env:ComSpec /d /s /c " + PowerShellQuote(rendered) : rendered;
        var scriptWindows = "$ErrorActionPreference='Stop';$global:LASTEXITCODE=0;" +
            "$PSNativeCommandUseErrorActionPreference=$true;try{" +
            (string.IsNullOrWhiteSpace(working.Data) ? "" : "Set-Location -LiteralPath " + PowerShellQuote(working.Data!) + ";") +
            body + "\n;if($LASTEXITCODE -ne 0){exit $LASTEXITCODE};exit 0}catch{exit 1}";
        // 编码的是管理员脚本和公开路径，不包含凭据或证书私钥。
        return ApiResult<string>.Ok("powershell.exe -NoProfile -NonInteractive -EncodedCommand " +
            Convert.ToBase64String(Encoding.Unicode.GetBytes(scriptWindows)));
    }

    public static string PosixQuote(string value) => "'" + value.Replace("'", "'\"'\"'") + "'";
    public static string PowerShellQuote(string value) => "'" + value.Replace("'", "''") + "'";
    private static ApiResult<string> Invalid(string message) => ApiResult<string>.Fail("CONFIGURATION_INVALID", message);
    [GeneratedRegex(@"\{([A-Za-z][A-Za-z0-9]*)\}", RegexOptions.CultureInvariant)]
    private static partial Regex Variable();
}
