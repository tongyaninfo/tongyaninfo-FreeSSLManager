using System.Security.Cryptography;
using System.Text;
using SslManager.Api.Models;

namespace SslManager.Api.Common;

/// <summary>SSH 只传输命令协议；锁和结果文件保存在远端，管理服务重启不丢失执行证据。</summary>
public static class RemoteCommandRecoveryProtocol
{
    /// <summary>探测无回执属于暂时不可达，不能误判为永久不兼容并终结原计划。</summary>
    public static ApiResult<bool> AvailabilityResult(RemoteCommandResult result, bool windows)
    {
        if (!result.OutcomeKnown)
            return ApiResult<bool>.Fail("REMOTE_TIMEOUT", "远端命令恢复能力暂时无法核对，将自动重试查询，未执行部署写入。");
        if (result.ExitCode == 0 && (!windows || result.Output.Trim() == "SSLRECOVERY|Supported")) return ApiResult<bool>.Ok(true);
        return ApiResult<bool>.Fail("COMMAND_RECOVERY_UNSUPPORTED", windows
            ? "Windows 远端缺少经核对的 PowerShell/原生执行锁能力，未写入文件或执行部署命令。"
            : "Linux 远端未检测到 flock 命令执行锁能力，未写入文件或执行部署命令；请先配置支持环境。");
    }

    public static ApiResult<string> Execute(RemoteCommandIdentity identity, string command)
    {
        var paths = Paths(identity);
        if (!paths.Success) return ApiResult<string>.Fail(paths.Code, paths.Message);
        var (lockPath, resultPath) = paths.Data;
        if (identity.Windows) return ApiResult<string>.Ok(WindowsRemoteCommandRecoveryProtocol.Execute(command, lockPath, resultPath, identity.CommandDigest));
        var script = Header(lockPath, resultPath, identity.CommandDigest) + "\n" +
            "if ! flock -n 9; then printf 'SSLRECOVERY|Running\\n'; exit 126; fi\n" +
            ReadResult("exit \"$rc\"") + "\n" +
            "if [ -e \"$started\" ]; then printf 'SSLRECOVERY|StoppedUnknown\\n'; exit 125; fi\n" +
            "( set -C; printf 'SSLRECOVERY|%s|Started\\n' \"$digest\" > \"$started\" ) || exit 124\n" +
            "(\n" + command + "\n)\nrc=$?\n" +
            "pending=\"$result.$$.pending\"\n( set -C; printf 'SSLRECOVERY|%s|Completed|%s\\n' \"$digest\" \"$rc\" > \"$pending\" ) || exit 124\n" +
            "mv -n \"$pending\" \"$result\" || exit 124\n" +
            "exit \"$rc\"";
        return ApiResult<string>.Ok("sh -c " + RemoteCommandHelper.PosixQuote(script));
    }

    public static ApiResult<string> Inspect(RemoteCommandIdentity identity)
    {
        var paths = Paths(identity);
        if (!paths.Success) return ApiResult<string>.Fail(paths.Code, paths.Message);
        var (lockPath, resultPath) = paths.Data;
        if (identity.Windows) return ApiResult<string>.Ok(WindowsRemoteCommandRecoveryProtocol.Inspect(lockPath, resultPath, identity.CommandDigest));
        var script = Header(lockPath, resultPath, identity.CommandDigest) + "\n" +
            // 子命令继承 fd9，管理进程或 SSH 父进程退出后，真实命令仍运行便继续持锁。
            "if ! flock -n 9; then printf 'SSLRECOVERY|Running\\n'; exit 0; fi\n" +
            ReadResult("printf 'SSLRECOVERY|Completed|%s\\n' \"$rc\"; exit 0") + "\n" +
            "if [ -f \"$started\" ]; then\n" +
            "  IFS= read -r previous < \"$started\" || true\n" +
            "  if [ \"$previous\" = \"SSLRECOVERY|$digest|Started\" ]; then printf 'SSLRECOVERY|StoppedUnknown\\n'; else printf 'SSLRECOVERY|Conflict\\n'; fi\n" +
            "else printf 'SSLRECOVERY|NotStarted\\n'; fi";
        return ApiResult<string>.Ok("sh -c " + RemoteCommandHelper.PosixQuote(script));
    }

    public static RemoteCommandEvidence ReadEvidence(RemoteCommandResult result)
    {
        if (!result.OutcomeKnown) return new("Unavailable");
        var line = result.Output.Trim();
        if (line is "SSLRECOVERY|Running" or "SSLRECOVERY|StoppedUnknown" or "SSLRECOVERY|NotStarted" or "SSLRECOVERY|Conflict" or "SSLRECOVERY|Unsupported")
            return new(line["SSLRECOVERY|".Length..]);
        const string completed = "SSLRECOVERY|Completed|";
        return result.ExitCode == 0 && line.StartsWith(completed, StringComparison.Ordinal) && int.TryParse(line[completed.Length..], out var code)
            ? new("Completed", code) : new("Unavailable");
    }

    /// <summary>路径只依赖原任务和步骤；尝试序号只改变结果文件，不改变互斥锁。</summary>
    public static ApiResult<(string LockPath, string ResultPath)> Paths(RemoteCommandIdentity identity)
    {
        if (identity.TaskId.Length is 0 or > 80 || identity.TaskId.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('-' or '_')) ||
            identity.StepId.Length is 0 or > 100 || identity.CommandDigest.Length != 64 || identity.CommandDigest.Any(character => !char.IsAsciiHexDigit(character)) || identity.Attempt is < 0 or > 1000)
            return ApiResult<(string, string)>.Fail("CONFIGURATION_INVALID", "远端命令恢复身份不合法。");
        var directory = RemotePathHelper.ValidateAbsolute(identity.Directory, identity.Windows);
        if (!directory.Success) return ApiResult<(string, string)>.Fail(directory.Code, directory.Message);
        var step = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity.StepId))).ToLowerInvariant()[..20];
        var separator = identity.Windows ? "\\" : "/";
        var prefix = directory.Data!.TrimEnd('/', '\\') + separator + ".ssl-command-" + identity.TaskId + "-" + step;
        return ApiResult<(string, string)>.Ok((prefix + ".lock", prefix + ".attempt-" + identity.Attempt + ".result"));
    }

    private static string Header(string lockPath, string resultPath, string digest) =>
        "umask 077\n" +
        "lock=" + RemoteCommandHelper.PosixQuote(lockPath) + "\nresult=" + RemoteCommandHelper.PosixQuote(resultPath) + "\n" +
        "started=\"$result.started\"\ndigest=" + RemoteCommandHelper.PosixQuote(digest) + "\n" +
        "command -v flock >/dev/null 2>&1 || { printf 'SSLRECOVERY|Unsupported\\n'; exit 124; }\n" +
        "for item in \"$lock\" \"$result\" \"$started\"; do\n" +
        "  if [ -L \"$item\" ] || { [ -e \"$item\" ] && [ ! -f \"$item\" ]; }; then printf 'SSLRECOVERY|Conflict\\n'; exit 124; fi\n" +
        "done\nexec 9>>\"$lock\" || exit 124";

    private static string ReadResult(string onCompleted) =>
        "if [ -f \"$result\" ]; then\n" +
        "  IFS='|' read -r tag previous state rc extra < \"$result\" || true\n" +
        "  case \"$rc\" in ''|*[!0-9]*) printf 'SSLRECOVERY|Conflict\\n'; exit 124;; esac\n" +
        "  if [ \"$tag\" != SSLRECOVERY ] || [ \"$previous\" != \"$digest\" ] || [ \"$state\" != Completed ] || [ -n \"$extra\" ] || [ \"$rc\" -gt 255 ]; then printf 'SSLRECOVERY|Conflict\\n'; exit 124; fi\n" +
        "  " + onCompleted + "\nfi";
}
