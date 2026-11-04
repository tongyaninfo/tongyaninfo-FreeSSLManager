using System.Diagnostics;
using System.Text;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Tests;

/// <summary>
/// 在独立本地临时目录真实执行 POSIX 协议，验证继承文件描述符锁；不连接真实设备，测试现场按用户约定保留。
/// Darwin 没有 flock 命令时使用小型原生 syscall 适配，只补命令外壳，不模拟内核锁行为。
/// </summary>
public sealed class RemoteCommandRecoveryProtocolTests
{
    private static readonly Lazy<Task<string>> LockCommandDirectory = new(CreateLockCommandAsync);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void MissingProbeResponseRemainsRetryableInsteadOfFailingThePlanAsUnsupported(bool windows)
    {
        var result = RemoteCommandRecoveryProtocol.AvailabilityResult(new(null, false), windows);
        Assert.False(result.Success);
        Assert.Equal("REMOTE_TIMEOUT", result.Code);
    }

    [Theory]
    [InlineData(false, 0, "", true)]
    [InlineData(false, 1, "", false)]
    [InlineData(true, 0, "SSLRECOVERY|Supported", true)]
    [InlineData(true, 0, "unexpected", false)]
    public void CompatibilityRequiresAnExplicitSuccessfulProbe(bool windows, int exitCode, string output, bool supported)
    {
        var result = RemoteCommandRecoveryProtocol.AvailabilityResult(new(exitCode, true, output), windows);
        Assert.Equal(supported, result.Success);
        if (!supported) Assert.Equal("COMMAND_RECOVERY_UNSUPPORTED", result.Code);
    }

    [Fact]
    public async Task GeneratedScriptsPassRealBashSyntaxValidationWithQuotedPaths()
    {
        if (OperatingSystem.IsWindows()) return;
        var directory = TempDirectory();
        var identity = Identity(Path.Combine(directory, "space and owner's directory"));
        Directory.CreateDirectory(identity.Directory);
        var execute = RemoteCommandRecoveryProtocol.Execute(identity, Shell("printf 'test output\\n'"));
        var inspect = RemoteCommandRecoveryProtocol.Inspect(identity);
        Assert.True(execute.Success, execute.Message); Assert.True(inspect.Success, inspect.Message);

        var first = await RunAsync("/bin/bash", ["-n", "-c", Unwrap(execute.Data!)]);
        var second = await RunAsync("/bin/bash", ["-n", "-c", Unwrap(inspect.Data!)]);

        Assert.Equal(0, first.ExitCode); Assert.Equal(0, second.ExitCode);
    }

    [Fact]
    public async Task CompletedAttemptIsNeverExecutedAgainAndTheOriginalExitCodeSurvives()
    {
        if (OperatingSystem.IsWindows()) return;
        var directory = TempDirectory(); var identity = Identity(directory);
        var counter = Path.Combine(directory, "counter.txt");
        var command = Shell("printf 'once\\n' >> " + Quote(counter) + "; exit 7");

        var first = await ExecuteAsync(identity, command);
        var second = await ExecuteAsync(identity, command);
        var inspected = await InspectAsync(identity);

        Assert.Equal(7, first.ExitCode); Assert.Equal(7, second.ExitCode);
        Assert.Equal(new[] { "once" }, await File.ReadAllLinesAsync(counter));
        Assert.Equal("Completed", inspected.State); Assert.Equal(7, inspected.ExitCode);
        Assert.True(File.Exists(RemoteCommandRecoveryProtocol.Paths(identity).Data.ResultPath));
    }

    [Fact]
    public async Task AnActiveAttemptHoldsTheKernelLockAcrossInspectionAndANewAttempt()
    {
        if (OperatingSystem.IsWindows()) return;
        var directory = TempDirectory(); var identity = Identity(directory);
        var ready = Path.Combine(directory, "ready"); var release = Path.Combine(directory, "release");
        var counter = Path.Combine(directory, "counter");
        var command = Shell("printf 'once\\n' >> " + Quote(counter) + "; printf ready > " + Quote(ready) +
            "; while [ ! -f " + Quote(release) + " ]; do sleep 0.02; done");
        await using var running = await StartProtocolAsync(identity, command, unwrap: false);
        await EventuallyAsync(() => File.Exists(ready));
        try
        {
            Assert.Equal("Running", (await InspectAsync(identity)).State);
            var attempted = await ExecuteAsync(identity with { Attempt = 1 }, Shell("printf 'duplicate\\n' >> " + Quote(counter)));
            Assert.Equal("SSLRECOVERY|Running", attempted.Output.Trim());
            Assert.Equal(new[] { "once" }, await File.ReadAllLinesAsync(counter));
        }
        finally { await File.WriteAllTextAsync(release, "release"); }
        var completed = await running.CompleteAsync();
        Assert.Equal(0, completed.ExitCode);
        Assert.Equal("Completed", (await InspectAsync(identity)).State);
    }

    [Fact]
    public async Task KillingOnlyTheWrapperDoesNotReleaseTheLockHeldByTheRealChild()
    {
        if (OperatingSystem.IsWindows()) return;
        var directory = TempDirectory(); var identity = Identity(directory);
        var ready = Path.Combine(directory, "ready"); var release = Path.Combine(directory, "release");
        var finished = Path.Combine(directory, "finished"); var counter = Path.Combine(directory, "counter");
        var command = Shell("printf 'once\\n' >> " + Quote(counter) + "; printf ready > " + Quote(ready) +
            "; while [ ! -f " + Quote(release) + " ]; do sleep 0.02; done; printf done > " + Quote(finished));
        // 直接运行解码后的包装脚本，Process.Id 就是要终止的包装进程，不依赖 shell 的 exec 优化。
        await using var running = await StartProtocolAsync(identity, command, unwrap: true);
        await EventuallyAsync(() => File.Exists(ready));
        running.Process.Kill(entireProcessTree: false);
        await running.Process.WaitForExitAsync();
        try
        {
            Assert.Equal("Running", (await InspectAsync(identity)).State);
            var second = await ExecuteAsync(identity with { Attempt = 1 }, Shell("printf 'duplicate\\n' >> " + Quote(counter)));
            Assert.Equal("SSLRECOVERY|Running", second.Output.Trim());
            Assert.Equal(new[] { "once" }, await File.ReadAllLinesAsync(counter));
        }
        finally { await File.WriteAllTextAsync(release, "release"); }
        await EventuallyAsync(() => File.Exists(finished));
        await EventuallyAsync(async () => (await InspectAsync(identity)).State == "StoppedUnknown");
        Assert.False(File.Exists(RemoteCommandRecoveryProtocol.Paths(identity).Data.ResultPath));
        Assert.True(File.Exists(RemoteCommandRecoveryProtocol.Paths(identity).Data.ResultPath + ".started"));
        await running.CompleteAsync();
    }

    [Fact]
    public async Task AStoppedUnknownAttemptCanBeRetriedAsANewAttemptUsingTheSameStableLock()
    {
        if (OperatingSystem.IsWindows()) return;
        var directory = TempDirectory(); var identity = Identity(directory);
        var counter = Path.Combine(directory, "counter");
        var paths = RemoteCommandRecoveryProtocol.Paths(identity).Data;
        // started 且没有完成结果模拟已结束的历史尝试；新 attempt 的授权由上层恢复策略决定。
        await File.WriteAllTextAsync(paths.ResultPath + ".started", "SSLRECOVERY|" + identity.CommandDigest + "|Started\n");
        Assert.Equal("StoppedUnknown", (await InspectAsync(identity)).State);
        var nextIdentity = identity with { Attempt = 1 };
        Assert.Equal(paths.LockPath, RemoteCommandRecoveryProtocol.Paths(nextIdentity).Data.LockPath);

        var result = await ExecuteAsync(nextIdentity, Shell("printf 'retry\\n' >> " + Quote(counter)));

        Assert.Equal(0, result.ExitCode);
        Assert.Equal(new[] { "retry" }, await File.ReadAllLinesAsync(counter));
        Assert.Equal("Completed", (await InspectAsync(nextIdentity)).State);
        Assert.Equal("StoppedUnknown", (await InspectAsync(identity)).State);
        Assert.True(File.Exists(paths.ResultPath + ".started"));
    }

    [Fact]
    public async Task MarkerFilesContainOnlyIdentityAndResultWithOwnerOnlyPermissions()
    {
        if (OperatingSystem.IsWindows()) return;
        var directory = TempDirectory(); var identity = Identity(directory);
        var result = await ExecuteAsync(identity, Shell("printf 'sensitive-output-not-a-receipt\\n'"));
        Assert.Equal(0, result.ExitCode);
        var paths = RemoteCommandRecoveryProtocol.Paths(identity).Data;
        foreach (var file in new[] { paths.LockPath, paths.ResultPath, paths.ResultPath + ".started" })
        {
            var text = await File.ReadAllTextAsync(file);
            Assert.DoesNotContain("sensitive-output-not-a-receipt", text);
            Assert.DoesNotContain("printf", text);
            Assert.Equal(UnixFileMode.None, File.GetUnixFileMode(file) &
                (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute));
        }
    }

    [Fact]
    public async Task ResultDigestMismatchIsAConflictAndDoesNotExecuteAnotherCommand()
    {
        if (OperatingSystem.IsWindows()) return;
        var directory = TempDirectory(); var identity = Identity(directory);
        Assert.Equal(0, (await ExecuteAsync(identity, Shell("true"))).ExitCode);
        var changed = identity with { CommandDigest = new string('B', 64) };

        var result = await InspectAsync(changed);

        Assert.Equal("Conflict", result.State);
    }

    private static string TempDirectory() => Directory.CreateTempSubdirectory("ssl-command-protocol-").FullName;
    private static RemoteCommandIdentity Identity(string directory) => new("task-1", "PostCommand:0", new string('A', 64), directory);
    private static string Quote(string text) => RemoteCommandHelper.PosixQuote(text);
    private static string Shell(string script) => RemoteCommandHelper.Build(new DeploymentCommand(script), "sh", false,
        new Dictionary<string, string>()).Data!;
    private static async Task<ProcessResult> ExecuteAsync(RemoteCommandIdentity identity, string command)
    {
        var generated = RemoteCommandRecoveryProtocol.Execute(identity, command);
        Assert.True(generated.Success, generated.Message);
        return await RunAsync("/bin/sh", ["-c", generated.Data!], await LockCommandDirectory.Value);
    }
    private static async Task<RemoteCommandEvidence> InspectAsync(RemoteCommandIdentity identity)
    {
        var generated = RemoteCommandRecoveryProtocol.Inspect(identity);
        Assert.True(generated.Success, generated.Message);
        var result = await RunAsync("/bin/sh", ["-c", generated.Data!], await LockCommandDirectory.Value);
        return RemoteCommandRecoveryProtocol.ReadEvidence(new(result.ExitCode, true, result.Output, result.Error));
    }
    private static async Task<RunningProcess> StartProtocolAsync(RemoteCommandIdentity identity, string command, bool unwrap)
    {
        var generated = RemoteCommandRecoveryProtocol.Execute(identity, command);
        Assert.True(generated.Success, generated.Message);
        return Start("/bin/sh", ["-c", unwrap ? Unwrap(generated.Data!) : generated.Data!], await LockCommandDirectory.Value);
    }
    private static string Unwrap(string command)
    {
        const string prefix = "sh -c ";
        Assert.StartsWith(prefix, command);
        var quoted = command[prefix.Length..];
        Assert.StartsWith("'", quoted); Assert.EndsWith("'", quoted);
        return quoted[1..^1].Replace("'\"'\"'", "'", StringComparison.Ordinal);
    }
    private static RunningProcess Start(string executable, string[] arguments, string? lockCommandDirectory = null)
    {
        var start = new ProcessStartInfo(executable) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var argument in arguments) start.ArgumentList.Add(argument);
        if (lockCommandDirectory is not null) start.Environment["PATH"] = lockCommandDirectory + Path.PathSeparator + Environment.GetEnvironmentVariable("PATH");
        var process = Process.Start(start)!;
        return new(process, process.StandardOutput.ReadToEndAsync(), process.StandardError.ReadToEndAsync());
    }
    private static async Task<ProcessResult> RunAsync(string executable, string[] arguments, string? lockCommandDirectory = null)
    {
        await using var running = Start(executable, arguments, lockCommandDirectory);
        return await running.CompleteAsync();
    }
    private static async Task EventuallyAsync(Func<bool> predicate) => await EventuallyAsync(() => Task.FromResult(predicate()));
    private static async Task EventuallyAsync(Func<Task<bool>> predicate)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (!await predicate()) await Task.Delay(20, timeout.Token);
    }
    private static async Task<string> CreateLockCommandAsync()
    {
        var directory = Directory.CreateTempSubdirectory("ssl-command-flock-syscall-").FullName;
        var source = Path.Combine(directory, "flock.c"); var binary = Path.Combine(directory, "flock");
        await File.WriteAllTextAsync(source, "#include <sys/file.h>\nint main(void) { return flock(9, LOCK_EX | LOCK_NB) == 0 ? 0 : 1; }\n", new UTF8Encoding(false));
        // 仅编译一个使用系统 flock syscall 的适配器，不安装依赖，不用假锁代替内核生命周期。
        var compiled = await RunAsync("/usr/bin/cc", [source, "-o", binary]);
        Assert.True(compiled.ExitCode == 0, compiled.Error);
        return directory;
    }
    private sealed record ProcessResult(int ExitCode, string Output, string Error);
    private sealed class RunningProcess(Process process, Task<string> output, Task<string> error) : IAsyncDisposable
    {
        public Process Process => process;
        public async Task<ProcessResult> CompleteAsync()
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await process.WaitForExitAsync(timeout.Token);
            return new(process.ExitCode, await output.WaitAsync(timeout.Token), await error.WaitAsync(timeout.Token));
        }
        public ValueTask DisposeAsync()
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
            process.Dispose(); return ValueTask.CompletedTask;
        }
    }
}
