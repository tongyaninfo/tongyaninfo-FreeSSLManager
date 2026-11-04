using System.IO.Compression;
using System.Text;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Tests;

/// <summary>只验证生成的 Windows SSH 协议和原生句柄约束；本机不伪造真实 Windows 进程生命周期验证。</summary>
public sealed class WindowsRemoteCommandRecoveryTests
{
    private static readonly string Digest = new('A', 64);

    [Fact]
    public void ActualChildInheritsTheExclusiveHandleAndParentWaitsBeforeCommittingTheResult()
    {
        var script = Decode(WindowsRemoteCommandRecoveryProtocol.Execute(Command("Restart-Service Example"),
            @"D:\ssl\command.lock", @"D:\ssl\command-attempt1.result", Digest));

        Assert.Contains("InheritHandle = true", script);
        Assert.Contains("CreateFileW(path, 0xC0000000, 0, ref security", script);
        Assert.Contains("CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, true", script);
        Assert.Contains("WaitForSingleObject(process.Process, 0xFFFFFFFF)", script);
        var started = script.LastIndexOf("WriteImmutable($startedPath", StringComparison.Ordinal);
        var launched = script.LastIndexOf("RunPowerShell(", StringComparison.Ordinal);
        var result = script.LastIndexOf("WriteImmutable($resultPath", StringComparison.Ordinal);
        Assert.True(started >= 0 && started < launched && launched < result);
        Assert.Contains("StdInput = nul, StdOutput = nul, StdError = nul", script);
    }

    [Fact]
    public void InspectionChecksTheLiveLockBeforeReadingAnyCompletionOrStartedMarker()
    {
        var script = Decode(WindowsRemoteCommandRecoveryProtocol.Inspect(@"D:\ssl\command.lock", @"D:\ssl\attempt.result", Digest));
        var body = script[script.LastIndexOf("try {", StringComparison.Ordinal)..];

        Assert.True(body.IndexOf("Acquire-RecoveryLock", StringComparison.Ordinal) < body.IndexOf("Read-RecoveryState", StringComparison.Ordinal));
        Assert.Contains("$reason -eq 32 -or $reason -eq 33", script);
        Assert.Contains("Write-RecoveryState 'Running'", script);
        Assert.Contains("Kind = 'StoppedUnknown'", script);
        Assert.Contains("Kind = 'NotStarted'", script);
        Assert.Contains("$parts[2] -ne $digest", script);
        Assert.Contains("[int]::TryParse($parts[3], [ref]$code)", script);
    }

    [Fact]
    public void ExistingAttemptCannotBeSentAgainAndResultPublicationNeverDeletesOrOverwritesFiles()
    {
        var script = Decode(WindowsRemoteCommandRecoveryProtocol.Execute(Command("Write-Output Done"),
            @"D:\ssl\command.lock", @"D:\ssl\attempt.result", Digest));

        Assert.Contains("if ($state.Kind -eq 'Completed')", script);
        Assert.Contains("if ($state.Kind -ne 'NotStarted')", script);
        Assert.Contains("FileMode.CreateNew", script);
        Assert.Contains("stream.Flush(true)", script);
        Assert.Contains("File.Move(staged, path)", script);
        Assert.DoesNotContain("File.Delete", script);
        Assert.DoesNotContain("Remove-Item", script);
        Assert.DoesNotContain("FileMode.Create,", script);
    }

    [Fact]
    public void PathsAreQuotedAsDataAndEncodedUserCommandIsNotReinterpretedByTheOuterShell()
    {
        const string lockPath = @"D:\ssl store\owner's-step.lock";
        const string resultPath = @"D:\ssl store\owner's-attempt.result";
        var child = Command("Write-Output 'inline-secret-value'");
        var script = Decode(WindowsRemoteCommandRecoveryProtocol.Execute(child, lockPath, resultPath, Digest));

        Assert.Contains("$lockPath = 'D:\\ssl store\\owner''s-step.lock'", script);
        Assert.Contains("$resultPath = 'D:\\ssl store\\owner''s-attempt.result'", script);
        Assert.DoesNotContain("inline-secret-value", script);
        Assert.Contains(child.Split(' ')[^1], script);
        Assert.Contains("Environment.SpecialFolder.System", script);
        Assert.Contains("WindowsPowerShell\\\\v1.0\\\\powershell.exe", script);
    }

    [Theory]
    [InlineData("relative.lock", @"D:\ssl\attempt.result")]
    [InlineData(@"D:\ssl\..\command.lock", @"D:\ssl\attempt.result")]
    [InlineData(@"D:\ssl\same", @"D:\ssl\same")]
    [InlineData(@"D:\ssl\attempt.result.started", @"D:\ssl\attempt.result")]
    public void InvalidOrCollidingMarkerPathsAreRejectedBeforeGeneratingExecutableCode(string lockPath, string resultPath) =>
        Assert.Throws<ArgumentException>(() => WindowsRemoteCommandRecoveryProtocol.Inspect(lockPath, resultPath, Digest));

    [Theory]
    [InlineData("powershell.exe -Command Write-Output unsafe")]
    [InlineData("powershell.exe -NoProfile -NonInteractive -EncodedCommand YQ== & dangerous")]
    [InlineData("powershell.exe -NoProfile -NonInteractive -EncodedCommand invalid")]
    public void OnlyTheExistingEncodedPowerShellContractCanBeWrapped(string command) =>
        Assert.Throws<ArgumentException>(() => WindowsRemoteCommandRecoveryProtocol.Execute(command, @"D:\ssl\command.lock", @"D:\ssl\attempt.result", Digest));

    [Fact]
    public void MarkerDigestMustBeACompleteSha256Value() => Assert.Throws<ArgumentException>(() =>
        WindowsRemoteCommandRecoveryProtocol.Inspect(@"D:\ssl\command.lock", @"D:\ssl\attempt.result", "invalid-digest"));

    [Fact]
    public void NativeProtocolFitsTheWindowsCommandLineLimitWithoutSavingAScriptFile()
    {
        var command = WindowsRemoteCommandRecoveryProtocol.Execute(Command("Restart-Service Example"),
            @"D:\ssl\command.lock", @"D:\ssl\attempt.result", Digest);

        Assert.InRange(command.Length, 1, 32000);
        var bootstrap = Encoding.Unicode.GetString(Convert.FromBase64String(command.Split(' ')[^1]));
        Assert.Contains("GZipStream", bootstrap);
        Assert.Contains("[ScriptBlock]::Create($scriptText)", bootstrap);
        Assert.DoesNotContain("WriteAllText", bootstrap);
        Assert.DoesNotContain(".ps1", bootstrap);
    }

    [Fact]
    public void AvailabilityCompilesTheNativeContractAndChecksExportsWithoutCreatingExecutionEvidence()
    {
        var command = WindowsRemoteCommandRecoveryProtocol.Availability();
        var script = Decode(command);

        Assert.InRange(command.Length, 1, 32000);
        Assert.Contains("$env:OS -ne 'Windows_NT'", script);
        Assert.Contains("$PSVersionTable.PSVersion.Major -lt 5", script);
        Assert.Contains("Add-Type -TypeDefinition", script);
        Assert.Contains("[IO.File]::Exists($childPowerShell)", script);
        Assert.Contains("[SslRecoveryNativeV1]::ProbeExports()", script);
        Assert.Contains("SSLRECOVERY|Supported", script);
        Assert.DoesNotContain("::OpenExclusive(", script);
        Assert.DoesNotContain("::WriteImmutable(", script);
        Assert.DoesNotContain("::RunPowerShell(", script);
    }

    private static string Command(string script) => RemoteCommandHelper.Build(new DeploymentCommand(script), "powershell", true,
        new Dictionary<string, string>()).Data!;
    private static string Decode(string command)
    {
        const string prefix = "powershell.exe -NoProfile -NonInteractive -EncodedCommand ";
        Assert.StartsWith(prefix, command);
        var bootstrap = Encoding.Unicode.GetString(Convert.FromBase64String(command[prefix.Length..]));
        const string start = "[Convert]::FromBase64String('";
        var offset = bootstrap.IndexOf(start, StringComparison.Ordinal) + start.Length;
        var end = bootstrap.IndexOf("')", offset, StringComparison.Ordinal);
        using var input = new MemoryStream(Convert.FromBase64String(bootstrap[offset..end]));
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var reader = new StreamReader(gzip, Encoding.UTF8);
        return reader.ReadToEnd();
    }
}
