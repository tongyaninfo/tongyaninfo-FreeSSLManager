using System.IO.Compression;
using System.Text;

namespace SslManager.Api.Common;

/// <summary>
/// 为 Windows SSH 命令生成独占执行和持久回执协议。真实子命令继承锁句柄，SSH 包装进程退出也不会提前释放执行锁。
/// </summary>
public static class WindowsRemoteCommandRecoveryProtocol
{
    private const string PowerShellPrefix = "powershell.exe -NoProfile -NonInteractive -EncodedCommand ";

    /// <summary>只探测运行时和原生入口，不创建锁、回执或执行管理员脚本；部署预检在文件激活之前调用。</summary>
    public static string Availability()
    {
        var script = $$"""
            $ErrorActionPreference = 'Stop'
            try {
                if ($env:OS -ne 'Windows_NT' -or $PSVersionTable.PSVersion.Major -lt 5) {
                    [Console]::Out.WriteLine('SSLRECOVERY|Unsupported'); exit 0
                }
                Add-Type -TypeDefinition @'
            {{NativeSource}}
            '@
                $childPowerShell = [IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::System), 'WindowsPowerShell\v1.0\powershell.exe')
                if (-not [IO.File]::Exists($childPowerShell) -or -not [SslRecoveryNativeV1]::ProbeExports()) {
                    [Console]::Out.WriteLine('SSLRECOVERY|Unsupported'); exit 0
                }
                [Console]::Out.WriteLine('SSLRECOVERY|Supported')
                exit 0
            } catch {
                [Console]::Out.WriteLine('SSLRECOVERY|Unsupported')
                exit 0
            }
            """;
        return Encode(script);
    }

    /// <summary>同一 attempt 只执行一次；重试使用新的结果路径，稳定锁路径跨 attempt 复用。</summary>
    public static string Execute(string compiledCommand, string lockPath, string resultPath, string commandDigest)
    {
        Validate(lockPath, resultPath, commandDigest);
        if (!compiledCommand.StartsWith(PowerShellPrefix, StringComparison.Ordinal))
            throw new ArgumentException("Windows 跟踪命令必须使用已编码的 PowerShell 契约。", nameof(compiledCommand));
        var childPayload = compiledCommand[PowerShellPrefix.Length..];
        if (childPayload.Length is 0 or > 32000 || childPayload.Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('+' or '/' or '=')))
            throw new ArgumentException("PowerShell 编码命令格式不正确。", nameof(compiledCommand));
        try { _ = Convert.FromBase64String(childPayload); }
        catch (FormatException exception) { throw new ArgumentException("PowerShell 编码命令格式不正确。", nameof(compiledCommand), exception); }

        var script = CommonScript(lockPath, resultPath, commandDigest) + "\n" + $$"""
            try {
                if (-not (Acquire-RecoveryLock)) { exit 125 }
                $state = Read-RecoveryState
                if ($state.Kind -eq 'Completed') { Write-RecoveryState $state.Kind $state.Code; exit $state.Code }
                if ($state.Kind -ne 'NotStarted') { Write-RecoveryState $state.Kind; exit 125 }
                # started 先持久化，创建子进程前崩溃只能得到 StoppedUnknown，不能伪造未执行。
                [SslRecoveryNativeV1]::WriteImmutable($startedPath, ('SSLRECOVERY|1|' + $digest + '|Started'))
                $exitCode = [SslRecoveryNativeV1]::RunPowerShell({{RemoteCommandHelper.PowerShellQuote(childPayload)}}, $lockHandle)
                [SslRecoveryNativeV1]::WriteImmutable($resultPath, ('SSLRECOVERY|1|' + $digest + '|' + $exitCode.ToString([Globalization.CultureInfo]::InvariantCulture)))
                Write-RecoveryState 'Completed' $exitCode
                exit $exitCode
            } catch {
                # 不输出异常正文，避免用户脚本或路径内容回显；不确定时保留原始现场。
                Write-RecoveryState 'Conflict'
                exit 125
            } finally {
                if ($lockHandle -ne [IntPtr]::Zero -and $lockHandle -ne [IntPtr](-1)) { [void][SslRecoveryNativeV1]::CloseHandle($lockHandle) }
            }
            """;
        return Encode(script);
    }

    /// <summary>先检查活跃锁，再读取不可覆盖结果；锁可获取且只有 started 才表示已结束但无完成证明。</summary>
    public static string Inspect(string lockPath, string resultPath, string commandDigest)
    {
        Validate(lockPath, resultPath, commandDigest);
        var script = CommonScript(lockPath, resultPath, commandDigest) + "\n" + """
            try {
                if (-not (Acquire-RecoveryLock)) { exit 0 }
                $state = Read-RecoveryState
                Write-RecoveryState $state.Kind $state.Code
                exit 0
            } catch {
                Write-RecoveryState 'Conflict'
                exit 0
            } finally {
                if ($lockHandle -ne [IntPtr]::Zero -and $lockHandle -ne [IntPtr](-1)) { [void][SslRecoveryNativeV1]::CloseHandle($lockHandle) }
            }
            """;
        return Encode(script);
    }

    private static string CommonScript(string lockPath, string resultPath, string commandDigest) => $$"""
        $ErrorActionPreference = 'Stop'
        $lockPath = {{RemoteCommandHelper.PowerShellQuote(lockPath)}}
        $resultPath = {{RemoteCommandHelper.PowerShellQuote(resultPath)}}
        $startedPath = $resultPath + '.started'
        $digest = {{RemoteCommandHelper.PowerShellQuote(commandDigest)}}
        $lockHandle = [IntPtr]::Zero
        Add-Type -TypeDefinition @'
        {{NativeSource}}
        '@
        function Write-RecoveryState([string]$kind, [int]$code = 0) {
            if ($kind -eq 'Completed') { [Console]::Out.WriteLine('SSLRECOVERY|Completed|' + $code.ToString([Globalization.CultureInfo]::InvariantCulture)) }
            else { [Console]::Out.WriteLine('SSLRECOVERY|' + $kind) }
        }
        function Acquire-RecoveryLock {
            [SslRecoveryNativeV1]::RequireSafeFilePath($lockPath)
            [SslRecoveryNativeV1]::RequireSafeFilePath($resultPath)
            [SslRecoveryNativeV1]::RequireSafeFilePath($startedPath)
            $script:lockHandle = [SslRecoveryNativeV1]::OpenExclusive($lockPath)
            if ($script:lockHandle -eq [IntPtr](-1)) {
                $reason = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if ($reason -eq 32 -or $reason -eq 33) { Write-RecoveryState 'Running' }
                else { Write-RecoveryState 'Conflict' }
                return $false
            }
            return $true
        }
        function Read-RecoveryState {
            $result = [SslRecoveryNativeV1]::ReadMarker($resultPath)
            $started = [SslRecoveryNativeV1]::ReadMarker($startedPath)
            if ($null -ne $started -and $started -ne ('SSLRECOVERY|1|' + $digest + '|Started')) {
                return @{ Kind = 'Conflict'; Code = 0 }
            }
            if ($null -ne $result) {
                $parts = $result.Split('|')
                $code = 0
                if ($parts.Length -ne 4 -or $parts[0] -ne 'SSLRECOVERY' -or $parts[1] -ne '1' -or
                    $parts[2] -ne $digest -or -not [int]::TryParse($parts[3], [ref]$code)) {
                    return @{ Kind = 'Conflict'; Code = 0 }
                }
                return @{ Kind = 'Completed'; Code = $code }
            }
            if ($null -ne $started) { return @{ Kind = 'StoppedUnknown'; Code = 0 } }
            return @{ Kind = 'NotStarted'; Code = 0 }
        }
        """;

    // 子命令继承同一独占文件句柄。仅给包装进程加互斥锁再启动普通子进程会留下重叠执行窗口，因此不用该做法。
    private const string NativeSource = """
        using System;
        using System.ComponentModel;
        using System.IO;
        using System.Runtime.InteropServices;
        using System.Text;

        public static class SslRecoveryNativeV1
        {
            [StructLayout(LayoutKind.Sequential)]
            private struct SECURITY_ATTRIBUTES
            {
                public int Length;
                public IntPtr SecurityDescriptor;
                [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
            }
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private struct STARTUPINFO
            {
                public int Size;
                public string Reserved;
                public string Desktop;
                public string Title;
                public uint X, Y, XSize, YSize, XChars, YChars, FillAttribute, Flags;
                public ushort ShowWindow, Reserved2Length;
                public IntPtr Reserved2, StdInput, StdOutput, StdError;
            }
            [StructLayout(LayoutKind.Sequential)]
            private struct PROCESS_INFORMATION
            {
                public IntPtr Process, Thread;
                public uint ProcessId, ThreadId;
            }
            [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            private static extern IntPtr CreateFileW(string name, uint access, uint share, ref SECURITY_ATTRIBUTES security,
                uint creation, uint attributes, IntPtr template);
            [DllImport("kernel32.dll", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CreateProcessW(string application, StringBuilder commandLine, IntPtr processSecurity,
                IntPtr threadSecurity, [MarshalAs(UnmanagedType.Bool)] bool inheritHandles, uint flags,
                IntPtr environment, string directory, ref STARTUPINFO startup, out PROCESS_INFORMATION process);
            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool GetExitCodeProcess(IntPtr process, out uint code);
            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CloseHandle(IntPtr handle);
            [DllImport("kernel32.dll", EntryPoint = "GetModuleHandleW", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
            private static extern IntPtr GetModuleHandleW(string name);
            [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
            private static extern IntPtr GetProcAddress(IntPtr module, string name);

            public static bool ProbeExports()
            {
                var module = GetModuleHandleW("kernel32.dll");
                if (module == IntPtr.Zero) return false;
                foreach (var name in new[] { "CreateFileW", "CreateProcessW", "WaitForSingleObject", "GetExitCodeProcess", "CloseHandle" })
                    if (GetProcAddress(module, name) == IntPtr.Zero) return false;
                return true;
            }

            public static IntPtr OpenExclusive(string path)
            {
                var security = new SECURITY_ATTRIBUTES { Length = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), InheritHandle = true };
                // share=0 提供跨 SSH 会话互斥；InheritHandle=true 使真正的命令进程在父包装退出后继续持锁。
                return CreateFileW(path, 0xC0000000, 0, ref security, 4, 0x00200080, IntPtr.Zero);
            }

            public static int RunPowerShell(string encodedCommand, IntPtr inheritedLock)
            {
                if (inheritedLock == IntPtr.Zero || inheritedLock == new IntPtr(-1)) throw new InvalidOperationException("Missing execution lock");
                var security = new SECURITY_ATTRIBUTES { Length = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), InheritHandle = true };
                var nul = CreateFileW("NUL", 0xC0000000, 3, ref security, 3, 0x80, IntPtr.Zero);
                if (nul == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
                var startup = new STARTUPINFO { Size = Marshal.SizeOf(typeof(STARTUPINFO)), Flags = 0x100,
                    StdInput = nul, StdOutput = nul, StdError = nul };
                PROCESS_INFORMATION process = new PROCESS_INFORMATION();
                try
                {
                    var executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "WindowsPowerShell\\v1.0\\powershell.exe");
                    var commandLine = new StringBuilder("\"" + executable + "\" -NoProfile -NonInteractive -EncodedCommand " + encodedCommand);
                    // bInheritHandles=true：子命令拥有独占锁句柄，包装进程被杀不能让新执行绕过仍活跃的原命令。
                    if (!CreateProcessW(executable, commandLine, IntPtr.Zero, IntPtr.Zero, true, 0x08000000,
                        IntPtr.Zero, null, ref startup, out process)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    if (WaitForSingleObject(process.Process, 0xFFFFFFFF) != 0) throw new Win32Exception(Marshal.GetLastWin32Error());
                    uint code;
                    if (!GetExitCodeProcess(process.Process, out code)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    return unchecked((int)code);
                }
                finally
                {
                    if (process.Thread != IntPtr.Zero) CloseHandle(process.Thread);
                    if (process.Process != IntPtr.Zero) CloseHandle(process.Process);
                    CloseHandle(nul);
                }
            }

            public static void RequireSafeFilePath(string path)
            {
                var parent = Path.GetDirectoryName(path);
                if (String.IsNullOrEmpty(parent) || !Directory.Exists(parent)) throw new IOException("Missing marker directory");
                for (var directory = new DirectoryInfo(parent); directory != null; directory = directory.Parent)
                    if ((directory.Attributes & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse directory refused");
                if (Directory.Exists(path)) throw new IOException("Marker is a directory");
                if (File.Exists(path) && (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0) throw new IOException("Reparse marker refused");
            }

            public static string ReadMarker(string path)
            {
                RequireSafeFilePath(path);
                if (!File.Exists(path)) return null;
                var info = new FileInfo(path);
                if (info.Length == 0 || info.Length > 4096) throw new IOException("Invalid marker length");
                return File.ReadAllText(path, Encoding.UTF8).TrimEnd('\r', '\n');
            }

            public static void WriteImmutable(string path, string text)
            {
                RequireSafeFilePath(path);
                if (File.Exists(path))
                {
                    if (!String.Equals(ReadMarker(path), text, StringComparison.Ordinal)) throw new IOException("Marker conflict");
                    return;
                }
                // 同目录新文件先持久化再原子改名；崩溃暂存现场保留，不删除、不覆盖已有完成回执。
                var staged = path + ".pending-" + System.Diagnostics.Process.GetCurrentProcess().Id + "-" + Guid.NewGuid().ToString("N");
                var bytes = new UTF8Encoding(false).GetBytes(text + "\n");
                using (var stream = new FileStream(staged, FileMode.CreateNew, FileAccess.Write, FileShare.Read))
                {
                    stream.Write(bytes, 0, bytes.Length);
                    stream.Flush(true);
                }
                File.Move(staged, path);
            }
        }
        """;

    private static void Validate(string lockPath, string resultPath, string commandDigest)
    {
        if (!RemotePathHelper.ValidateAbsolute(lockPath, true).Success || !RemotePathHelper.ValidateAbsolute(resultPath, true).Success ||
            string.Equals(lockPath, resultPath, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(lockPath, resultPath + ".started", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("命令恢复锁与回执必须使用不同的 Windows 绝对文件路径。");
        if (commandDigest.Length != 64 || commandDigest.Any(character => !char.IsAsciiHexDigit(character)))
            throw new ArgumentException("命令恢复摘要必须是 SHA256 十六进制值。", nameof(commandDigest));
    }
    private static string Encode(string script)
    {
        // Native 契约和用户子命令双重编码会迅速超过 Windows 命令行上限；仅在内存中解压，不写脚本文件。
        using var packed = new MemoryStream();
        using (var gzip = new GZipStream(packed, CompressionLevel.Optimal, leaveOpen: true))
            gzip.Write(Encoding.UTF8.GetBytes(script));
        var compressed = Convert.ToBase64String(packed.ToArray());
        var bootstrap = "$ErrorActionPreference='Stop';$bytes=[Convert]::FromBase64String('" + compressed + "');" +
            "$memory=[IO.MemoryStream]::new($bytes,$false);$gzip=[IO.Compression.GZipStream]::new($memory,[IO.Compression.CompressionMode]::Decompress);" +
            "$reader=[IO.StreamReader]::new($gzip,[Text.Encoding]::UTF8);$scriptText=$reader.ReadToEnd();$reader.Dispose();$memory.Dispose();" +
            "& ([ScriptBlock]::Create($scriptText))";
        var command = PowerShellPrefix + Convert.ToBase64String(Encoding.Unicode.GetBytes(bootstrap));
        if (command.Length > 32000) throw new ArgumentException("Windows 恢复包装后的命令超出安全长度，请缩短管理员脚本。");
        return command;
    }
}
