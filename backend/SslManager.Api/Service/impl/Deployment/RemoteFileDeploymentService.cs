using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SslManager.Api.Common;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl.Deployment;

/// <summary>共用文件部署编排；远程材料只经有界会话传输，原文件移动到备份而不直接删除。</summary>
public sealed class RemoteFileDeploymentService(IRemoteTransport transport)
{
    private const int FileLimit = 8 * 1024 * 1024;

    public async Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, bool windows, CancellationToken ct)
    {
        var connected = await transport.ConnectAsync(target, ct);
        if (!connected.Success || connected.Data is null) return Failure<DeploymentConnectionTest>(connected.Code, connected.Message);
        await using var session = connected.Data;
        try
        {
        var directory = target.Configuration.OutputDirectory;
        if (!directory.Contains('{') && !string.IsNullOrWhiteSpace(directory))
        {
            var check = RemotePathHelper.ValidateAbsolute(directory, windows);
            if (!check.Success) return Failure<DeploymentConnectionTest>(check.Code, check.Message);
            var info = await session.StatAsync(check.Data!, ct);
            if (info.IsSymbolicLink || (info.Exists && !info.IsDirectory))
                return ApiResult<DeploymentConnectionTest>.Fail("CONFIGURATION_INVALID", "输出目录不是允许的普通目录。");
            if (!info.Exists && !target.Configuration.CreateDirectory)
                return ApiResult<DeploymentConnectionTest>.Fail("DIRECTORY_NOT_FOUND", "输出目录不存在，且未允许创建目录。");
        }
        return ApiResult<DeploymentConnectionTest>.Ok(new(windows ? "Windows SSH" : "Linux SSH",
            "SSH 主机指纹、认证和 SFTP 连接已通过；此测试没有写文件或执行后置命令，未证明目录可写。",
            ["SftpRead", "FileDeployment", "RemoteCommands"]));
        }
        catch (Exception exception) when (exception is IOException or Renci.SshNet.Common.SshException or UnauthorizedAccessException)
        {
            return ApiResult<DeploymentConnectionTest>.Fail("REMOTE_READ_FAILED", "远端目录读取失败，请核对目录和访问权限。");
        }
    }

    public async Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target,
        CertificateMaterialMetadata metadata, bool windows, CancellationToken ct)
    {
        var paths = Paths(target, metadata, windows);
        if (!paths.Success || paths.Data is null) return Failure<DeploymentTargetPlan>(paths.Code, paths.Message);
        var connected = await transport.ConnectAsync(target, ct);
        if (!connected.Success || connected.Data is null) return Failure<DeploymentTargetPlan>(connected.Code, connected.Message);
        await using var session = connected.Data;
        try
        {
            if (target.Configuration.ValidationCommands.Count + target.Configuration.PostCommands.Count > 0 && session.SupportsCommandRecovery)
            {
                var support = await session.CheckCommandRecoverySupportAsync(windows, ct);
                if (!support.Success) return Failure<DeploymentTargetPlan>(support.Code, support.Message);
            }
            var state = await ReadStateAsync(session, target, metadata, paths.Data, windows, ct);
            var warnings = new List<string> { "固定文件逐个替换，不保证证书和私钥整体原子切换；原文件保留为本次任务备份。" };
            if (windows) warnings.Add("Windows 新文件继承目标目录 ACL，不自动复制原文件自定义 ACL；请保证目录权限适合部署账户和实际服务账户。");
            if (target.Configuration.PostCommands.Any(command => command.ExecutionMode == "ExpectDisconnect"))
                warnings.Add("预期断连命令发送后若无法取得确定回执，将进入待核对，系统不会自动重复执行命令。");
            var resourceIdentity = target.Configuration.HostKeyFingerprint.Trim();
            var key = "ssh:" + Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(resourceIdentity))).ToLowerInvariant();
            var sourceSummary = string.IsNullOrEmpty(target.Configuration.SourceFormat) ? ""
                : $"源格式 {target.Configuration.SourceFormat}：" + string.Join("；", paths.Data.Select(file => file.SourceFileName + " → " + file.Path)) + "。";
            return ApiResult<DeploymentTargetPlan>.Ok(new(key, state.Files.Any(file => file.Exists) ? "ReplaceFiles" : "CreateFiles",
                $"向 {paths.Data.Count} 个文件写入证书材料；配置验证 {target.Configuration.ValidationCommands.Count} 条，后置命令 {target.Configuration.PostCommands.Count} 条。" + sourceSummary,
                JsonSerializer.Serialize(state), FilePaths: paths.Data.Select(path => path.Path).ToArray(), Warnings: warnings.ToArray()));
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or ArgumentException or
            Renci.SshNet.Common.SshException or UnauthorizedAccessException)
        { return ApiResult<DeploymentTargetPlan>.Fail("REMOTE_READ_FAILED", "无法读取远端文件前置条件，请核对目录、权限和路径。"); }
    }

    public async Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, bool windows, CancellationToken ct)
    {
        var expected = JsonSerializer.Deserialize<FileState>(context.Plan.PreconditionsJson);
        if (expected is null) return ApiResult<DeploymentExecutionResult>.Fail("PLAN_STALE", "文件部署计划不完整，请重新生成。");
        var paths = Paths(context.Target, context.Material.Metadata, windows);
        if (!paths.Success || paths.Data is null) return Failure<DeploymentExecutionResult>(paths.Code, paths.Message);
        if (!ValidTaskId(context.TaskId)) return ApiResult<DeploymentExecutionResult>.Fail("CONFIGURATION_INVALID", "任务标识不合法。");
        var connected = await transport.ConnectAsync(context.Target, ct);
        if (!connected.Success || connected.Data is null) return Failure<DeploymentExecutionResult>(connected.Code, connected.Message);
        await using var session = connected.Data;
        if (context.Target.Configuration.ValidationCommands.Count + context.Target.Configuration.PostCommands.Count > 0 && session.SupportsCommandRecovery)
        {
            var support = await session.CheckCommandRecoverySupportAsync(windows, ct);
            if (!support.Success) return Failure<DeploymentExecutionResult>(support.Code, support.Message);
        }
        var receipts = new List<FileReceipt>();
        var journal = new RecoveryJournal(context.Material.Metadata.Fingerprint, receipts);
        var activated = false;
        try
        {
            var current = await ReadStateAsync(session, context.Target, context.Material.Metadata, paths.Data, windows, ct);
            if (!SameState(current, expected)) return ApiResult<DeploymentExecutionResult>.Fail("PLAN_STALE", "远端文件或证书材料已变化，请重新生成部署计划。");
            var payloads = new List<(ResolvedFile File, byte[] Content)>();
            foreach (var path in paths.Data)
            {
                var content = Content(context.Material, path, context.Target.Configuration.SourceFormat, context.Target.Credentials.PfxPassword);
                if (!content.Success || content.Data is null) return Failure<DeploymentExecutionResult>(content.Code, content.Message);
                payloads.Add((path, content.Data));
            }
            // 在任何远端写入之前保存完整文件意图，崩溃后仍可核对每个暂存、备份和目标文件。
            foreach (var item in payloads)
            {
                var original = expected.Files.Single(file => file.Path == item.File.Path);
                receipts.Add(new(item.File.Path, item.File.Path + ".ssl-backup-" + context.TaskId,
                    item.File.Path + ".ssl-stage-" + context.TaskId, original.Exists, original.Digest, Digest(item.Content)));
            }
            await CheckpointAsync(context, journal, "StageIntent", ct);
            await context.ReportProgressAsync("Stage", "暂存上传并校验文件哈希。", ct);
            foreach (var item in payloads)
            {
                var original = expected.Files.Single(file => file.Path == item.File.Path);
                var stage = item.File.Path + ".ssl-stage-" + context.TaskId;
                var backup = item.File.Path + ".ssl-backup-" + context.TaskId;
                if ((await session.StatAsync(stage, ct)).Exists || (await session.StatAsync(backup, ct)).Exists)
                    return ApiResult<DeploymentExecutionResult>.Fail("REMOTE_RESULT_UNKNOWN", "本次任务的暂存或备份已存在，请先核对现场，不能重复覆盖。");
                await BeforeMutationAsync(context, ct);
                await EnsureDirectoryAsync(session, RemotePathHelper.Parent(item.File.Path), windows, context.Target.Configuration.CreateDirectory, ct, context.BeforeExternalMutationAsync);
                var sourceFile = context.Material.SourcePackages.FirstOrDefault(package => package.Format == context.Target.Configuration.SourceFormat)
                    ?.Files.FirstOrDefault(file => file.Name == item.File.SourceFileName);
                var secret = sourceFile?.ContainsSecrets == true || item.File.Role is "PrivateKey" or "Pfx" or "Jks" or "Password";
                var mode = windows ? (short?)null : secret ? (short)384 : original.Permissions ?? (short)420;
                await BeforeMutationAsync(context, ct);
                await session.WriteNewAsync(stage, item.Content, mode, ct);
                var expectedDigest = Digest(item.Content);
                if (Digest(await session.ReadAsync(stage, FileLimit, ct)) != expectedDigest)
                    return ApiResult<DeploymentExecutionResult>.Fail("FILE_VERIFICATION_FAILED", "暂存文件读回校验失败，原文件尚未替换。");
                await CheckpointAsync(context, journal, "Staged", ct);
            }
            // 暂存可能耗时，在首次覆盖前再次核对，不能覆盖排队或上传期间的外部修改。
            current = await ReadStateAsync(session, context.Target, context.Material.Metadata, paths.Data, windows, ct);
            if (!SameState(current, expected)) return ApiResult<DeploymentExecutionResult>.Fail("PLAN_STALE", "上传期间远端原文件已被修改，已停止激活。");
            await context.ReportProgressAsync("Activate", "保留原文件备份并激活新文件。", ct);
            journal.ActivationStarted = true;
            await CheckpointAsync(context, journal, "ActivateIntent", ct);
            activated = true;
            foreach (var receipt in receipts)
            {
                if (receipt.Existed)
                {
                    await BeforeMutationAsync(context, ct);
                    await session.MoveAsync(receipt.Path, receipt.BackupPath, ct);
                }
                await CheckpointAsync(context, journal, "BackupConfirmed", ct);
                await BeforeMutationAsync(context, ct);
                await session.MoveAsync(receipt.StagePath, receipt.Path, ct);
                await CheckpointAsync(context, journal, "FileActivated", ct);
            }
            var variables = CommandVariables(context, paths.Data);
            var validations = await CommandsAsync(session, context, context.Target.Configuration.ValidationCommands, variables, windows, "ValidateConfiguration", journal, ct);
            if (!validations.Success)
            {
                if (validations.Code != "REMOTE_RESULT_UNKNOWN")
                {
                    var restored = await RestoreAsync(session, receipts, context.TaskId + "-validation", ct, context.BeforeExternalMutationAsync);
                    return ExecutionFailure(restored ? "COMMAND_VALIDATION_FAILED" : "REMOTE_RESULT_UNKNOWN",
                        restored ? "配置验证失败，已恢复原文件；未执行后置命令。" : "配置验证失败且文件恢复未完全确认，请核对现场。",
                        context, receipts, journal);
                }
                return ExecutionFailure(validations.Code, validations.Message, context, receipts, journal);
            }
            var commands = await CommandsAsync(session, context, context.Target.Configuration.PostCommands, variables, windows, "PostCommand", journal, ct);
            if (!commands.Success) return ExecutionFailure(commands.Code, commands.Message, context, receipts, journal);
            await context.ReportProgressAsync("Verify", "读回完整文件集合并校验内容。", ct);
            foreach (var receipt in receipts)
                if (Digest(await session.ReadAsync(receipt.Path, FileLimit, ct)) != receipt.NewDigest)
                    return ExecutionFailure("FILE_VERIFICATION_FAILED", "激活后的文件内容与本次材料不一致。", context, receipts, journal);
            var verifyTls = !string.IsNullOrWhiteSpace(context.Target.Configuration.VerificationHost);
            if (verifyTls)
            {
                var tls = await DeploymentTlsVerification.VerifyAsync(context.Target.Configuration, context.Material.Metadata, ct);
                if (!tls.Success) return ExecutionFailure(tls.Code, tls.Message, context, receipts, journal);
            }
            return ApiResult<DeploymentExecutionResult>.Ok(new(verifyTls
                    ? "文件与命令完成，严格业务 TLS 检查已确认服务使用本次证书。"
                    : "文件部署及配置的命令已完成，已核对远端文件哈希；未配置业务 TLS 生效检查。",
                Fingerprint: context.Material.Metadata.Fingerprint, VerificationLevel: verifyTls ? "TlsObserved" : "FilesChecked",
                ReceiptJson: Serialize(journal)));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return ExecutionFailure("REMOTE_RESULT_UNKNOWN", "操作被取消；远端可能已经写入或执行，请先核对结果。", context, receipts, journal);
        }
        catch (Exception exception) when (exception is IOException or Renci.SshNet.Common.SshException or
            System.Net.Sockets.SocketException or InvalidOperationException)
        {
            if (activated)
                return ExecutionFailure("REMOTE_RESULT_UNKNOWN", "远端激活或后续操作发生异常，结果待核对；系统不会自动重放。", context, receipts, journal);
            return ExecutionFailure("REMOTE_WRITE_FAILED", "暂存上传失败，未进入原文件激活阶段；请检查目录和权限。", context, receipts, journal);
        }
    }

    /// <summary>逐文件读取现场后继续原任务；仅补齐缺少的移动和命令步骤，未知脚本不会直接重放。</summary>
    public async Task<ApiResult<DeploymentRecoveryResult>> RecoverAsync(DeploymentExecutionContext context, bool windows, CancellationToken ct)
    {
        var paths = Paths(context.Target, context.Material.Metadata, windows);
        if (!paths.Success || paths.Data is null) return RecoveryFailure(paths.Code, paths.Message, null);
        if (!ValidTaskId(context.TaskId)) return RecoveryFailure("CONFIGURATION_INVALID", "任务标识不合法。", null);
        FileState? expected;
        try { expected = JsonSerializer.Deserialize<FileState>(context.Plan.PreconditionsJson); }
        catch (JsonException) { return RecoveryFailure("PLAN_STALE", "原文件前置条件无法读取。", null); }
        if (expected?.Files is null) return RecoveryFailure("PLAN_STALE", "原文件前置条件缺失。", null);
        var connected = await transport.ConnectAsync(context.Target, ct);
        if (!connected.Success || connected.Data is null) return RecoveryFailure(connected.Code, connected.Message, null, retry: true);
        await using var session = connected.Data;
        if (context.Target.Configuration.ValidationCommands.Count + context.Target.Configuration.PostCommands.Count > 0 && session.SupportsCommandRecovery)
        {
            var support = await session.CheckCommandRecoverySupportAsync(windows, ct);
            if (!support.Success) return RecoveryFailure(support.Code, support.Message, null);
        }
        RecoveryJournal? journal = null;
        try
        {
            var stored = ReadReceipt(context.ReceiptJson);
            if (stored?.Files is not { Count: > 0 })
            {
                // 原现场未变不能证明脚本从未执行；只有新任务持久化的正面哨兵允许首次执行。
                if (!ExplicitlyNotStarted(context.ReceiptJson))
                    return RecoveryFailure("RECOVERY_EVIDENCE_MISSING", "缺少原任务未执行的明确证据，仅保留只读核对，不重发文件或命令。", null);
                foreach (var file in paths.Data)
                    if ((await session.StatAsync(file.Path + ".ssl-stage-" + context.TaskId, ct)).Exists ||
                        (await session.StatAsync(file.Path + ".ssl-backup-" + context.TaskId, ct)).Exists)
                        return RecoveryFailure("RECOVERY_EVIDENCE_MISSING", "存在原任务暂存或备份，但缺少可核对的持久回执。", null);
                var current = await ReadStateAsync(session, context.Target, context.Material.Metadata, paths.Data, windows, ct);
                if (!SameState(current, expected))
                    return RecoveryFailure("RECOVERY_CONFLICT", "没有持久回执且远端现场已变化，不能猜测或重复执行。", null);
                var first = await ExecuteAsync(context, windows, ct);
                return first.Success && first.Data is not null
                    ? ApiResult<DeploymentRecoveryResult>.Ok(new("Completed", first.Message, first.Data))
                    : RecoveryFailure(first.Code, first.Message, first.Data, retry: IsRetryable(first.Code));
            }
            if (stored.SchemaVersion is < 0 or > 1 || stored.Fingerprint != context.Material.Metadata.Fingerprint ||
                stored.Files.Count != paths.Data.Count ||
                !stored.Files.Select(file => file.Path).ToHashSet(StringComparer.Ordinal).SetEquals(paths.Data.Select(file => file.Path)))
                return RecoveryFailure("RECOVERY_CONFLICT", "文件恢复回执版本、证书身份或输出路径不匹配。", null);
            journal = new(stored.Fingerprint, stored.Files.ToList()) { ActivationStarted = stored.ActivationStarted, SchemaVersion = stored.SchemaVersion };
            if (stored.Commands is not null) journal.Commands.AddRange(stored.Commands);
            if (journal.Commands.Count > 32 || journal.Commands.Select(item => item.StepId).Distinct(StringComparer.Ordinal).Count() != journal.Commands.Count ||
                journal.Commands.Any(item => item.Status is not ("Started" or "Completed" or "Failed") || item.Attempt is < 0 or > 1000 || item.TrackingVersion is < 0 or > 1))
                return RecoveryFailure("RECOVERY_CONFLICT", "命令检查点格式不完整，不能推断其执行结果。", Partial(context, journal));
            if (journal.Commands.Any(item => item.Status == "Failed"))
                return RecoveryFailure("COMMAND_FAILED", "原任务已有明确的命令失败回执，已保留现场，不自动重新激活文件。", Partial(context, journal));
            foreach (var file in journal.Files)
            {
                var original = expected.Files.SingleOrDefault(item => item.Path == file.Path);
                var stagePrefix = file.Path + ".ssl-stage-" + context.TaskId;
                if (original is null || original.Exists != file.Existed || original.Digest != file.OldDigest ||
                    file.BackupPath != file.Path + ".ssl-backup-" + context.TaskId ||
                    !file.StagePath.StartsWith(stagePrefix, StringComparison.Ordinal) ||
                    file.StagePath.AsSpan(stagePrefix.Length).ContainsAnyExcept("-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") ||
                    file.StagePath.Length > file.Path.Length + context.TaskId.Length + 80 ||
                    file.NewDigest.Length != 64 || file.NewDigest.Any(character => !char.IsAsciiHexDigit(character)))
                    return RecoveryFailure("RECOVERY_CONFLICT", "文件恢复回执与原计划不一致。", Partial(context, journal));
                var safeStage = RemotePathHelper.ValidateAbsolute(file.StagePath, windows);
                if (!safeStage.Success) return RecoveryFailure("RECOVERY_CONFLICT", "暂存路径不合法。", Partial(context, journal));
                await CheckDirectoryAsync(session, RemotePathHelper.Parent(file.Path), context.Target.Configuration.CreateDirectory, ct);
                if (!await FileCanResumeAsync(session, file, ct))
                    return RecoveryFailure("RECOVERY_CONFLICT", "远端文件或备份已被其他操作修改，已停止自动恢复。", Partial(context, journal));
            }
            // 原始文件全部通过核对后，先补齐全部暂存文件，再继续逐项激活。
            for (var index = 0; index < journal.Files.Count; index++)
            {
                var file = journal.Files[index];
                if (await FileCompletedAsync(session, file, ct)) continue;
                var staged = await SafeDigestAsync(session, file.StagePath, ct);
                if (staged == file.NewDigest) continue;
                var path = paths.Data.Single(item => item.Path == file.Path);
                var content = Content(context.Material, path, context.Target.Configuration.SourceFormat, context.Target.Credentials.PfxPassword);
                if (!content.Success || content.Data is null) return RecoveryFailure(content.Code, content.Message, Partial(context, journal));
                // 只为尚未激活的文件重建封装；已激活 PFX/JKS 始终按原哈希核对，避免随机封装改变期望。
                var newStage = staged is null ? file.StagePath : file.Path + ".ssl-stage-" + context.TaskId + "-" + Guid.NewGuid().ToString("N");
                file = file with { StagePath = newStage, NewDigest = Digest(content.Data) };
                journal.Files[index] = file;
                await CheckpointAsync(context, journal, "RecoveryStageIntent", ct);
                await EnsureDirectoryAsync(session, RemotePathHelper.Parent(file.Path), windows, context.Target.Configuration.CreateDirectory, ct, context.BeforeExternalMutationAsync);
                var original = expected.Files.Single(item => item.Path == file.Path);
                var source = context.Material.SourcePackages.FirstOrDefault(package => package.Format == context.Target.Configuration.SourceFormat)
                    ?.Files.FirstOrDefault(item => item.Name == path.SourceFileName);
                var secret = source?.ContainsSecrets == true || path.Role is "PrivateKey" or "Pfx" or "Jks" or "Password";
                var mode = windows ? (short?)null : secret ? (short)384 : original.Permissions ?? (short)420;
                await BeforeMutationAsync(context, ct);
                await session.WriteNewAsync(file.StagePath, content.Data, mode, ct);
                if (await SafeDigestAsync(session, file.StagePath, ct) != file.NewDigest)
                    return RecoveryFailure("FILE_VERIFICATION_FAILED", "恢复暂存文件读回未通过，原文件未被覆盖。", Partial(context, journal));
                await CheckpointAsync(context, journal, "RecoveryStaged", ct);
            }
            foreach (var file in journal.Files)
                if (!await FileCanResumeAsync(session, file, ct))
                    return RecoveryFailure("RECOVERY_CONFLICT", "暂存期间原文件发生变化，已阻止激活。", Partial(context, journal));
            journal.ActivationStarted = true;
            await CheckpointAsync(context, journal, "RecoveryActivateIntent", ct);
            foreach (var file in journal.Files)
            {
                if (await FileCompletedAsync(session, file, ct)) continue;
                if (!await FileCanResumeAsync(session, file, ct))
                    return RecoveryFailure("RECOVERY_CONFLICT", "激活前文件状态发生变化，已保留现场。", Partial(context, journal));
                if (file.Existed && await SafeDigestAsync(session, file.BackupPath, ct) is null)
                {
                    await BeforeMutationAsync(context, ct);
                    await session.MoveAsync(file.Path, file.BackupPath, ct);
                    await CheckpointAsync(context, journal, "RecoveryBackupConfirmed", ct);
                }
                await BeforeMutationAsync(context, ct);
                await session.MoveAsync(file.StagePath, file.Path, ct);
                await CheckpointAsync(context, journal, "RecoveryFileActivated", ct);
            }
            if (journal.SchemaVersion == 0 && context.Target.Configuration.ValidationCommands.Count + context.Target.Configuration.PostCommands.Count > 0)
                return RecoveryFailure("COMMAND_RECOVERY_UNCONFIRMED", "旧版任务缺少命令步骤回执，文件已核对，但不能猜测脚本是否执行。", Partial(context, journal));
            var variables = CommandVariables(context, paths.Data);
            var validations = await CommandsAsync(session, context, context.Target.Configuration.ValidationCommands, variables, windows, "ValidateConfiguration", journal, ct);
            if (!validations.Success) return RecoveryFailure(validations.Code, validations.Message, Partial(context, journal), IsRetryable(validations.Code));
            var commands = await CommandsAsync(session, context, context.Target.Configuration.PostCommands, variables, windows, "PostCommand", journal, ct);
            if (!commands.Success) return RecoveryFailure(commands.Code, commands.Message, Partial(context, journal), IsRetryable(commands.Code));
            foreach (var file in journal.Files)
                if (await SafeDigestAsync(session, file.Path, ct) != file.NewDigest)
                    return RecoveryFailure("RECOVERY_CONFLICT", "恢复完成检查发现文件内容已变化。", Partial(context, journal));
            var tlsConfigured = !string.IsNullOrWhiteSpace(context.Target.Configuration.VerificationHost);
            if (tlsConfigured)
            {
                var tls = await DeploymentTlsVerification.VerifyAsync(context.Target.Configuration, context.Material.Metadata, ct);
                if (!tls.Success) return RecoveryFailure(tls.Code, tls.Message, Partial(context, journal), retry: true);
            }
            await CheckpointAsync(context, journal, "RecoveryVerified", ct);
            var result = new DeploymentExecutionResult("完整文件、命令步骤和配置的生效检查已恢复完成。",
                Fingerprint: context.Material.Metadata.Fingerprint, VerificationLevel: tlsConfigured ? "TlsObserved" : "FilesChecked", ReceiptJson: Serialize(journal));
            return ApiResult<DeploymentRecoveryResult>.Ok(new("Completed", result.Message, result));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception exception) when (exception is IOException or Renci.SshNet.Common.SshException or System.Net.Sockets.SocketException or InvalidOperationException)
        {
            return RecoveryFailure("RECOVERY_RETRY", "远端现场暂时无法完整核对，稍后沿本任务继续。", journal is null ? null : Partial(context, journal), retry: true);
        }
    }

    private static DeploymentExecutionResult Partial(DeploymentExecutionContext context, RecoveryJournal journal) => new(
        "已保存文件恢复检查点。", Fingerprint: context.Material.Metadata.Fingerprint, VerificationLevel: "None", ReceiptJson: Serialize(journal));
    private static ApiResult<DeploymentRecoveryResult> RecoveryFailure(string code, string message, DeploymentExecutionResult? result, bool retry = false) =>
        new(false, code, message, new(retry ? "Retry" : "Blocked", message, result));
    private static bool IsRetryable(string code) => code is "REMOTE_RESULT_UNKNOWN" or "RECOVERY_RETRY" or "REMOTE_WRITE_FAILED" or "REMOTE_READ_FAILED" or "NETWORK_ERROR";
    private static bool ExplicitlyNotStarted(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            return root.ValueKind == JsonValueKind.Object && root.EnumerateObject().Count() == 2 &&
                root.TryGetProperty("schemaVersion", out var version) && version.ValueKind == JsonValueKind.Number && version.TryGetInt32(out var value) && value == 1 &&
                root.TryGetProperty("executionState", out var state) && state.ValueKind == JsonValueKind.String && state.GetString() == "NotStarted";
        }
        catch (JsonException) { return false; }
    }
    private static async Task<bool> FileCompletedAsync(IRemoteSession session, FileReceipt file, CancellationToken ct) =>
        await SafeDigestAsync(session, file.Path, ct) == file.NewDigest &&
        (!file.Existed || await SafeDigestAsync(session, file.BackupPath, ct) == file.OldDigest);
    private static async Task<bool> FileCanResumeAsync(IRemoteSession session, FileReceipt file, CancellationToken ct)
    {
        var current = await SafeDigestAsync(session, file.Path, ct);
        var backup = await SafeDigestAsync(session, file.BackupPath, ct);
        if (backup is not null && (!file.Existed || backup != file.OldDigest)) return false;
        if (current == file.NewDigest && (!file.Existed || backup == file.OldDigest)) return true;
        return file.Existed ? (current == file.OldDigest && backup is null || current is null && backup == file.OldDigest)
            : current is null && backup is null;
    }

    public async Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, bool windows, CancellationToken ct)
    {
        var paths = Paths(context.Target, context.Material, windows);
        if (!paths.Success || paths.Data is null) return Failure<DeploymentInspection>(paths.Code, paths.Message);
        var connected = await transport.ConnectAsync(context.Target, ct);
        if (!connected.Success || connected.Data is null) return Failure<DeploymentInspection>(connected.Code, connected.Message);
        await using var session = connected.Data;
        try
        {
            var completeReceipt = ReadReceipt(context.ReceiptJson);
            if (completeReceipt?.Files is { } allFiles && allFiles.Count == paths.Data.Count &&
                allFiles.Select(file => file.Path).ToHashSet(StringComparer.Ordinal).SetEquals(paths.Data.Select(file => file.Path)))
            {
                // 所有角色都要读回，不能仅以叶子证书相同推断私钥、证书链或密码文件已完成。
                foreach (var file in allFiles)
                    if (await SafeDigestAsync(session, file.Path, ct) != file.NewDigest)
                        return ApiResult<DeploymentInspection>.Ok(new(false, "至少一个远端文件与本次持久回执不一致。", VerificationLevel: "FileHashReadback"));
                return ApiResult<DeploymentInspection>.Ok(new(true, "完整文件集合与本次持久回执一致；命令完成情况仍由独立步骤回执证明。",
                    context.Material.Fingerprint, "FileHashReadback"));
            }
            if (!string.IsNullOrEmpty(context.Target.Configuration.SourceFormat))
            {
                // 格式包可能包含 PFX/JKS/密码文件，逐个比对本次真实上传字节的回执，不重新转换格式。
                var receipt = ReadReceipt(context.ReceiptJson);
                if (receipt?.Files is null || receipt.Files.Count != paths.Data.Count ||
                    !receipt.Files.Select(file => file.Path).ToHashSet(StringComparer.Ordinal).SetEquals(paths.Data.Select(file => file.Path)))
                    return ApiResult<DeploymentInspection>.Fail("INSPECTION_UNAVAILABLE", "缺少完整的源文件上传回执，无法核对部署文件集合。");
                foreach (var file in receipt.Files)
                    if (Digest(await session.ReadAsync(file.Path, FileLimit, ct)) != file.NewDigest)
                        return ApiResult<DeploymentInspection>.Ok(new(false, "至少一个远端文件与本次源文件字节不一致。", VerificationLevel: "FileHashReadback"));
                return ApiResult<DeploymentInspection>.Ok(new(true, "所有映射文件与本次源格式证书包一致；命令执行结果请查看任务步骤。",
                    context.Material.Fingerprint, "FileHashReadback"));
            }
            var certificatePath = paths.Data.FirstOrDefault(file => file.Role is "Leaf" or "FullChain" or "Pfx");
            if (certificatePath is null) return ApiResult<DeploymentInspection>.Fail("CONFIGURATION_INVALID", "输出至少需要包含叶子证书、完整链或 PFX。");
            var content = await session.ReadAsync(certificatePath.Path, FileLimit, ct);
            if (certificatePath.Role == "Pfx")
            {
                // PFX 的完整字节回执足够核对；不把真实私钥导入 macOS 钥匙串或其他本机密钥存储。
                var receipt = ReadReceipt(context.ReceiptJson);
                var recorded = receipt?.Files?.FirstOrDefault(file => file.Path == certificatePath.Path);
                if (recorded is null) return ApiResult<DeploymentInspection>.Fail("INSPECTION_UNAVAILABLE", "PFX 缺少本次上传的字节回执，不能确认其完整性。");
                var pfxMatches = Digest(content) == recorded.NewDigest;
                return ApiResult<DeploymentInspection>.Ok(new(pfxMatches,
                    pfxMatches ? "PFX 文件字节与本次回执一致；此检查不能证明未知后置命令完成或服务生效。" : "PFX 文件字节与本次回执不一致。",
                    pfxMatches ? context.Material.Fingerprint : "", "FileHashReadback"));
            }
            using var certificate = X509Certificate2.CreateFromPem(Encoding.UTF8.GetString(content));
            var fingerprint = Convert.ToHexString(SHA256.HashData(certificate.RawData));
            var matches = NormalizeFingerprint(fingerprint) == NormalizeFingerprint(context.Material.Fingerprint);
            return ApiResult<DeploymentInspection>.Ok(new(matches,
                matches ? "远端证书指纹一致；此核对不能证明未知后置命令已完成或服务已经生效。" : "远端证书指纹与预期不一致。",
                fingerprint, "FileCertificateReadback"));
        }
        catch (Exception exception) when (exception is IOException or CryptographicException or Renci.SshNet.Common.SshException)
        { return ApiResult<DeploymentInspection>.Fail("REMOTE_READ_FAILED", "远端证书读取或解析失败。"); }
    }

    public async Task<ApiResult<DeploymentRollbackResult>> RollbackAsync(DeploymentRollbackContext context, CancellationToken ct)
    {
        var receipt = ReadReceipt(context.ReceiptJson);
        if (receipt?.Files is not { Count: > 0 }) return ApiResult<DeploymentRollbackResult>.Fail("ROLLBACK_UNAVAILABLE", "没有可用的文件备份回执。");
        var connected = await transport.ConnectAsync(context.Target, ct);
        if (!connected.Success || connected.Data is null) return Failure<DeploymentRollbackResult>(connected.Code, connected.Message);
        await using var session = connected.Data;
        // 先核对全部当前文件，防止恢复旧任务覆盖后来部署或人工修改。
        foreach (var file in receipt.Files)
        {
            var info = await session.StatAsync(file.Path, ct);
            if (!info.Exists || info.IsDirectory || info.IsSymbolicLink || Digest(await session.ReadAsync(file.Path, FileLimit, ct)) != file.NewDigest)
                return ApiResult<DeploymentRollbackResult>.Fail("PLAN_STALE", "当前远端文件已不再是原任务产物，不能直接恢复。");
            if (file.Existed && (!(await session.StatAsync(file.BackupPath, ct)).Exists ||
                    Digest(await session.ReadAsync(file.BackupPath, FileLimit, ct)) != file.OldDigest))
                return ApiResult<DeploymentRollbackResult>.Fail("ROLLBACK_UNAVAILABLE", "原文件备份不存在或已变化，不能恢复。");
        }
        var restored = await RestoreAsync(session, receipt.Files, context.SourceTaskId + "-rollback", ct);
        return restored
            ? ApiResult<DeploymentRollbackResult>.Ok(new("原文件集合已恢复；新文件保留为恢复现场，不自动重放服务命令。"))
            : ApiResult<DeploymentRollbackResult>.Fail("REMOTE_RESULT_UNKNOWN", "恢复操作没有完全确认，请核对现场。");
    }

    private static ApiResult<List<ResolvedFile>> Paths(DeploymentTargetContext target, CertificateMaterialMetadata metadata, bool windows)
    {
        if (string.IsNullOrWhiteSpace(target.Configuration.HostKeyFingerprint))
            return ApiResult<List<ResolvedFile>>.Fail("HOST_IDENTITY_REQUIRED", "请先测试连接并通过可信渠道核对 SSH 主机指纹。");
        if (target.Configuration.Files.Count is 0 or > 16)
            return ApiResult<List<ResolvedFile>>.Fail("CONFIGURATION_INVALID", "请配置 1 至 16 个证书输出文件。");
        if (target.Configuration.ValidationCommands.Count + target.Configuration.PostCommands.Count > 32)
            return ApiResult<List<ResolvedFile>>.Fail("CONFIGURATION_INVALID", "验证和后置命令最多共 32 条。");
        var sourceFormat = target.Configuration.SourceFormat;
        var sourceMapping = !string.IsNullOrEmpty(sourceFormat);
        if (sourceMapping && (windows || sourceFormat is not ("nginx" or "apache" or "iis" or "tomcat") ||
            !DeploymentSourceBinding.Matches(target.Configuration, metadata)))
            return ApiResult<List<ResolvedFile>>.Fail("SOURCE_CERTIFICATE_MISMATCH", "请为当前 Linux 目标选择匹配的绑定域名及支持的源格式。");
        IReadOnlyDictionary<string, string> variables;
        try { variables = RemotePathHelper.MaterialVariables(metadata); }
        catch (ArgumentException) { return ApiResult<List<ResolvedFile>>.Fail("CONFIGURATION_INVALID", "证书域名不能安全用于路径模板。"); }
        var result = new List<ResolvedFile>();
        var roles = new HashSet<string>(StringComparer.Ordinal);
        var outputPaths = new HashSet<string>(windows ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var mapping in target.Configuration.Files)
        {
            var role = mapping.Role;
            var validRole = role is "Leaf" or "Chain" or "FullChain" or "PrivateKey" or "Pfx" ||
                (sourceMapping && role is "Jks" or "Password" or "Auxiliary");
            // Harbor 可同时维护代理挂载文件与 harbor.yml 的源副本；每份都进入现有备份和哈希回执。
            var allowsHarborCopy = target.ExecutorKey == "harbor.compose.ssh.v1" && role is ("FullChain" or "PrivateKey");
            if (!validRole || (!roles.Add(role) && !sourceMapping && !allowsHarborCopy))
                return ApiResult<List<ResolvedFile>>.Fail("CONFIGURATION_INVALID", "文件角色不受支持或重复。");
            if (sourceMapping ? string.IsNullOrWhiteSpace(mapping.SourceFileName) || mapping.SourceFileName.Length > 2048 || mapping.SourceFileName.Any(char.IsControl)
                : !string.IsNullOrEmpty(mapping.SourceFileName))
                return ApiResult<List<ResolvedFile>>.Fail("CONFIGURATION_INVALID", "源文件映射不完整，请重新选择源格式及文件。");
            var directory = string.IsNullOrWhiteSpace(mapping.Directory) ? target.Configuration.OutputDirectory : mapping.Directory;
            var path = RemotePathHelper.Resolve(directory, mapping.FileName, windows, variables);
            if (!path.Success) return Failure<List<ResolvedFile>>(path.Code, path.Message);
            if (!outputPaths.Add(path.Data!)) return ApiResult<List<ResolvedFile>>.Fail("CONFIGURATION_INVALID", "输出文件存在重名或路径冲突。");
            result.Add(new(role, path.Data!, mapping.SourceFileName));
        }
        if (!roles.Any(role => role is "Leaf" or "FullChain" or "Pfx" or "Jks"))
            return ApiResult<List<ResolvedFile>>.Fail("CONFIGURATION_INVALID", "输出需要包含证书、完整链或证书容器文件。");
        var outputDirectory = RemotePathHelper.Parent(result[0].Path);
        if (!string.IsNullOrWhiteSpace(target.Configuration.OutputDirectory))
        {
            var expanded = RemotePathHelper.Expand(target.Configuration.OutputDirectory, variables);
            if (!expanded.Success) return Failure<List<ResolvedFile>>(expanded.Code, expanded.Message);
            var validated = RemotePathHelper.ValidateAbsolute(expanded.Data!, windows);
            if (!validated.Success) return Failure<List<ResolvedFile>>(validated.Code, validated.Message);
            outputDirectory = validated.Data!;
        }
        var commandVariables = new Dictionary<string, string>(variables) { ["outputDirectory"] = outputDirectory, ["taskId"] = "preview" };
        AddFileVariables(commandVariables, result);
        foreach (var command in target.Configuration.ValidationCommands.Concat(target.Configuration.PostCommands))
        {
            var compiled = RemoteCommandHelper.Build(command, target.Configuration.Shell, windows, commandVariables);
            if (!compiled.Success) return Failure<List<ResolvedFile>>(compiled.Code, compiled.Message);
            if (!string.IsNullOrWhiteSpace(command.RecoveryCheckCommand))
            {
                var check = RemoteCommandHelper.Build(command with { Command = command.RecoveryCheckCommand, ExecutionMode = "WaitForExit" },
                    target.Configuration.Shell, windows, commandVariables);
                if (!check.Success) return Failure<List<ResolvedFile>>(check.Code, check.Message);
            }
        }
        return ApiResult<List<ResolvedFile>>.Ok(result);
    }

    private static async Task<FileState> ReadStateAsync(IRemoteSession session, DeploymentTargetContext target,
        CertificateMaterialMetadata metadata, List<ResolvedFile> paths, bool windows, CancellationToken ct)
    {
        var files = new List<PlannedFile>();
        foreach (var file in paths)
        {
            await CheckDirectoryAsync(session, RemotePathHelper.Parent(file.Path), target.Configuration.CreateDirectory, ct);
            var info = await session.StatAsync(file.Path, ct);
            if (info.IsDirectory || info.IsSymbolicLink || info.Length > FileLimit) throw new IOException("远端输出不是允许的普通文件。");
            files.Add(new(file.Path, info.Exists, info.Exists ? Digest(await session.ReadAsync(file.Path, FileLimit, ct)) : "", windows ? null : info.Permissions));
        }
        return new(metadata.MaterialDigest, files);
    }

    private static async Task CheckDirectoryAsync(IRemoteSession session, string path, bool allowCreate, CancellationToken ct)
    {
        var current = path;
        for (var depth = 0; depth < 64; depth++)
        {
            var info = await session.StatAsync(current, ct);
            if (info.IsSymbolicLink || (info.Exists && !info.IsDirectory)) throw new IOException("目录包含符号链接或不是普通目录。");
            if (!info.Exists && !allowCreate) throw new IOException("目录不存在。");
            var parent = RemotePathHelper.Parent(current);
            if (parent == current || current == "/" || current.Length == 3 && current[1] == ':') return;
            current = parent;
        }
        throw new IOException("目录层级过深。");
    }

    private static async Task EnsureDirectoryAsync(IRemoteSession session, string path, bool windows, bool allowCreate, CancellationToken ct,
        Func<CancellationToken, Task>? beforeMutation = null)
    {
        var info = await session.StatAsync(path, ct);
        if (info.IsSymbolicLink || (info.Exists && !info.IsDirectory)) throw new IOException("输出目录不是普通目录。");
        if (info.Exists) return;
        if (!allowCreate || path is "/" || path.Length == 3 && path[1] == ':') throw new IOException("输出目录不可创建。");
        await EnsureDirectoryAsync(session, RemotePathHelper.Parent(path), windows, allowCreate, ct, beforeMutation);
        if (beforeMutation is not null) await beforeMutation(ct);
        await session.CreateDirectoryAsync(path, windows ? null : (short)448, ct);
    }

    private static async Task<ApiResult<bool>> CommandsAsync(IRemoteSession session, DeploymentExecutionContext context,
        List<DeploymentCommand> commands, IReadOnlyDictionary<string, string> variables, bool windows, string phase,
        RecoveryJournal journal, CancellationToken ct)
    {
        for (var index = 0; index < commands.Count; index++)
        {
            var compiled = RemoteCommandHelper.Build(commands[index], context.Target.Configuration.Shell, windows, variables);
            if (!compiled.Success) return Failure<bool>(compiled.Code, compiled.Message);
            var stepId = phase + ":" + index;
            var commandDigest = Digest(Encoding.UTF8.GetBytes(compiled.Data!));
            var previous = journal.Commands.SingleOrDefault(item => item.StepId == stepId);
            if (previous is not null && previous.Digest != commandDigest)
                return ApiResult<bool>.Fail("RECOVERY_CONFLICT", "命令内容与持久化步骤不一致，已停止恢复。");
            if (previous?.Status == "Completed") continue;
            if (previous?.Status == "Failed")
                return ApiResult<bool>.Fail("COMMAND_FAILED", "此命令已有明确失败回执，需修正后重新计划。");
            var attempt = previous?.Attempt ?? 0;
            var tracked = session.SupportsCommandRecovery;
            var directory = RemotePathHelper.Parent(journal.Files[0].Path);
            RemoteCommandIdentity Identity(int number) => new(context.TaskId, stepId, commandDigest, directory, windows, number);
            if (previous?.Status == "Started")
            {
                RemoteCommandEvidence? evidence = null;
                if (previous.TrackingVersion == 1)
                {
                    if (!tracked) return ApiResult<bool>.Fail("RECOVERY_RETRY", "当前会话暂不支持原命令的远端执行证据查询。");
                    evidence = await session.InspectCommandAsync(Identity(attempt), commands[index].TimeoutSeconds, ct);
                    if (evidence.State is "Running" or "Unavailable")
                        return ApiResult<bool>.Fail("RECOVERY_RETRY", "原命令仍在远端运行或暂时无法核对，未发送第二次执行。");
                    if (evidence.State is "Conflict" or "Unsupported")
                        return ApiResult<bool>.Fail("RECOVERY_CONFLICT", "远端命令锁或结果回执无法安全核对，已保留现场。");
                    if (evidence.State == "Completed")
                    {
                        journal.Commands[journal.Commands.IndexOf(previous)] = previous with
                        { Status = evidence.ExitCode == 0 ? "Completed" : "Failed", ExitCode = evidence.ExitCode };
                        await CheckpointAsync(context, journal, phase + "RemoteConfirmed", ct);
                        if (evidence.ExitCode != 0)
                            return ApiResult<bool>.Fail("COMMAND_FAILED", "远端持久回执确认命令返回非成功退出码，后续步骤未执行。");
                        continue;
                    }
                    if (evidence.State is not ("StoppedUnknown" or "NotStarted"))
                        return ApiResult<bool>.Fail("RECOVERY_RETRY", "原命令执行证据尚不完整，继续查询。");
                }
                // 任意脚本不能凭证书指纹相同推断已执行；优先使用管理员显式配置的结果查询。
                if (!string.IsNullOrWhiteSpace(commands[index].RecoveryCheckCommand))
                {
                    var check = commands[index] with { Command = commands[index].RecoveryCheckCommand, ExecutionMode = "WaitForExit" };
                    var compiledCheck = RemoteCommandHelper.Build(check, context.Target.Configuration.Shell, windows, variables);
                    if (!compiledCheck.Success) return Failure<bool>(compiledCheck.Code, compiledCheck.Message);
                    await BeforeMutationAsync(context, ct);
                    var checkedResult = await session.ExecuteAsync(compiledCheck.Data!, check.TimeoutSeconds, ct);
                    if (!checkedResult.OutcomeKnown)
                        return ApiResult<bool>.Fail("RECOVERY_RETRY", "命令结果查询暂时未确认，稍后继续核对。");
                    if (checkedResult.ExitCode == 0)
                    {
                        journal.Commands[journal.Commands.IndexOf(previous)] = previous with { Status = "Completed", ExitCode = 0 };
                        await CheckpointAsync(context, journal, phase + "Confirmed", ct);
                        continue;
                    }
                }
                if (!commands[index].RetryOnInterruption)
                {
                    if (evidence?.State != "NotStarted")
                        return ApiResult<bool>.Fail("COMMAND_RECOVERY_UNCONFIRMED", "中断命令缺少成功证明且未声明可安全重试，已保留现场；不会重复执行。");
                }
                // 远端锁可用且本尝试已有开始标记、没有完整结果，才证明旧执行已结束但结果未知。
                // 显式幂等重试使用新尝试结果文件，始终共用原步骤的远端互斥锁。
                if (evidence?.State == "StoppedUnknown") attempt++;
                else if (evidence?.State != "NotStarted")
                    return ApiResult<bool>.Fail("RECOVERY_RETRY", "缺少原远端执行已经结束的证明，继续核对，不并发重发命令。");
            }
            if (attempt > 1000) return ApiResult<bool>.Fail("COMMAND_RECOVERY_UNCONFIRMED", "命令自动恢复尝试次数超过限制，请核对现场。");
            var started = new FileCommandReceipt(stepId, commandDigest, "Started", Attempt: attempt, TrackingVersion: tracked ? 1 : 0);
            if (previous is null) journal.Commands.Add(started);
            else journal.Commands[journal.Commands.IndexOf(previous)] = started;
            await CheckpointAsync(context, journal, phase + "Intent", ct);
            // 不保存命令输出，避免管理员脚本输出证书正文或其他秘密进入日志。
            await context.ReportProgressAsync(phase, $"开始执行第 {index + 1} 条命令。", ct);
            await BeforeMutationAsync(context, ct);
            var response = tracked
                ? await session.ExecuteTrackedAsync(Identity(attempt), compiled.Data!, commands[index].TimeoutSeconds, ct)
                : await session.ExecuteAsync(compiled.Data!, commands[index].TimeoutSeconds, ct);
            if (tracked)
            {
                var proof = await session.InspectCommandAsync(Identity(attempt), commands[index].TimeoutSeconds, ct);
                if (proof.State is "Conflict" or "Unsupported")
                    return ApiResult<bool>.Fail("RECOVERY_CONFLICT", "命令远端执行协议不可用或持久回执冲突，未推断命令完成。");
                if (proof.State != "Completed")
                    return ApiResult<bool>.Fail("RECOVERY_RETRY", "命令执行后的远端锁和完成回执尚未确认，后续只查询，不重复发送。");
                response = new(proof.ExitCode, true);
            }
            if (!response.OutcomeKnown || !tracked && commands[index].ExecutionMode == "ExpectDisconnect")
                return ApiResult<bool>.Fail("REMOTE_RESULT_UNKNOWN", "命令已发送，但断连、超时或预期重启导致最终结果需核对；不会自动再次执行。");
            if (response.ExitCode != 0)
            {
                journal.Commands[journal.Commands.FindIndex(item => item.StepId == stepId)] = started with { Status = "Failed", ExitCode = response.ExitCode };
                await CheckpointAsync(context, journal, phase + "Failed", ct);
                return ApiResult<bool>.Fail("COMMAND_FAILED", $"第 {index + 1} 条命令返回非成功退出码 {response.ExitCode}；后续命令已停止。");
            }
            journal.Commands[journal.Commands.FindIndex(item => item.StepId == stepId)] = started with { Status = "Completed", ExitCode = 0 };
            await CheckpointAsync(context, journal, phase + "Completed", ct);
            await context.ReportProgressAsync(phase, $"第 {index + 1} 条命令完成，退出码 0。", ct);
        }
        return ApiResult<bool>.Ok(true);
    }

    private static IReadOnlyDictionary<string, string> CommandVariables(DeploymentExecutionContext context, List<ResolvedFile> paths)
    {
        var materialVariables = RemotePathHelper.MaterialVariables(context.Material.Metadata);
        var result = new Dictionary<string, string>(materialVariables)
        { ["outputDirectory"] = string.IsNullOrWhiteSpace(context.Target.Configuration.OutputDirectory) ? RemotePathHelper.Parent(paths[0].Path)
                : RemotePathHelper.Expand(context.Target.Configuration.OutputDirectory, materialVariables).Data!,
          ["taskId"] = context.TaskId };
        AddFileVariables(result, paths);
        return result;
    }
    private static void AddFileVariables(Dictionary<string, string> variables, List<ResolvedFile> files)
    {
        for (var index = 0; index < files.Count; index++)
        {
            variables[$"file{index + 1}Path"] = files[index].Path;
            // 同类源文件可映射到多个目录；旧角色变量固定指向第一项，其余可用 fileNPath。
            variables.TryAdd(VariableName(files[index].Role), files[index].Path);
        }
    }
    private static string VariableName(string role) => role switch
    { "Leaf" => "certPath", "PrivateKey" => "keyPath", "FullChain" => "fullchainPath", "Chain" => "chainPath",
        "Jks" => "jksPath", "Password" => "passwordFilePath", "Auxiliary" => "auxiliaryPath", _ => "pfxPath" };

    private static ApiResult<byte[]> Content(CertificateMaterial material, ResolvedFile file, string sourceFormat, string pfxPassword)
    {
        if (!string.IsNullOrEmpty(sourceFormat))
        {
            var source = material.SourcePackages.SingleOrDefault(package => package.Format == sourceFormat)
                ?.Files.SingleOrDefault(item => item.Name == file.SourceFileName);
            return source is not null && source.Role == file.Role && Digest(source.Content) == source.Sha256
                ? ApiResult<byte[]>.Ok(source.Content)
                : ApiResult<byte[]>.Fail("SOURCE_FILE_UNAVAILABLE", "固定的源格式文件已缺失或不一致，请重新生成部署计划。");
        }
        var role = file.Role;
        try
        {
            if (role == "Pfx")
            {
                using var leaf = X509Certificate2.CreateFromPem(material.CertificatePem, material.PrivateKeyPem);
                var certificates = new X509Certificate2Collection(leaf);
                var chain = new X509Certificate2Collection();
                chain.ImportFromPem(material.ChainPem);
                foreach (var item in chain) if (item.Thumbprint != leaf.Thumbprint) certificates.Add(item);
                var bytes = certificates.Export(X509ContentType.Pkcs12, pfxPassword);
                foreach (var item in chain) item.Dispose();
                return bytes is not null ? ApiResult<byte[]>.Ok(bytes) : ApiResult<byte[]>.Fail("CERTIFICATE_MATERIAL_INVALID", "PFX 转换失败。");
            }
            var pem = role switch
            { "Leaf" => material.CertificatePem, "Chain" => material.ChainPem, "PrivateKey" => material.PrivateKeyPem, _ => material.FullChainPem };
            return string.IsNullOrWhiteSpace(pem)
                ? ApiResult<byte[]>.Fail("CERTIFICATE_MATERIAL_MISSING", "配置的输出角色没有对应材料。")
                : ApiResult<byte[]>.Ok(Encoding.UTF8.GetBytes(pem));
        }
        catch (CryptographicException) { return ApiResult<byte[]>.Fail("CERTIFICATE_MATERIAL_INVALID", "证书或私钥无法转换为请求的格式。"); }
    }

    private static Task BeforeMutationAsync(DeploymentExecutionContext context, CancellationToken ct) =>
        context.BeforeExternalMutationAsync?.Invoke(ct) ?? Task.CompletedTask;

    private static async Task<bool> RestoreAsync(IRemoteSession session, IReadOnlyList<FileReceipt> receipts, string suffix, CancellationToken ct, Func<CancellationToken, Task>? beforeMutation = null)
    {
        try
        {
            foreach (var file in receipts.Reverse())
            {
                var info = await session.StatAsync(file.Path, ct);
                if (info.Exists)
                {
                    var digest = Digest(await session.ReadAsync(file.Path, FileLimit, ct));
                    if (digest == file.OldDigest && file.Existed) continue;
                    if (digest != file.NewDigest) return false;
                    if (beforeMutation is not null) await beforeMutation(ct);
                    await session.MoveAsync(file.Path, file.Path + ".ssl-restored-" + suffix, ct);
                }
                if (file.Existed)
                {
                    if (!(await session.StatAsync(file.BackupPath, ct)).Exists ||
                        Digest(await session.ReadAsync(file.BackupPath, FileLimit, ct)) != file.OldDigest) return false;
                    if (beforeMutation is not null) await beforeMutation(ct);
                    await session.MoveAsync(file.BackupPath, file.Path, ct);
                }
            }
            return true;
        }
        catch (Exception exception) when (exception is IOException or Renci.SshNet.Common.SshException or OperationCanceledException)
        { return false; }
    }

    private static ApiResult<DeploymentExecutionResult> ExecutionFailure(string code, string message,
        DeploymentExecutionContext context, IReadOnlyList<FileReceipt> receipts, RecoveryJournal? journal = null) =>
        new(false, code, message, new(message, Fingerprint: context.Material.Metadata.Fingerprint, VerificationLevel: "None",
            ReceiptJson: journal is null ? JsonSerializer.Serialize(new FileDeploymentReceipt(context.Material.Metadata.Fingerprint, receipts)) : Serialize(journal)));
    private static ApiResult<T> Failure<T>(string code, string message) => ApiResult<T>.Fail(code, message);
    private static string Digest(byte[] content) => Convert.ToHexString(SHA256.HashData(content));
    private static bool SameState(FileState first, FileState second) => JsonSerializer.Serialize(first) == JsonSerializer.Serialize(second);
    private static bool ValidTaskId(string id) => id.Length is > 0 and <= 80 && id.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_');
    private static string NormalizeFingerprint(string value) => value.Replace("SHA256:", "", StringComparison.OrdinalIgnoreCase).Replace(":", "").ToUpperInvariant();
    private sealed record ResolvedFile(string Role, string Path, string SourceFileName = "");
    public sealed record PlannedFile(string Path, bool Exists, string Digest, short? Permissions);
    public sealed record FileState(string MaterialDigest, IReadOnlyList<PlannedFile> Files);
    public sealed record FileReceipt(string Path, string BackupPath, string StagePath, bool Existed, string OldDigest, string NewDigest);
    // 上传尚未完成时可能只有空回执；返回不可核对，避免失败后的查询再次抛系统异常。
    private static FileDeploymentReceipt? ReadReceipt(string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;
        try { return JsonSerializer.Deserialize<FileDeploymentReceipt>(json); }
        catch (JsonException) { return null; }
    }

    /// <summary>新增字段为可选值，旧文件回滚和既有回执保持兼容；不保存命令正文或材料内容。</summary>
    public sealed record FileDeploymentReceipt(string Fingerprint, IReadOnlyList<FileReceipt> Files,
        IReadOnlyList<FileCommandReceipt>? Commands = null, bool ActivationStarted = false, int SchemaVersion = 0);
    public sealed record FileCommandReceipt(string StepId, string Digest, string Status, int? ExitCode = null,
        int Attempt = 0, int TrackingVersion = 0);
    private sealed class RecoveryJournal(string fingerprint, List<FileReceipt> files)
    {
        public string Fingerprint { get; } = fingerprint;
        public List<FileReceipt> Files { get; } = files;
        public List<FileCommandReceipt> Commands { get; } = [];
        public bool ActivationStarted { get; set; }
        public int SchemaVersion { get; set; } = 1;
    }
    private static string Serialize(RecoveryJournal journal) => JsonSerializer.Serialize(new FileDeploymentReceipt(
        journal.Fingerprint, journal.Files, journal.Commands, journal.ActivationStarted, journal.SchemaVersion));
    private static Task CheckpointAsync(DeploymentExecutionContext context, RecoveryJournal journal, string phase, CancellationToken ct) =>
        context.SaveCheckpointAsync?.Invoke(phase, Serialize(journal), ct) ?? Task.CompletedTask;
    private static async Task<string?> SafeDigestAsync(IRemoteSession session, string path, CancellationToken ct)
    {
        var info = await session.StatAsync(path, ct);
        if (!info.Exists) return null;
        if (info.IsDirectory || info.IsSymbolicLink || info.Length > FileLimit) throw new IOException("恢复文件不是允许的普通文件。");
        return Digest(await session.ReadAsync(path, FileLimit, ct));
    }
}
