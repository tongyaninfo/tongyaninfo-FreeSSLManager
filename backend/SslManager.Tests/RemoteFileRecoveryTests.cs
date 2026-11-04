using System.Text;
using System.Text.Json;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Deployment;

namespace SslManager.Tests;

/// <summary>通过进程强退替身和持久化回执验证 SSH 断点续跑；不连接真实设备或删除文件。</summary>
public sealed class RemoteFileRecoveryTests
{
    [Theory]
    [InlineData("write", 1)]
    [InlineData("write", 2)]
    [InlineData("move", 1)]
    [InlineData("move", 2)]
    [InlineData("move", 3)]
    [InlineData("move", 4)]
    public async Task ProcessExitAfterEachFileMutationContinuesOnlyMissingOperations(string operation, int index)
    {
        var fixture = new Fixture();
        var plan = await fixture.PlanAsync();
        fixture.Remote.CrashOperation = operation;
        fixture.Remote.CrashIndex = index;
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        var interruptedWrites = fixture.Remote.Writes.Count;
        fixture.Remote.CrashOperation = "";

        // 新服务只读取保存后的 JSON 和远端现场，不复用原调用的局部回执。
        var restarted = new RemoteFileDeploymentService(new FakeTransport(fixture.Remote));
        var result = await restarted.RecoverAsync(fixture.Context(plan, recovery: true), false, default);

        Assert.True(result.Success, result.Message);
        Assert.Equal("Completed", result.Data!.Disposition);
        Assert.Equal("new-certificate", fixture.Remote.Text("/ssl/cert.pem"));
        Assert.Equal("new-private-key", fixture.Remote.Text("/ssl/key.pem"));
        Assert.Equal("old-certificate", fixture.Remote.Text("/ssl/cert.pem.ssl-backup-task-1"));
        Assert.Equal("old-key", fixture.Remote.Text("/ssl/key.pem.ssl-backup-task-1"));
        Assert.Equal(2, fixture.Remote.Writes.Count);
        Assert.Equal(4, fixture.Remote.Moves.Count);
        if (operation == "move") Assert.Equal(interruptedWrites, fixture.Remote.Writes.Count);
        Assert.DoesNotContain("new-private-key", fixture.Checkpoint);
    }

    [Fact]
    public async Task PartiallyWrittenStageIsPreservedAndReplacedWithANewStagePath()
    {
        var fixture = new Fixture();
        var plan = await fixture.PlanAsync();
        fixture.Remote.PartialWriteThenCrash = true;
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        var originalStage = "/ssl/cert.pem.ssl-stage-task-1";
        Assert.Equal("partial", fixture.Remote.Text(originalStage));

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.True(result.Success, result.Message);
        Assert.Equal("partial", fixture.Remote.Text(originalStage));
        Assert.Equal("new-certificate", fixture.Remote.Text("/ssl/cert.pem"));
        Assert.Contains(fixture.Remote.Writes, path => path.StartsWith(originalStage + "-", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ExternalFileChangeStopsRecoveryBeforeAnyAdditionalMutation()
    {
        var fixture = new Fixture();
        var plan = await fixture.PlanAsync();
        fixture.Remote.CrashOperation = "write"; fixture.Remote.CrashIndex = 1;
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        fixture.Remote.CrashOperation = "";
        fixture.Remote.Set("/ssl/key.pem", "human-replacement");
        var writes = fixture.Remote.Writes.Count;

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.False(result.Success);
        Assert.Equal("RECOVERY_CONFLICT", result.Code);
        Assert.Equal("Blocked", result.Data!.Disposition);
        Assert.Equal(writes, fixture.Remote.Writes.Count);
        Assert.Empty(fixture.Remote.Moves);
    }

    [Fact]
    public async Task UnknownCommandWithoutProofIsNotReplayed()
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.PostCommands = [new("restart-service"), new("next-command")];
        var plan = await fixture.PlanAsync();
        fixture.Remote.CrashOperation = "command"; fixture.Remote.CrashIndex = 1;
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        fixture.Remote.CrashOperation = "";

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.Equal("COMMAND_RECOVERY_UNCONFIRMED", result.Code);
        Assert.Equal("Blocked", result.Data!.Disposition);
        Assert.Single(fixture.Remote.Commands);
        Assert.Equal(2, fixture.Remote.Writes.Count);
    }

    [Fact]
    public async Task CommandReadbackProvesCompletionAndContinuesTheNextCommand()
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.PostCommands = [new("restart-service", RecoveryCheckCommand: "check-service"), new("next-command")];
        var plan = await fixture.PlanAsync();
        fixture.Remote.CrashOperation = "command"; fixture.Remote.CrashIndex = 1;
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        fixture.Remote.CrashOperation = "";

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.True(result.Success, result.Message);
        Assert.Equal(3, fixture.Remote.Commands.Count);
        Assert.Single(fixture.Remote.Commands, command => command.Contains("restart-service"));
        Assert.Contains("check-service", fixture.Remote.Commands[1]);
        Assert.Contains("next-command", fixture.Remote.Commands[2]);
    }

    [Fact]
    public async Task FailedCommandReadbackDoesNotAuthorizeRepeatingTheCommand()
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.PostCommands = [new("restart-service", RecoveryCheckCommand: "check-service")];
        var plan = await fixture.PlanAsync();
        fixture.Remote.CrashOperation = "command"; fixture.Remote.CrashIndex = 1;
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        fixture.Remote.CrashOperation = "";
        fixture.Remote.CommandResults.Enqueue(new(1, true));

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.Equal("Blocked", result.Data!.Disposition);
        Assert.Equal(2, fixture.Remote.Commands.Count);
        Assert.Single(fixture.Remote.Commands, command => command.Contains("restart-service"));
    }

    [Fact]
    public async Task RetryPolicyDoesNotReplayWhileTheOriginalRemoteExecutionCouldStillBeRunning()
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.PostCommands = [new("idempotent-reload", RetryOnInterruption: true)];
        var plan = await fixture.PlanAsync();
        fixture.Remote.CrashOperation = "command"; fixture.Remote.CrashIndex = 1;
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        fixture.Remote.CrashOperation = "";

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.False(result.Success);
        Assert.Equal("Retry", result.Data!.Disposition);
        Assert.Equal("RECOVERY_RETRY", result.Code);
        Assert.Single(fixture.Remote.Commands);
        Assert.Equal(2, fixture.Remote.Writes.Count);
    }

    [Fact]
    public async Task CompletedCommandCheckpointSurvivesExitBeforeTheNextCommand()
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.PostCommands = [new("first-command"), new("second-command")];
        var plan = await fixture.PlanAsync();
        fixture.ExitOnCheckpoint = "PostCommandCompleted";
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        fixture.ExitOnCheckpoint = "";

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.True(result.Success, result.Message);
        Assert.Equal(2, fixture.Remote.Commands.Count);
        Assert.Single(fixture.Remote.Commands, command => command.Contains("first-command"));
        Assert.Contains("second-command", fixture.Remote.Commands[1]);
    }

    [Fact]
    public async Task InspectionChecksThePrivateKeyAsWellAsTheCertificate()
    {
        var fixture = new Fixture();
        var plan = await fixture.PlanAsync();
        var completed = await fixture.Service.ExecuteAsync(fixture.Context(plan), false, default);
        Assert.True(completed.Success);
        fixture.Remote.Set("/ssl/key.pem", "foreign-key");

        var result = await fixture.Service.InspectAsync(new(fixture.Target, plan, fixture.Material.Metadata, completed.Data!.ReceiptJson), false, default);

        Assert.True(result.Success);
        Assert.False(result.Data!.MatchesExpected);
    }

    [Fact]
    public async Task MissingReceiptCanResumeOnlyAnUntouchedOriginalScene()
    {
        var fixture = new Fixture();
        var plan = await fixture.PlanAsync();
        fixture.Remote.Set("/ssl/cert.pem.ssl-stage-task-1", "unknown-stage");

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.Equal("RECOVERY_EVIDENCE_MISSING", result.Code);
        Assert.Empty(fixture.Remote.Writes);
        Assert.Empty(fixture.Remote.Moves);
    }

    [Fact]
    public async Task ExplicitlyFailedValidationCannotReactivateFilesDuringRecovery()
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.ValidationCommands = [new("validate-config")];
        fixture.Remote.CommandResults.Enqueue(new(1, true));
        var plan = await fixture.PlanAsync();
        var failed = await fixture.Service.ExecuteAsync(fixture.Context(plan), false, default);
        Assert.Equal("COMMAND_VALIDATION_FAILED", failed.Code);
        var writes = fixture.Remote.Writes.Count;
        var moves = fixture.Remote.Moves.Count;

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.Equal("COMMAND_FAILED", result.Code);
        Assert.Equal("old-certificate", fixture.Remote.Text("/ssl/cert.pem"));
        Assert.Equal("old-key", fixture.Remote.Text("/ssl/key.pem"));
        Assert.Equal(writes, fixture.Remote.Writes.Count);
        Assert.Equal(moves, fixture.Remote.Moves.Count);
    }

    [Theory]
    [InlineData("{}")]
    [InlineData("invalid-json")]
    [InlineData("{\"schemaVersion\":2,\"executionState\":\"NotStarted\"}")]
    [InlineData("{\"schemaVersion\":\"1\",\"executionState\":\"NotStarted\"}")]
    public async Task UnchangedOriginalFilesDoNotProveAnOldTaskWasNeverExecuted(string receipt)
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.PostCommands = [new("must-not-repeat")];
        var plan = await fixture.PlanAsync(); fixture.Checkpoint = receipt;

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.Equal("RECOVERY_EVIDENCE_MISSING", result.Code);
        Assert.Equal("Blocked", result.Data!.Disposition);
        Assert.Empty(fixture.Remote.Commands); Assert.Empty(fixture.Remote.Writes); Assert.Empty(fixture.Remote.Moves);
    }

    [Fact]
    public async Task ExplicitNotStartedSentinelCanContinueTheFirstExecution()
    {
        var fixture = new Fixture();
        var plan = await fixture.PlanAsync(); fixture.Checkpoint = "{\"schemaVersion\":1,\"executionState\":\"NotStarted\"}";

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.True(result.Success, result.Message);
        Assert.Equal(2, fixture.Remote.Writes.Count);
    }

    [Fact]
    public async Task RemoteCompletedReceiptFinishesACommandWhoseDatabaseCompletionWasLost()
    {
        var fixture = new Fixture(); fixture.Remote.TrackCommands = true;
        fixture.Target.Configuration.PostCommands = [new("restart-service")];
        var plan = await fixture.PlanAsync(); fixture.Remote.CrashOperation = "command"; fixture.Remote.CrashIndex = 1;
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        fixture.Remote.CrashOperation = "";
        fixture.Remote.Evidence[("PostCommand:0", 0)] = new("Completed", 0);

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.True(result.Success, result.Message);
        Assert.Single(fixture.Remote.Commands);
    }

    [Fact]
    public async Task ActiveRemoteLockPreventsTheSecondExecutionAndAnyPrematureSuccessCheck()
    {
        var fixture = new Fixture(); fixture.Remote.TrackCommands = true;
        fixture.Target.Configuration.PostCommands = [new("long-running-command", RecoveryCheckCommand: "check-result", RetryOnInterruption: true)];
        var plan = await fixture.PlanAsync(); fixture.Remote.CrashOperation = "command"; fixture.Remote.CrashIndex = 1;
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        fixture.Remote.CrashOperation = "";

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.Equal("Retry", result.Data!.Disposition);
        Assert.Single(fixture.Remote.Commands);
        Assert.Single(fixture.Remote.TrackedExecutions);
    }

    [Fact]
    public async Task HistoricalStartedWithoutATrackingMarkerCannotUseMissingNewMarkersAsProofOfNotStarted()
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.PostCommands = [new("legacy-command", RetryOnInterruption: true)];
        var plan = await fixture.PlanAsync(); fixture.Remote.CrashOperation = "command"; fixture.Remote.CrashIndex = 1;
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        fixture.Remote.CrashOperation = "";
        // 升级后的会话支持新协议，但旧Started没有TrackingVersion=1，远端NotStarted不能追认旧命令未发送。
        fixture.Remote.TrackCommands = true;

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.Equal("Retry", result.Data!.Disposition);
        Assert.Single(fixture.Remote.Commands);
        Assert.Empty(fixture.Remote.TrackedExecutions);
    }

    [Fact]
    public async Task StoppedUnknownExecutionCanUseANewAttemptOnlyWithAnExplicitRetryPolicy()
    {
        var fixture = new Fixture(); fixture.Remote.TrackCommands = true;
        fixture.Target.Configuration.PostCommands = [new("idempotent-reload", RetryOnInterruption: true)];
        var plan = await fixture.PlanAsync(); fixture.Remote.CrashOperation = "command"; fixture.Remote.CrashIndex = 1;
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        fixture.Remote.CrashOperation = "";
        fixture.Remote.Evidence[("PostCommand:0", 0)] = new("StoppedUnknown");

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.True(result.Success, result.Message);
        Assert.Equal(2, fixture.Remote.Commands.Count);
        Assert.Equal(new[] { 0, 1 }, fixture.Remote.TrackedExecutions.Select(item => item.Attempt));
        Assert.Single(fixture.Remote.TrackedExecutions.Select(item => item.StepId).Distinct());
    }

    [Fact]
    public async Task RemoteNotStartedEvidenceCanContinueThePersistedCommandIntentWithoutRequiringARetryPolicy()
    {
        var fixture = new Fixture(); fixture.Remote.TrackCommands = true;
        fixture.Target.Configuration.PostCommands = [new("first-execution")];
        var plan = await fixture.PlanAsync(); fixture.ExitOnCheckpoint = "PostCommandIntent";
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        fixture.ExitOnCheckpoint = "";

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.True(result.Success, result.Message);
        Assert.Single(fixture.Remote.Commands);
        Assert.Equal(0, Assert.Single(fixture.Remote.TrackedExecutions).Attempt);
    }

    [Fact]
    public async Task NonzeroRemoteCompletionStopsBeforeTheNextCommand()
    {
        var fixture = new Fixture(); fixture.Remote.TrackCommands = true;
        fixture.Target.Configuration.PostCommands = [new("failed-command"), new("next-command")];
        var plan = await fixture.PlanAsync(); fixture.Remote.CrashOperation = "command"; fixture.Remote.CrashIndex = 1;
        await Assert.ThrowsAsync<ProcessExit>(() => fixture.Service.ExecuteAsync(fixture.Context(plan), false, default));
        fixture.Remote.CrashOperation = "";
        fixture.Remote.Evidence[("PostCommand:0", 0)] = new("Completed", 7);

        var result = await fixture.Service.RecoverAsync(fixture.Context(plan, true), false, default);

        Assert.Equal("COMMAND_FAILED", result.Code);
        Assert.Single(fixture.Remote.Commands);
    }

    [Fact]
    public async Task MissingRemoteProtocolDependencyIsRejectedDuringPlanningAndBeforeAnyFileWrite()
    {
        var fixture = new Fixture(); fixture.Remote.TrackCommands = true;
        fixture.Target.Configuration.PostCommands = [new("reload-service")];
        var plan = await fixture.PlanAsync();
        fixture.Remote.CommandRecoveryAvailable = false;

        var replanned = await fixture.Service.PlanAsync(fixture.Target, fixture.Material.Metadata, false, default);
        var execution = await fixture.Service.ExecuteAsync(fixture.Context(plan), false, default);

        Assert.Equal("COMMAND_RECOVERY_UNSUPPORTED", replanned.Code);
        Assert.Equal("COMMAND_RECOVERY_UNSUPPORTED", execution.Code);
        Assert.Empty(fixture.Remote.Writes); Assert.Empty(fixture.Remote.Moves); Assert.Empty(fixture.Remote.Commands);
    }

    private sealed class Fixture
    {
        public FakeRemote Remote { get; } = new();
        public RemoteFileDeploymentService Service { get; }
        public DeploymentTargetContext Target { get; } = new()
        {
            Id = "target", Configuration = new() { HostKeyFingerprint = "SHA256:verified", OutputDirectory = "/ssl",
                Files = [new("FullChain", "cert.pem"), new("PrivateKey", "key.pem")] }
        };
        public CertificateMaterial Material { get; } = new()
        {
            Metadata = new("cert", "example.test", ["example.test"], "fingerprint", "material-digest", DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(30)),
            CertificatePem = "new-certificate", FullChainPem = "new-certificate", PrivateKeyPem = "new-private-key"
        };
        public string Checkpoint { get; set; } = "{}";
        public string ExitOnCheckpoint { get; set; } = "";
        public Fixture()
        {
            Remote.Set("/ssl/cert.pem", "old-certificate"); Remote.Set("/ssl/key.pem", "old-key");
            Service = new(new FakeTransport(Remote));
        }
        public async Task<DeploymentTargetPlan> PlanAsync()
        {
            var result = await Service.PlanAsync(Target, Material.Metadata, false, default);
            Assert.True(result.Success, result.Message); return result.Data!;
        }
        public DeploymentExecutionContext Context(DeploymentTargetPlan plan, bool recovery = false) => new()
        {
            TaskId = "task-1", Target = Target, Material = Material, Plan = plan, IsRecovery = recovery, ReceiptJson = Checkpoint,
            ReportProgressAsync = (_, _, _) => Task.CompletedTask,
            SaveCheckpointAsync = (phase, receipt, _) =>
            {
                Checkpoint = receipt;
                if (phase == ExitOnCheckpoint) throw new ProcessExit();
                return Task.CompletedTask;
            }
        };
    }
    private sealed class ProcessExit : Exception;
    private sealed class FakeTransport(FakeRemote remote) : IRemoteTransport
    {
        public Task<ApiResult<IRemoteSession>> ConnectAsync(DeploymentTargetContext target, CancellationToken ct) =>
            Task.FromResult(ApiResult<IRemoteSession>.Ok(remote));
    }
    private sealed class FakeRemote : IRemoteSession
    {
        public Dictionary<string, byte[]> Files { get; } = new(StringComparer.Ordinal);
        public List<string> Writes { get; } = [];
        public List<(string Source, string Destination)> Moves { get; } = [];
        public List<string> Commands { get; } = [];
        public Queue<RemoteCommandResult> CommandResults { get; } = new();
        public string CrashOperation { get; set; } = "";
        public int CrashIndex { get; set; }
        public bool PartialWriteThenCrash { get; set; }
        public bool TrackCommands { get; set; }
        public bool SupportsCommandRecovery => TrackCommands;
        public bool CommandRecoveryAvailable { get; set; } = true;
        public Task<ApiResult<bool>> CheckCommandRecoverySupportAsync(bool windows, CancellationToken ct) =>
            Task.FromResult(CommandRecoveryAvailable ? ApiResult<bool>.Ok(true) : ApiResult<bool>.Fail("COMMAND_RECOVERY_UNSUPPORTED", "缺少测试执行锁能力。"));
        public Dictionary<(string StepId, int Attempt), RemoteCommandEvidence> Evidence { get; } = [];
        public List<RemoteCommandIdentity> TrackedExecutions { get; } = [];
        public void Set(string path, string value) => Files[path] = Encoding.UTF8.GetBytes(value);
        public string Text(string path) => Encoding.UTF8.GetString(Files[path]);
        public Task<RemoteFileInfo> StatAsync(string path, CancellationToken ct) => Task.FromResult(
            Files.TryGetValue(path, out var content) ? new RemoteFileInfo(true, Length: content.Length, Permissions: 420)
                : new RemoteFileInfo(path is "/" or "/ssl", path is "/" or "/ssl"));
        public Task<byte[]> ReadAsync(string path, int byteLimit, CancellationToken ct) => Files.TryGetValue(path, out var content)
            ? Task.FromResult(content) : throw new IOException("Missing file");
        public Task WriteNewAsync(string path, byte[] content, short? permissions, CancellationToken ct)
        {
            if (!Files.TryAdd(path, PartialWriteThenCrash ? Encoding.UTF8.GetBytes("partial") : content)) throw new IOException("Already exists");
            Writes.Add(path);
            if (PartialWriteThenCrash) { PartialWriteThenCrash = false; throw new ProcessExit(); }
            Crash("write", Writes.Count); return Task.CompletedTask;
        }
        public Task CreateDirectoryAsync(string path, short? permissions, CancellationToken ct) => throw new InvalidOperationException("Existing test directories only");
        public Task MoveAsync(string source, string destination, CancellationToken ct)
        {
            if (!Files.TryGetValue(source, out var content) || Files.ContainsKey(destination)) throw new IOException("Invalid move");
            Files[destination] = content; Files.Remove(source); Moves.Add((source, destination));
            Crash("move", Moves.Count); return Task.CompletedTask;
        }
        public Task<RemoteCommandResult> ExecuteAsync(string command, int timeoutSeconds, CancellationToken ct)
        {
            Commands.Add(command); Crash("command", Commands.Count);
            return Task.FromResult(CommandResults.Count > 0 ? CommandResults.Dequeue() : new RemoteCommandResult(0, true));
        }
        public async Task<RemoteCommandResult> ExecuteTrackedAsync(RemoteCommandIdentity identity, string command, int timeoutSeconds, CancellationToken ct)
        {
            TrackedExecutions.Add(identity);
            if (Evidence.Any(pair => pair.Key.StepId == identity.StepId && pair.Value.State == "Running")) return new(null, false);
            Evidence[(identity.StepId, identity.Attempt)] = new("Running");
            var result = await ExecuteAsync(command, timeoutSeconds, ct);
            Evidence[(identity.StepId, identity.Attempt)] = result.OutcomeKnown ? new("Completed", result.ExitCode) : new("Running");
            return result;
        }
        public Task<RemoteCommandEvidence> InspectCommandAsync(RemoteCommandIdentity identity, int timeoutSeconds, CancellationToken ct)
        {
            if (Evidence.Any(pair => pair.Key.StepId == identity.StepId && pair.Value.State == "Running"))
                return Task.FromResult(new RemoteCommandEvidence("Running"));
            return Task.FromResult(Evidence.GetValueOrDefault((identity.StepId, identity.Attempt), new("NotStarted")));
        }
        private void Crash(string operation, int index) { if (CrashOperation == operation && CrashIndex == index) throw new ProcessExit(); }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
