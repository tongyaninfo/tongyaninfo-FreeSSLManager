using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Deployment;
using SslManager.Api.Service.impl.Deployment.Executors;

namespace SslManager.Tests;

/// <summary>Harbor 专项测试使用内存文件系统，不连接 Harbor、签发证书或运行 Docker。</summary>
public sealed class HarborDeploymentTests
{
    [Fact]
    public void DescriptorDeclaresOnlyHarborComposeAndPemMaterials()
    {
        var f = new Fixture();
        var resolved = new DeploymentExecutorResolver([f.Executor]).Resolve(HarborComposeSshDeploymentExecutor.ExecutorKey);
        Assert.True(resolved.Success);
        Assert.Equal("Harbor", resolved.Data!.Descriptor.TargetType);
        Assert.Equal(new[] { "FullChain", "PrivateKey" }, resolved.Data.Descriptor.MaterialFormats);
        Assert.True(resolved.Data is IDeploymentRecoveryExecutor);
    }

    [Theory]
    [InlineData("directory")]
    [InlineData("compose")]
    [InlineData("service")]
    [InlineData("domain")]
    [InlineData("verification")]
    [InlineData("port")]
    [InlineData("sni")]
    [InlineData("source")]
    [InlineData("roles")]
    [InlineData("validation")]
    [InlineData("post")]
    public async Task InvalidConfigurationStopsBeforeConnecting(string field)
    {
        var f = new Fixture();
        var c = f.Target.Configuration;
        switch (field)
        {
            case "directory": c.HarborInstallDirectory = "/home/../harbor"; break;
            case "compose": c.HarborComposeCommand = "docker compose; touch /tmp/injected"; break;
            case "service": c.HarborProxyService = "proxy; touch /tmp/injected"; break;
            case "domain": c.SourceDomain = "*.example.com"; break;
            case "verification": c.VerificationHost = "https://127.0.0.1"; break;
            case "port": c.VerificationPort = 0; break;
            case "sni": c.VerificationServerName = "other.example.com"; break;
            case "source": c.SourceFormat = "nginx"; break;
            case "roles": c.Files = [new("FullChain", "fullchain.pem"), new("Pfx", "server.pfx")]; break;
            case "validation": c.ValidationCommands = [new("true")]; break;
            case "post": c.PostCommands = [new("docker compose down")]; break;
        }
        var result = await f.Executor.TestAsync(f.Target, default);
        Assert.Equal("CONFIGURATION_INVALID", result.Code);
        Assert.Equal(0, f.Transport.ConnectCount);
        Assert.Empty(f.Remote.Writes);
    }

    [Fact]
    public async Task ConnectionTestReadsOnlyComposeServicesAndProxyImage()
    {
        var f = new Fixture();
        var result = await f.Executor.TestAsync(f.Target, default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("Harbor v2.10.0", result.Data!.ProductVersion);
        var query = Assert.Single(f.Remote.Commands);
        Assert.Contains("config --services", query);
        Assert.Contains(".Config.Image", query);
        Assert.Contains("id -u", query);
        Assert.Contains("id -g", query);
        Assert.DoesNotContain(".Config.Env", query);
        Assert.DoesNotContain("harbor.yml", query);
        Assert.DoesNotContain("--force-recreate", query);
        Assert.Empty(f.Remote.Writes);
        Assert.Empty(f.Remote.Moves);
    }

    [Theory]
    [InlineData("goharbor/nginx-photon:v1.10.0")]
    [InlineData("goharbor/nginx-photon:v3.0.0")]
    [InlineData("nginx:latest")]
    public async Task UnsupportedProxyImageCannotCreatePlan(string image)
    {
        var f = new Fixture();
        f.Remote.Image = image;
        var result = await f.Executor.PlanAsync(f.Target, f.Material.Metadata, new("harbor"), default);
        Assert.Equal("HARBOR_VERSION_UNSUPPORTED", result.Code);
        Assert.Empty(f.Remote.Writes);
        Assert.Empty(f.Remote.Moves);
    }

    [Fact]
    public async Task ProxyProbeFailureDoesNotExposeRemoteOutput()
    {
        var f = new Fixture();
        f.Remote.ProbeExitCode = 1;
        f.Remote.Image = "SECRET_REMOTE_OUTPUT";
        var result = await f.Executor.TestAsync(f.Target, default);
        Assert.Equal("HARBOR_PROBE_FAILED", result.Code);
        Assert.DoesNotContain("SECRET_REMOTE_OUTPUT", result.Message);
        Assert.Empty(f.Remote.Writes);
    }

    [Theory]
    [InlineData("-1")]
    [InlineData("10000; touch /tmp/injected")]
    [InlineData("4294967295")]
    [InlineData("10000\nadditional-output")]
    public async Task InvalidProxyAccountCannotCreatePlan(string uid)
    {
        var f = new Fixture();
        f.Remote.Uid = uid;
        var planned = await f.Executor.PlanAsync(f.Target, f.Material.Metadata, new("harbor"), default);
        Assert.Equal("HARBOR_PROBE_FAILED", planned.Code);
        Assert.Empty(f.Remote.Writes);
    }

    [Fact]
    public async Task ParentDirectorySymlinkBlocksProbeBeforeCommands()
    {
        var f = new Fixture();
        f.Remote.SymbolicLinks.Add("/home");
        var result = await f.Executor.TestAsync(f.Target, default);
        Assert.Equal("CONFIGURATION_INVALID", result.Code);
        Assert.Empty(f.Remote.Commands);
    }

    [Fact]
    public async Task AutomaticDirectoryCreationIsRejectedBeforeAnyRemoteOperation()
    {
        var f = new Fixture();
        f.Target.Configuration.CreateDirectory = true;
        var error = HarborComposeSshDeploymentExecutor.ValidateConfiguration(f.Target.Configuration);
        Assert.Contains("不支持自动创建目录", error);
        var result = await f.Executor.TestAsync(f.Target, default);
        Assert.Equal("CONFIGURATION_INVALID", result.Code);
        Assert.Equal(0, f.Transport.ConnectCount);
        Assert.Empty(f.Remote.Commands);
        Assert.Empty(f.Remote.Writes);
    }

    [Fact]
    public async Task PlanDoesNotMutatePersistentConfigurationAndDescribesProxyInterruption()
    {
        var f = new Fixture();
        var before = JsonSerializer.Serialize(f.Target.Configuration);
        var plan = await f.PlanAsync();
        Assert.Equal(before, JsonSerializer.Serialize(f.Target.Configuration));
        Assert.Equal(new[] { "/ssl/fullchain.pem", "/ssl/privkey.pem" }, plan.FilePaths);
        Assert.Contains("只重建 Harbor proxy", plan.Summary);
        Assert.Contains(plan.Warnings!, warning => warning.Contains("HTTPS 访问会短暂中断"));
        Assert.Contains(plan.Warnings!, warning => warning.Contains("恢复原文件仅恢复"));
        using var snapshot = JsonDocument.Parse(plan.PreconditionsJson);
        var identity = snapshot.RootElement.GetProperty("HarborPlan");
        Assert.Equal(1, identity.GetProperty("SchemaVersion").GetInt32());
        Assert.Equal(10000, identity.GetProperty("Uid").GetInt32());
        Assert.Equal(10000, identity.GetProperty("Gid").GetInt32());
        Assert.Empty(f.Remote.Writes);
    }

    [Fact]
    public async Task CertificateDomainAndSanMustBothMatchBinding()
    {
        var f = new Fixture();
        var metadata = f.Material.Metadata with { Domain = "other.example.com" };
        Assert.Equal("SOURCE_CERTIFICATE_MISMATCH",
            (await f.Executor.PlanAsync(f.Target, metadata, new("harbor"), default)).Code);
        metadata = f.Material.Metadata with { Domains = ["other.example.com"] };
        Assert.Equal("SOURCE_CERTIFICATE_MISMATCH",
            (await f.Executor.PlanAsync(f.Target, metadata, new("harbor"), default)).Code);
        Assert.Equal(0, f.Transport.ConnectCount);
    }

    [Fact]
    public async Task StalePlanStopsBeforeUploadAndProxyRecreation()
    {
        var f = new Fixture();
        var plan = await f.PlanAsync();
        f.Remote.Set("/ssl/fullchain.pem", "external-change");
        var result = await f.Executor.ExecuteAsync(f.Context(plan), default);
        Assert.Equal("PLAN_STALE", result.Code);
        Assert.Empty(f.Remote.Writes);
        Assert.DoesNotContain(f.Remote.Commands, command => command.Contains("--force-recreate"));
    }

    [Fact]
    public async Task MaterialValidationFailureRestoresFilesWithoutActivatingProxy()
    {
        var f = new Fixture();
        f.Remote.ValidationExitCode = 1;
        var result = await f.Executor.ExecuteAsync(f.Context(await f.PlanAsync()), default);
        Assert.Equal("COMMAND_VALIDATION_FAILED", result.Code);
        Assert.Equal("old-certificate", f.Remote.Text("/ssl/fullchain.pem"));
        Assert.Equal("old-private-key", f.Remote.Text("/ssl/privkey.pem"));
        Assert.DoesNotContain(f.Remote.Commands, command => command.Contains("--force-recreate"));
        Assert.Empty(f.Target.Configuration.ValidationCommands);
        Assert.Empty(f.Target.Configuration.PostCommands);
    }

    [Fact]
    public async Task DeploymentPreservesBackupsAndCannotSucceedWithoutStrictTls()
    {
        var f = new Fixture();
        var before = JsonSerializer.Serialize(f.Target.Configuration);
        var plan = await f.PlanAsync();
        var result = await f.Executor.ExecuteAsync(f.Context(plan), default);
        Assert.Equal("VERIFICATION_FAILED", result.Code);
        Assert.Equal("new-full-chain", f.Remote.Text("/ssl/fullchain.pem"));
        Assert.Equal("new-private-key", f.Remote.Text("/ssl/privkey.pem"));
        Assert.Equal("old-certificate", f.Remote.Text("/ssl/fullchain.pem.ssl-backup-harbor-task"));
        Assert.Equal("old-private-key", f.Remote.Text("/ssl/privkey.pem.ssl-backup-harbor-task"));
        Assert.Equal((short)384, f.Remote.Permissions["/ssl/privkey.pem"]);
        var activate = Assert.Single(f.Remote.Commands, command => command.Contains("--force-recreate"));
        Assert.Contains("up -d --no-deps --force-recreate", activate);
        Assert.Contains("nginx -t", activate);
        Assert.Contains("exec -T", activate);
        Assert.Contains("sleep 1", activate);
        var validation = Assert.Single(f.Remote.Commands, command => command.Contains("chown --"));
        Assert.Contains("chown -- 10000:10000", validation);
        Assert.DoesNotContain("id -u", validation);
        Assert.DoesNotContain("id -g", validation);
        Assert.True(f.Remote.Commands.IndexOf(validation) < f.Remote.Commands.IndexOf(activate));
        Assert.DoesNotContain(" down", activate);
        Assert.DoesNotContain("prepare", activate);
        Assert.DoesNotContain("install.sh", activate);
        Assert.Equal(before, JsonSerializer.Serialize(f.Target.Configuration));
        Assert.DoesNotContain("new-private-key", result.Data!.ReceiptJson);
        var inspection = await f.Executor.InspectAsync(new(f.Target, plan, f.Material.Metadata, result.Data.ReceiptJson), default);
        Assert.True(inspection.Data!.MatchesExpected);
        Assert.Equal("FileHashReadback", inspection.Data.VerificationLevel);
    }

    [Fact]
    public async Task InterruptedActivationIsNotRepeatedByRecovery()
    {
        var f = new Fixture();
        f.Remote.ActivationOutcomeKnown = false;
        var plan = await f.PlanAsync();
        var deployed = await f.Executor.ExecuteAsync(f.Context(plan), default);
        Assert.Equal("REMOTE_RESULT_UNKNOWN", deployed.Code);
        var recovered = await f.Executor.RecoverAsync(f.Context(plan, deployed.Data!.ReceiptJson), default);
        Assert.False(recovered.Success);
        Assert.Equal("COMMAND_RECOVERY_UNCONFIRMED", recovered.Code);
        Assert.Single(f.Remote.Commands, command => command.Contains("--force-recreate"));
    }

    [Fact]
    public async Task RecoveryVerifiesTlsAgainWithoutRepeatingCompletedActivation()
    {
        var f = new Fixture();
        var plan = await f.PlanAsync();
        var deployed = await f.Executor.ExecuteAsync(f.Context(plan), default);
        Assert.Equal("VERIFICATION_FAILED", deployed.Code);
        var recovered = await f.Executor.RecoverAsync(f.Context(plan, deployed.Data!.ReceiptJson), default);
        Assert.False(recovered.Success);
        Assert.Equal("VERIFICATION_FAILED", recovered.Code);
        Assert.Single(f.Remote.Commands, command => command.Contains("--force-recreate"));
    }

    [Fact]
    public async Task RollbackRestoresFilesAndExplicitlyRequiresProxyActivation()
    {
        var f = new Fixture();
        var deployed = await f.Executor.ExecuteAsync(f.Context(await f.PlanAsync()), default);
        var count = f.Remote.Commands.Count;
        var restored = await f.Executor.RollbackAsync(new(f.Target, "harbor-task", deployed.Data!.ReceiptJson), default);
        Assert.True(restored.Success, restored.Message);
        Assert.Equal("old-certificate", f.Remote.Text("/ssl/fullchain.pem"));
        Assert.Equal("old-private-key", f.Remote.Text("/ssl/privkey.pem"));
        Assert.Contains("尚未激活 Harbor 代理", restored.Data!.Message);
        Assert.Equal(count, f.Remote.Commands.Count);
    }

    [Fact]
    public async Task ActiveAndPrepareCopiesAreAllBackedUpVerifiedOwnedAndRestorable()
    {
        var f = new Fixture();
        f.Target.Configuration.Files.AddRange([new("FullChain", "source.crt", "/cert"), new("PrivateKey", "source.key", "/cert")]);
        f.Remote.Directories.Add("/cert");
        f.Remote.Set("/cert/source.crt", "old-source-certificate");
        f.Remote.Set("/cert/source.key", "old-source-key");
        var plan = await f.PlanAsync();
        var deployed = await f.Executor.ExecuteAsync(f.Context(plan), default);
        Assert.Equal("VERIFICATION_FAILED", deployed.Code);
        Assert.Equal(4, plan.FilePaths!.Length);
        Assert.Equal("new-full-chain", f.Remote.Text("/cert/source.crt"));
        Assert.Equal("new-private-key", f.Remote.Text("/cert/source.key"));
        Assert.Equal("old-source-key", f.Remote.Text("/cert/source.key.ssl-backup-harbor-task"));
        Assert.Equal((short)384, f.Remote.Permissions["/cert/source.key"]);
        var ownership = Assert.Single(f.Remote.Commands, command => command.Contains("chown --"));
        Assert.Contains("/cert/source.crt", ownership);
        Assert.Contains("/cert/source.key", ownership);
        var inspection = await f.Executor.InspectAsync(new(f.Target, plan, f.Material.Metadata, deployed.Data!.ReceiptJson), default);
        Assert.True(inspection.Data!.MatchesExpected);
        var rollback = await f.Executor.RollbackAsync(new(f.Target, "harbor-task", deployed.Data.ReceiptJson), default);
        Assert.True(rollback.Success, rollback.Message);
        Assert.Equal("old-source-certificate", f.Remote.Text("/cert/source.crt"));
        Assert.Equal("old-source-key", f.Remote.Text("/cert/source.key"));
    }

    [Theory]
    [InlineData("image")]
    [InlineData("uid")]
    [InlineData("gid")]
    public async Task IdentityChangeAfterPreviewStopsBeforeAnyWrite(string field)
    {
        var f = new Fixture();
        var plan = await f.PlanAsync();
        if (field == "image") f.Remote.Image = "goharbor/nginx-photon:v2.11.0";
        else if (field == "uid") f.Remote.Uid = "10001";
        else f.Remote.Gid = "10001";
        var deployed = await f.Executor.ExecuteAsync(f.Context(plan), default);
        Assert.Equal("PLAN_STALE", deployed.Code);
        Assert.Empty(f.Remote.Writes);
        Assert.Empty(f.Remote.Moves);
    }

    [Theory]
    [InlineData("missing")]
    [InlineData("version")]
    [InlineData("uid")]
    [InlineData("image")]
    public async Task MissingOrInvalidIdentityBlocksExecutionAndRecoveryWithoutGuessing(string field)
    {
        var f = new Fixture();
        var plan = await f.PlanAsync();
        var json = JsonNode.Parse(plan.PreconditionsJson)!.AsObject();
        if (field == "missing") json.Remove("HarborPlan");
        else if (field == "version") json["HarborPlan"]!["SchemaVersion"] = 2;
        else if (field == "uid") json["HarborPlan"]!["Uid"] = "10000; touch /tmp/injected";
        else json["HarborPlan"]!["ProxyImage"] = "nginx:latest";
        plan = plan with { PreconditionsJson = json.ToJsonString() };
        var connections = f.Transport.ConnectCount;
        Assert.Equal("PLAN_STALE", (await f.Executor.ExecuteAsync(f.Context(plan), default)).Code);
        Assert.Equal("PLAN_STALE", (await f.Executor.RecoverAsync(f.Context(plan), default)).Code);
        Assert.Equal(connections, f.Transport.ConnectCount);
        Assert.Empty(f.Remote.Writes);
    }

    [Fact]
    public async Task RecoveryCanSetFrozenOwnershipAfterCrashEvenWhenProxyCannotStart()
    {
        var f = new Fixture();
        var plan = await f.PlanAsync();
        var receipt = "{}";
        var context = new DeploymentExecutionContext
        {
            TaskId = "harbor-task", Target = f.Target, Plan = plan, Material = f.Material,
            ReportProgressAsync = (_, _, _) => Task.CompletedTask,
            SaveCheckpointAsync = (phase, checkpoint, _) =>
            {
                receipt = checkpoint;
                // 模拟进程在两个 root:root 文件完成切换、尚未设置容器账户权限时被终止。
                if (phase == "FileActivated" && f.Remote.Text("/ssl/privkey.pem") == "new-private-key")
                    throw new SimulatedProcessCrash();
                return Task.CompletedTask;
            }
        };
        await Assert.ThrowsAsync<SimulatedProcessCrash>(() => f.Executor.ExecuteAsync(context, default));
        Assert.DoesNotContain(f.Remote.Commands, command => command.Contains("chown --"));
        f.Remote.ProxyRunning = false;
        var commandCount = f.Remote.Commands.Count;
        var recovered = await f.Executor.RecoverAsync(f.Context(plan, receipt), default);
        // 假环境没有可信 HTTPS；能推进到严格 TLS 就证明已恢复权限并重新启动代理。
        Assert.Equal("VERIFICATION_FAILED", recovered.Code);
        Assert.True(f.Remote.ProxyRunning);
        var recoveryCommands = f.Remote.Commands.Skip(commandCount).ToArray();
        Assert.DoesNotContain(recoveryCommands, command => command.Contains(".Config.Image") || command.Contains("id -u") || command.Contains("id -g"));
        Assert.Contains(recoveryCommands, command => command.Contains("chown -- 10000:10000"));
        Assert.Contains(recoveryCommands, command => command.Contains("--force-recreate"));
    }

    private sealed class SimulatedProcessCrash : Exception;

    private sealed class Fixture
    {
        public FakeRemoteSession Remote { get; } = new();
        public FakeTransport Transport { get; }
        public HarborComposeSshDeploymentExecutor Executor { get; }
        public DeploymentTargetContext Target { get; } = new()
        {
            Id = "harbor", ExecutorKey = HarborComposeSshDeploymentExecutor.ExecutorKey,
            Endpoint = "127.0.0.1", Port = 22, Username = "root",
            Configuration = new()
            {
                HarborInstallDirectory = "/home/harbor", HarborComposeCommand = "docker compose", HarborProxyService = "proxy",
                OutputDirectory = "/ssl", HostKeyFingerprint = "SHA256:verified-host", SourceDomain = "harbor.example.com",
                Files = [new("FullChain", "fullchain.pem"), new("PrivateKey", "privkey.pem")],
                VerificationHost = "127.0.0.1", VerificationPort = 1, VerificationServerName = "harbor.example.com"
            }
        };
        public CertificateMaterial Material { get; } = new()
        {
            Metadata = new("certificate", "harbor.example.com", ["harbor.example.com"], "EXPECTED-FINGERPRINT", "material-digest",
                DateTime.UtcNow.AddDays(-1), DateTime.UtcNow.AddDays(60)),
            FullChainPem = "new-full-chain", PrivateKeyPem = "new-private-key"
        };
        public Fixture()
        {
            Transport = new(Remote);
            Executor = new(new RemoteFileDeploymentService(Transport), Transport);
            Remote.Set("/ssl/fullchain.pem", "old-certificate");
            Remote.Set("/ssl/privkey.pem", "old-private-key");
        }
        public async Task<DeploymentTargetPlan> PlanAsync()
        {
            var planned = await Executor.PlanAsync(Target, Material.Metadata, new("harbor"), default);
            Assert.True(planned.Success, planned.Message);
            return planned.Data!;
        }
        public DeploymentExecutionContext Context(DeploymentTargetPlan plan, string receipt = "{}") => new()
        {
            TaskId = "harbor-task", Target = Target, Plan = plan, Material = Material, ReceiptJson = receipt,
            IsRecovery = receipt != "{}", ReportProgressAsync = (_, _, _) => Task.CompletedTask
        };
    }

    private sealed class FakeTransport(FakeRemoteSession remote) : IRemoteTransport
    {
        public int ConnectCount { get; private set; }
        public Task<ApiResult<IRemoteSession>> ConnectAsync(DeploymentTargetContext target, CancellationToken ct)
        { ConnectCount++; return Task.FromResult(ApiResult<IRemoteSession>.Ok(remote)); }
    }

    private sealed class FakeRemoteSession : IRemoteSession
    {
        public Dictionary<string, byte[]> Files { get; } = new(StringComparer.Ordinal);
        public Dictionary<string, short> Permissions { get; } = new(StringComparer.Ordinal);
        public HashSet<string> Directories { get; } = ["/", "/home", "/home/harbor", "/ssl"];
        public HashSet<string> SymbolicLinks { get; } = [];
        public List<string> Writes { get; } = [];
        public List<string> Moves { get; } = [];
        public List<string> Commands { get; } = [];
        public string Image { get; set; } = "goharbor/nginx-photon:v2.10.0";
        public string Uid { get; set; } = "10000";
        public string Gid { get; set; } = "10000";
        public bool ProxyRunning { get; set; } = true;
        public int ProbeExitCode { get; set; }
        public int ValidationExitCode { get; set; }
        public bool ActivationOutcomeKnown { get; set; } = true;
        public void Set(string path, string value) => Files[path] = Encoding.UTF8.GetBytes(value);
        public string Text(string path) => Encoding.UTF8.GetString(Files[path]);
        public Task<RemoteFileInfo> StatAsync(string path, CancellationToken ct) => Task.FromResult(
            Files.TryGetValue(path, out var bytes) ? new RemoteFileInfo(true, Length: bytes.Length,
                Permissions: Permissions.TryGetValue(path, out var permissions) ? permissions : (short)420)
                : new RemoteFileInfo(Directories.Contains(path), Directories.Contains(path), SymbolicLinks.Contains(path)));
        public Task<byte[]> ReadAsync(string path, int byteLimit, CancellationToken ct) => Task.FromResult(Files[path].ToArray());
        public Task WriteNewAsync(string path, byte[] content, short? permissions, CancellationToken ct)
        {
            if (!Files.TryAdd(path, content.ToArray())) throw new IOException("Already exists");
            if (permissions.HasValue) Permissions[path] = permissions.Value;
            Writes.Add(path);
            return Task.CompletedTask;
        }
        public Task CreateDirectoryAsync(string path, short? permissions, CancellationToken ct)
        { Directories.Add(path); return Task.CompletedTask; }
        public Task MoveAsync(string source, string destination, CancellationToken ct)
        {
            if (!Files.TryGetValue(source, out var content) || Files.ContainsKey(destination)) throw new IOException("Invalid move");
            Files[destination] = content; Files.Remove(source);
            if (Permissions.Remove(source, out var mode)) Permissions[destination] = mode;
            Moves.Add(destination);
            return Task.CompletedTask;
        }
        public Task<RemoteCommandResult> ExecuteAsync(string command, int timeoutSeconds, CancellationToken ct)
        {
            Commands.Add(command);
            if (command.Contains(".Config.Image")) return Task.FromResult(new RemoteCommandResult(ProxyRunning ? ProbeExitCode : 1, true, Image + "\n" + Uid + "\n" + Gid + "\n"));
            if (command.Contains("--force-recreate"))
            {
                ProxyRunning = true;
                return Task.FromResult(new RemoteCommandResult(0, ActivationOutcomeKnown));
            }
            if (!ProxyRunning && (command.Contains("id -u") || command.Contains("id -g")))
                return Task.FromResult(new RemoteCommandResult(1, true));
            return Task.FromResult(new RemoteCommandResult(ValidationExitCode, true));
        }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
