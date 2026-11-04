using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Deployment;
using SslManager.Api.Service.impl.Deployment.Executors;
using SslManager.Api.Service.impl.Deployment.Transports;

namespace SslManager.Tests;

/// <summary>使用假远程文件系统验证覆盖边界和失败恢复，不连接真实服务器。</summary>
public sealed class RemoteFileDeploymentTests
{
    [Fact]
    public async Task RevokedMcpPermissionStopsNextStageWriteWithoutReplacingOriginalFiles()
    {
        var fixture = new Fixture();
        fixture.Remote.Set("/ssl/fullchain.pem", "old-certificate");
        fixture.Remote.Set("/ssl/private.key", "old-key");
        var original = fixture.Context(await fixture.PlanAsync());
        var guarded = new DeploymentExecutionContext
        {
            TaskId = original.TaskId, Target = original.Target, Material = original.Material, Plan = original.Plan,
            ReportProgressAsync = original.ReportProgressAsync, SaveCheckpointAsync = original.SaveCheckpointAsync,
            BeforeExternalMutationAsync = _ => fixture.Remote.Writes.Count > 0
                ? Task.FromException(new McpExecutionDeniedException("MCP_REVOKED", "模拟暂存首文件后撤销。")) : Task.CompletedTask
        };
        await Assert.ThrowsAsync<McpExecutionDeniedException>(() => fixture.Executor.ExecuteAsync(guarded, default));
        Assert.Single(fixture.Remote.Writes);
        Assert.Empty(fixture.Remote.Moves);
        Assert.Empty(fixture.Remote.Commands);
        Assert.Equal("old-certificate", fixture.Remote.Text("/ssl/fullchain.pem"));
        Assert.Equal("old-key", fixture.Remote.Text("/ssl/private.key"));
    }

    [Fact]
    public async Task ConnectionTestNeverWritesFilesOrRunsCommands()
    {
        var fixture = new Fixture();
        var test = await fixture.Executor.TestAsync(fixture.Target, default);
        Assert.True(test.Success);
        Assert.Empty(fixture.Remote.Writes);
        Assert.Empty(fixture.Remote.Commands);
        Assert.Empty(fixture.Remote.Moves);
        Assert.Contains("未证明目录可写", test.Data!.Message);
    }

    [Fact]
    public async Task DeploymentStagesAllFilesBeforeActivationAndPreservesOriginalBackups()
    {
        var fixture = new Fixture();
        fixture.Remote.Set("/ssl/fullchain.pem", "old-certificate");
        fixture.Remote.Set("/ssl/private.key", "old-key");
        var plan = await fixture.PlanAsync();
        var result = await fixture.Executor.ExecuteAsync(fixture.Context(plan), default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("FilesChecked", result.Data!.VerificationLevel);
        Assert.Equal(fixture.Material.FullChainPem, fixture.Remote.Text("/ssl/fullchain.pem"));
        Assert.Equal(fixture.Material.PrivateKeyPem, fixture.Remote.Text("/ssl/private.key"));
        Assert.Equal("old-certificate", fixture.Remote.Text("/ssl/fullchain.pem.ssl-backup-task-1"));
        Assert.Equal("old-key", fixture.Remote.Text("/ssl/private.key.ssl-backup-task-1"));
        Assert.Equal((short)384, fixture.Remote.Permissions["/ssl/private.key"]);
        var firstMove = fixture.Remote.Operations.FindIndex(operation => operation.StartsWith("move:"));
        var lastWrite = fixture.Remote.Operations.FindLastIndex(operation => operation.StartsWith("write:"));
        Assert.True(firstMove > lastWrite, "完整暂存后才能更换原文件。");
        Assert.DoesNotContain(fixture.Material.PrivateKeyPem, result.Data.ReceiptJson);
    }

    [Fact]
    public async Task SourcePackageBytesUseIndependentDirectoriesAndInspectionChecksEveryFile()
    {
        var fixture = new Fixture();
        var container = new byte[] { 0x30, 0x82, 0x00, 0xff, 0x17, 0x42 };
        var password = Encoding.UTF8.GetBytes("source-password\r\n");
        fixture.UseSourcePackage("tomcat", new("tomcat/server.pfx", "Pfx", container, Convert.ToHexString(SHA256.HashData(container)), true),
            new("tomcat/keystorePass.txt", "Password", password, Convert.ToHexString(SHA256.HashData(password)), true));
        fixture.Target.Configuration.OutputDirectory = "";
        fixture.Target.Configuration.Files = [new("Pfx", "vpn.pfx", "/certificates", "tomcat/server.pfx"),
            new("Password", "vpn-password.txt", "/secrets", "tomcat/keystorePass.txt")];
        fixture.Target.Configuration.PostCommands = [new("systemctl restart anylink")];
        fixture.Remote.Directories.UnionWith(["/certificates", "/secrets"]);
        fixture.Remote.Set("/certificates/vpn.pfx", "old-container");
        var plan = await fixture.PlanAsync();
        Assert.Equal(new[] { "/certificates/vpn.pfx", "/secrets/vpn-password.txt" }, plan.FilePaths);
        Assert.Contains("tomcat/server.pfx", plan.Summary);
        var result = await fixture.Executor.ExecuteAsync(fixture.Context(plan), default);
        Assert.True(result.Success, result.Message);
        Assert.Equal(container, fixture.Remote.Files["/certificates/vpn.pfx"]);
        Assert.Equal(password, fixture.Remote.Files["/secrets/vpn-password.txt"]);
        Assert.Equal((short)384, fixture.Remote.Permissions["/secrets/vpn-password.txt"]);
        Assert.Equal("old-container", fixture.Remote.Text("/certificates/vpn.pfx.ssl-backup-task-1"));
        Assert.Contains("systemctl restart anylink", Assert.Single(fixture.Remote.Commands));
        Assert.DoesNotContain("source-password", result.Data!.ReceiptJson);
        var inspectionContext = new DeploymentInspectionContext(fixture.Target, plan, fixture.Material.Metadata, result.Data.ReceiptJson);
        var inspected = await fixture.Executor.InspectAsync(inspectionContext, default);
        Assert.True(inspected.Success, inspected.Message);
        Assert.True(inspected.Data!.MatchesExpected);
        fixture.Remote.Set("/secrets/vpn-password.txt", "changed-password");
        Assert.False((await fixture.Executor.InspectAsync(inspectionContext, default)).Data!.MatchesExpected);
    }

    [Theory]
    [InlineData("example.com")]
    [InlineData("EXAMPLE.COM.")]
    public async Task RenewedDomainCertificateWritesFrozenSourceBytesToExistingOutputPaths(string configuredDomain)
    {
        var fixture = new Fixture();
        var content = Encoding.UTF8.GetBytes("renewed-container-bytes");
        fixture.UseSourcePackage("tomcat", new CertificateSourceFile("renewed-release/server.pfx", "Pfx", content,
            Convert.ToHexString(SHA256.HashData(content)), true));
        fixture.Target.Configuration.SourceDomain = configuredDomain;
        fixture.Target.Configuration.SourceCertificateId = "previous-certificate-id";
        fixture.Target.Configuration.Files = [new("Pfx", "stable.pfx", "/ssl", "renewed-release/server.pfx")];
        fixture.Target.Configuration.PostCommands = [new("systemctl restart example")];
        fixture.Remote.Set("/ssl/stable.pfx", "old-container");

        var plan = await fixture.PlanAsync();
        var result = await fixture.Executor.ExecuteAsync(fixture.Context(plan), default);

        Assert.True(result.Success, result.Message);
        Assert.Equal(new[] { "/ssl/stable.pfx" }, plan.FilePaths);
        Assert.Equal(content, fixture.Remote.Files["/ssl/stable.pfx"]);
        Assert.Equal("old-container", fixture.Remote.Text("/ssl/stable.pfx.ssl-backup-task-1"));
        Assert.Contains("systemctl restart example", Assert.Single(fixture.Remote.Commands));
        Assert.Equal("FilesChecked", result.Data!.VerificationLevel);
    }

    [Fact]
    public async Task ExplicitDomainMismatchCannotBeBypassedByMatchingLegacyCertificateId()
    {
        var fixture = new Fixture();
        var content = Encoding.UTF8.GetBytes("container");
        fixture.UseSourcePackage("tomcat", new CertificateSourceFile("tomcat/server.pfx", "Pfx", content,
            Convert.ToHexString(SHA256.HashData(content)), true));
        fixture.Target.Configuration.SourceDomain = "other.example.com";
        fixture.Target.Configuration.Files = [new("Pfx", "stable.pfx", "/ssl", "tomcat/server.pfx")];

        var result = await fixture.Executor.PlanAsync(fixture.Target, fixture.Material.Metadata, new("target-1"), default);

        Assert.Equal("SOURCE_CERTIFICATE_MISMATCH", result.Code);
        Assert.Equal(0, fixture.Transport.ConnectCount);
        Assert.Empty(fixture.Remote.Writes);
        Assert.Empty(fixture.Remote.Commands);
    }

    [Fact]
    public async Task ExecutionDoesNotResolveAnotherBasenameAfterSourcePathWasFrozenInPreview()
    {
        var fixture = new Fixture();
        var content = Encoding.UTF8.GetBytes("preview-container");
        fixture.UseSourcePackage("tomcat", new CertificateSourceFile("changed-release/server.pfx", "Pfx", content,
            Convert.ToHexString(SHA256.HashData(content)), true));
        fixture.Target.Configuration.SourceDomain = "example.com";
        fixture.Target.Configuration.Files = [new("Pfx", "stable.pfx", "/ssl", "preview-release/server.pfx")];
        var plan = await fixture.PlanAsync();

        var result = await fixture.Executor.ExecuteAsync(fixture.Context(plan), default);

        Assert.Equal("SOURCE_FILE_UNAVAILABLE", result.Code);
        Assert.Empty(fixture.Remote.Writes);
        Assert.Empty(fixture.Remote.Moves);
        Assert.Empty(fixture.Remote.Commands);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{}")]
    [InlineData("{\"Files\":null}")]
    [InlineData("null")]
    [InlineData("not-json")]
    public async Task FailedUploadWithoutReceiptCanBeInspectedWithoutSystemError(string receipt)
    {
        var fixture = new Fixture();
        var bytes = Encoding.UTF8.GetBytes(fixture.Material.FullChainPem);
        fixture.UseSourcePackage("nginx", new CertificateSourceFile("nginx/cert.crt", "FullChain", bytes, Convert.ToHexString(SHA256.HashData(bytes)), false));
        fixture.Target.Configuration.Files = [new("FullChain", "cert.crt", "/ssl", "nginx/cert.crt")];
        var plan = await fixture.PlanAsync();
        var inspected = await fixture.Executor.InspectAsync(new(fixture.Target, plan, fixture.Material.Metadata, receipt), default);
        Assert.Equal("INSPECTION_UNAVAILABLE", inspected.Code);
        var rollback = await fixture.Executor.RollbackAsync(new(fixture.Target, "task-1", receipt), default);
        Assert.Equal("ROLLBACK_UNAVAILABLE", rollback.Code);
        Assert.Empty(fixture.Remote.Writes);
        Assert.Empty(fixture.Remote.Moves);
    }

    [Fact]
    public async Task MissingSourceFilePreventsAnyUpload()
    {
        var fixture = new Fixture();
        var bytes = Encoding.UTF8.GetBytes(fixture.Material.FullChainPem);
        fixture.UseSourcePackage("nginx", new CertificateSourceFile("nginx/cert.crt", "FullChain", bytes, Convert.ToHexString(SHA256.HashData(bytes)), false));
        fixture.Target.Configuration.Files = [new("FullChain", "cert.crt", "/ssl", "nginx/cert.crt"),
            new("PrivateKey", "key.pem", "/ssl", "nginx/missing.key")];
        var result = await fixture.Executor.ExecuteAsync(fixture.Context(await fixture.PlanAsync()), default);
        Assert.Equal("SOURCE_FILE_UNAVAILABLE", result.Code);
        Assert.Empty(fixture.Remote.Writes);
        Assert.Empty(fixture.Remote.Moves);
        Assert.Empty(fixture.Remote.Commands);
    }

    [Fact]
    public async Task IndependentDirectoriesCannotBypassPathValidationOrCollide()
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.Files = [new("FullChain", "same.pem", "/ssl"), new("PrivateKey", "same.pem", "/ssl")];
        var conflict = await fixture.Executor.PlanAsync(fixture.Target, fixture.Material.Metadata, new("target-1"), default);
        Assert.Equal("CONFIGURATION_INVALID", conflict.Code);
        fixture.Target.Configuration.Files = [new("FullChain", "cert.pem", "/ssl/../etc")];
        Assert.Equal("CONFIGURATION_INVALID", (await fixture.Executor.PlanAsync(fixture.Target, fixture.Material.Metadata, new("target-1"), default)).Code);
        Assert.Empty(fixture.Remote.Writes);
    }

    [Fact]
    public async Task ExternalChangeAfterPlanStopsBeforeAnyUpload()
    {
        var fixture = new Fixture();
        fixture.Remote.Set("/ssl/fullchain.pem", "original");
        var plan = await fixture.PlanAsync();
        fixture.Remote.Set("/ssl/fullchain.pem", "manually-changed");
        var result = await fixture.Executor.ExecuteAsync(fixture.Context(plan), default);
        Assert.Equal("PLAN_STALE", result.Code);
        Assert.Empty(fixture.Remote.Writes);
        Assert.Empty(fixture.Remote.Moves);
        Assert.Equal("manually-changed", fixture.Remote.Text("/ssl/fullchain.pem"));
    }

    [Fact]
    public async Task StageReadbackMismatchDoesNotReplaceOriginalFiles()
    {
        var fixture = new Fixture();
        fixture.Remote.Set("/ssl/fullchain.pem", "original");
        var plan = await fixture.PlanAsync();
        fixture.Remote.CorruptStagedReads = true;
        var result = await fixture.Executor.ExecuteAsync(fixture.Context(plan), default);
        Assert.Equal("FILE_VERIFICATION_FAILED", result.Code);
        Assert.Equal("original", fixture.Remote.Text("/ssl/fullchain.pem"));
        Assert.Empty(fixture.Remote.Moves);
        Assert.Empty(fixture.Remote.Commands);
    }

    [Fact]
    public async Task ConfigurationFailureRestoresOriginalFilesAndDoesNotRunPostCommands()
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.ValidationCommands.Add(new("nginx -t"));
        fixture.Target.Configuration.PostCommands.Add(new("nginx -s reload"));
        fixture.Remote.Set("/ssl/fullchain.pem", "old-certificate");
        fixture.Remote.Set("/ssl/private.key", "old-key");
        fixture.Remote.CommandResults.Enqueue(new(1, true, "DO-NOT-LOG-SECRET"));
        var plan = await fixture.PlanAsync();
        var result = await fixture.Executor.ExecuteAsync(fixture.Context(plan), default);
        Assert.Equal("COMMAND_VALIDATION_FAILED", result.Code);
        Assert.Single(fixture.Remote.Commands);
        Assert.Equal("old-certificate", fixture.Remote.Text("/ssl/fullchain.pem"));
        Assert.Equal("old-key", fixture.Remote.Text("/ssl/private.key"));
        Assert.DoesNotContain("DO-NOT-LOG-SECRET", string.Join('\n', fixture.Progress));
        Assert.NotNull(result.Data);
    }

    [Fact]
    public async Task UnknownPostCommandPreservesReceiptAndIsNeverAutomaticallyRetriedOrRolledBack()
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.PostCommands.Add(new("restart-service"));
        fixture.Target.Configuration.PostCommands.Add(new("second-command"));
        fixture.Remote.Set("/ssl/fullchain.pem", "old-certificate");
        fixture.Remote.CommandResults.Enqueue(new(null, false));
        var plan = await fixture.PlanAsync();
        var result = await fixture.Executor.ExecuteAsync(fixture.Context(plan), default);
        Assert.Equal("REMOTE_RESULT_UNKNOWN", result.Code);
        Assert.Single(fixture.Remote.Commands);
        Assert.Equal(fixture.Material.FullChainPem, fixture.Remote.Text("/ssl/fullchain.pem"));
        Assert.Equal("old-certificate", fixture.Remote.Text("/ssl/fullchain.pem.ssl-backup-task-1"));
        Assert.Contains("ssl-backup-task-1", result.Data!.ReceiptJson);
        Assert.Equal("None", result.Data.VerificationLevel);
        Assert.DoesNotContain(fixture.Remote.Moves, move => move.Destination.Contains("restored"));
    }

    [Fact]
    public async Task SecondFileActivationFailureRetainsAllRecoveryReferencesAndStopsCommands()
    {
        var fixture = new Fixture();
        fixture.Remote.Set("/ssl/fullchain.pem", "old-certificate");
        fixture.Remote.Set("/ssl/private.key", "old-key");
        fixture.Target.Configuration.PostCommands.Add(new("nginx -s reload"));
        var plan = await fixture.PlanAsync();
        fixture.Remote.FailMoveDestination = "/ssl/private.key";
        var result = await fixture.Executor.ExecuteAsync(fixture.Context(plan), default);
        Assert.Equal("REMOTE_RESULT_UNKNOWN", result.Code);
        Assert.Empty(fixture.Remote.Commands);
        var receipt = JsonSerializer.Deserialize<RemoteFileDeploymentService.FileDeploymentReceipt>(result.Data!.ReceiptJson)!;
        Assert.Equal(2, receipt.Files.Count);
        Assert.Equal("old-key", fixture.Remote.Text("/ssl/private.key.ssl-backup-task-1"));
        Assert.Equal(fixture.Material.FullChainPem, fixture.Remote.Text("/ssl/fullchain.pem"));
    }

    [Fact]
    public async Task RollbackCannotOverwriteLaterDeployment()
    {
        var fixture = new Fixture();
        fixture.Remote.Set("/ssl/fullchain.pem", "old-certificate");
        fixture.Remote.Set("/ssl/private.key", "old-key");
        var deployed = await fixture.Executor.ExecuteAsync(fixture.Context(await fixture.PlanAsync()), default);
        Assert.True(deployed.Success);
        var moveCount = fixture.Remote.Moves.Count;
        fixture.Remote.Set("/ssl/fullchain.pem", "later-deployment");
        var rollback = await fixture.Executor.RollbackAsync(new(fixture.Target, "task-1", deployed.Data!.ReceiptJson), default);
        Assert.Equal("PLAN_STALE", rollback.Code);
        Assert.Equal(moveCount, fixture.Remote.Moves.Count);
        Assert.Equal("later-deployment", fixture.Remote.Text("/ssl/fullchain.pem"));
    }

    [Fact]
    public async Task RollbackRestoresOriginalCollectionAndPreservesNewFiles()
    {
        var fixture = new Fixture();
        fixture.Remote.Set("/ssl/fullchain.pem", "old-certificate");
        fixture.Remote.Set("/ssl/private.key", "old-key");
        var deployed = await fixture.Executor.ExecuteAsync(fixture.Context(await fixture.PlanAsync()), default);
        var rollback = await fixture.Executor.RollbackAsync(new(fixture.Target, "task-1", deployed.Data!.ReceiptJson), default);
        Assert.True(rollback.Success, rollback.Message);
        Assert.Equal("old-certificate", fixture.Remote.Text("/ssl/fullchain.pem"));
        Assert.Equal("old-key", fixture.Remote.Text("/ssl/private.key"));
        Assert.Equal(fixture.Material.FullChainPem, fixture.Remote.Text("/ssl/fullchain.pem.ssl-restored-task-1-rollback"));
    }

    [Fact]
    public async Task PfxUsesConfiguredPasswordWithoutExposingItInReceipt()
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.Files = [new("Pfx", "certificate.pfx")];
        fixture.Target.Credentials.PfxPassword = "test-pfx-pass";
        var deployed = await fixture.Executor.ExecuteAsync(fixture.Context(await fixture.PlanAsync()), default);
        Assert.True(deployed.Success, deployed.Message);
        // 这里只导入本测试临时生成的合成密钥；业务核对使用文件哈希，不导入真实私钥。
        using var certificate = X509CertificateLoader.LoadPkcs12(fixture.Remote.Files["/ssl/certificate.pfx"], "test-pfx-pass",
            OperatingSystem.IsMacOS() ? X509KeyStorageFlags.DefaultKeySet : X509KeyStorageFlags.EphemeralKeySet);
        Assert.True(certificate.HasPrivateKey);
        Assert.DoesNotContain("test-pfx-pass", deployed.Data!.ReceiptJson);
    }

    [Theory]
    [InlineData("../private.key")]
    [InlineData("/outside.key")]
    [InlineData("folder/../../private.key")]
    public async Task TraversingOutputIsRejectedBeforeConnecting(string fileName)
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.Files[1] = new("PrivateKey", fileName);
        var plan = await fixture.Executor.PlanAsync(fixture.Target, fixture.Material.Metadata, new("target-1"), default);
        Assert.Equal("CONFIGURATION_INVALID", plan.Code);
        Assert.Equal(0, fixture.Transport.ConnectCount);
    }

    [Fact]
    public async Task WindowsDrivePathsArePreservedAndCommandsUseEncodedPowerShell()
    {
        var fixture = new Fixture();
        fixture.Target.Configuration.OutputDirectory = @"D:\nginx ssl";
        fixture.Target.Configuration.Shell = "PowerShell";
        fixture.Target.Configuration.PostCommands = [new("& 'D:\\nginx\\nginx.exe' -s reload", @"D:\nginx ssl")];
        fixture.Remote.Directories.UnionWith(["D:/", "D:/nginx ssl"]);
        var executor = new WindowsSshDeploymentExecutor(fixture.Service);
        var plan = await executor.PlanAsync(fixture.Target, fixture.Material.Metadata, new("target-1"), default);
        Assert.True(plan.Success, plan.Message);
        var result = await executor.ExecuteAsync(fixture.Context(plan.Data!), default);
        Assert.True(result.Success, result.Message);
        Assert.True(fixture.Remote.Files.ContainsKey("D:/nginx ssl/fullchain.pem"));
        var command = Assert.Single(fixture.Remote.Commands);
        Assert.StartsWith("powershell.exe -NoProfile -NonInteractive -EncodedCommand ", command);
        var decoded = Encoding.Unicode.GetString(Convert.FromBase64String(command.Split(' ').Last()));
        Assert.Contains("Set-Location -LiteralPath 'D:\\nginx ssl'", decoded);
        Assert.Contains("$LASTEXITCODE", decoded);
    }

    [Fact]
    public void HostKeyPinRejectsChangedKeyAndDoesNotAcceptMd5()
    {
        var key = Encoding.ASCII.GetBytes("test-host-public-key");
        var correct = "SHA256:" + Convert.ToBase64String(SHA256.HashData(key)).TrimEnd('=');
        Assert.True(SshRemoteTransport.FingerprintMatches(correct, key));
        Assert.False(SshRemoteTransport.FingerprintMatches(correct, Encoding.ASCII.GetBytes("changed")));
        Assert.False(SshRemoteTransport.FingerprintMatches("MD5:97:70:33:82:fd:29:3a:73:39:af:6a:07:ad:f8:80:49", key));
    }

    private sealed class Fixture
    {
        public FakeRemoteSession Remote { get; } = new();
        public FakeTransport Transport { get; }
        public RemoteFileDeploymentService Service { get; }
        public LinuxSshDeploymentExecutor Executor { get; }
        public DeploymentTargetContext Target { get; }
        public CertificateMaterial Material { get; private set; }
        public List<string> Progress { get; } = [];
        public Fixture()
        {
            Transport = new(Remote); Service = new(Transport); Executor = new(Service);
            Target = new()
            {
                Id = "target-1", Endpoint = "server.example.com", Username = "deployer",
                Configuration = new() { OutputDirectory = "/ssl", HostKeyFingerprint = "SHA256:verified-key",
                    Files = [new("FullChain", "fullchain.pem"), new("PrivateKey", "private.key")] }
            };
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var san = new SubjectAlternativeNameBuilder(); san.AddDnsName("example.com"); request.CertificateExtensions.Add(san.Build());
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30));
            var pem = certificate.ExportCertificatePem();
            var fingerprint = certificate.GetCertHashString(HashAlgorithmName.SHA256);
            Material = new() { Metadata = new("certificate-1", "example.com", ["example.com"], fingerprint, "test-material-digest",
                    certificate.NotBefore.ToUniversalTime(), certificate.NotAfter.ToUniversalTime()),
                CertificatePem = pem, FullChainPem = pem, PrivateKeyPem = key.ExportPkcs8PrivateKeyPem() };
        }
        public async Task<DeploymentTargetPlan> PlanAsync()
        {
            var plan = await Executor.PlanAsync(Target, Material.Metadata, new("target-1"), default);
            Assert.True(plan.Success, plan.Message);
            return plan.Data!;
        }
        public void UseSourcePackage(string format, params CertificateSourceFile[] files)
        {
            Target.Configuration.SourceFormat = format;
            Target.Configuration.SourceCertificateId = Material.Metadata.CertificateId;
            Material = new() { Metadata = Material.Metadata, CertificatePem = Material.CertificatePem,
                FullChainPem = Material.FullChainPem, PrivateKeyPem = Material.PrivateKeyPem, SourcePackages = [new(format, files)] };
        }
        public DeploymentExecutionContext Context(DeploymentTargetPlan plan) => new()
        {
            TaskId = "task-1", Target = Target, Material = Material, Plan = plan,
            ReportProgressAsync = (phase, message, _) => { Progress.Add(phase + ": " + message); return Task.CompletedTask; }
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
        public HashSet<string> Directories { get; } = new(StringComparer.Ordinal) { "/", "/ssl" };
        public List<string> Writes { get; } = [];
        public List<(string Source, string Destination)> Moves { get; } = [];
        public List<string> Commands { get; } = [];
        public List<string> Operations { get; } = [];
        public Queue<RemoteCommandResult> CommandResults { get; } = new();
        public bool CorruptStagedReads { get; set; }
        public string FailMoveDestination { get; set; } = "";
        private static string Key(string value) => RemotePathHelper.ToSftp(value);
        public void Set(string path, string text) => Files[Key(path)] = Encoding.UTF8.GetBytes(text);
        public string Text(string path) => Encoding.UTF8.GetString(Files[Key(path)]);
        public Task<RemoteFileInfo> StatAsync(string path, CancellationToken ct)
        {
            var key = Key(path);
            return Task.FromResult(Files.TryGetValue(key, out var bytes) ? new RemoteFileInfo(true, Length: bytes.Length,
                Permissions: Permissions.GetValueOrDefault(key, (short)420)) : new RemoteFileInfo(Directories.Contains(key), Directories.Contains(key)));
        }
        public Task<byte[]> ReadAsync(string path, int byteLimit, CancellationToken ct)
        {
            if (!Files.TryGetValue(Key(path), out var bytes) || bytes.Length > byteLimit) throw new IOException("Unavailable file");
            return Task.FromResult(CorruptStagedReads && path.Contains(".ssl-stage-") ? Encoding.ASCII.GetBytes("corrupted") : bytes);
        }
        public Task WriteNewAsync(string path, byte[] bytes, short? permissions, CancellationToken ct)
        {
            if (!Files.TryAdd(Key(path), bytes)) throw new IOException("Exists");
            if (permissions.HasValue) Permissions[Key(path)] = permissions.Value;
            Writes.Add(path); Operations.Add("write:" + path); return Task.CompletedTask;
        }
        public Task CreateDirectoryAsync(string path, short? permissions, CancellationToken ct)
        { Directories.Add(Key(path)); return Task.CompletedTask; }
        public Task MoveAsync(string source, string destination, CancellationToken ct)
        {
            if (destination == FailMoveDestination) throw new IOException("Simulated interrupted move");
            var sourceKey = Key(source); var destinationKey = Key(destination);
            if (!Files.TryGetValue(sourceKey, out var bytes) || Files.ContainsKey(destinationKey)) throw new IOException("Move invalid");
            Files[destinationKey] = bytes; Files.Remove(sourceKey);
            if (Permissions.Remove(sourceKey, out var mode)) Permissions[destinationKey] = mode;
            Moves.Add((source, destination)); Operations.Add("move:" + destination);
            return Task.CompletedTask;
        }
        public Task<RemoteCommandResult> ExecuteAsync(string command, int timeoutSeconds, CancellationToken ct)
        { Commands.Add(command); return Task.FromResult(CommandResults.Count > 0 ? CommandResults.Dequeue() : new(0, true)); }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}
