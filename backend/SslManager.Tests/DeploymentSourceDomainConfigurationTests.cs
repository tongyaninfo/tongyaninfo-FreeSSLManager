using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Deployment;

namespace SslManager.Tests;

/// <summary>通过隔离内存数据库验证来源域名保存、旧配置回填及续签后的绑定保留。</summary>
public sealed class DeploymentSourceDomainConfigurationTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task NewTargetStoresNormalizedDomainAndIgnoresAnObsoleteCertificateId()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Db.Certificates.Add(new() { Id = "renewed", Domain = "vpn.example.test", Status = "Issued" });
        await fixture.Db.SaveChangesAsync();
        var input = Input();
        input.Configuration.SourceDomain = " VPN.Example.Test. ";
        input.Configuration.SourceCertificateId = "removed-previous-certificate";

        var result = await fixture.Targets.SaveAsync(null, input, default);

        Assert.True(result.Success, result.Message);
        Assert.Equal("vpn.example.test", result.Data!.Configuration.SourceDomain);
        Assert.Empty(result.Data.Configuration.SourceCertificateId);
        var stored = JsonSerializer.Deserialize<DeploymentTargetConfiguration>((await fixture.Db.DeploymentTargets.SingleAsync()).ConfigurationJson, Json)!;
        Assert.Equal("vpn.example.test", stored.SourceDomain);
        Assert.Empty(stored.SourceCertificateId);
    }

    [Fact]
    public async Task LegacyInputDerivesPrimaryDomainButDoesNotKeepTheCertificateId()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Db.Certificates.Add(new() { Id = "original", Domain = "www.vpn.example.test, VPN.Example.Test.", Status = "Issued" });
        await fixture.Db.SaveChangesAsync();
        var input = Input();
        input.Configuration.SourceCertificateId = "original";

        var result = await fixture.Targets.SaveAsync(null, input, default);

        Assert.True(result.Success, result.Message);
        Assert.Equal("vpn.example.test", result.Data!.Configuration.SourceDomain);
        Assert.Empty(result.Data.Configuration.SourceCertificateId);
    }

    [Fact]
    public async Task BackfillIsIdempotentPreservesProtectedCredentialsAndSurvivesOldCertificateRemoval()
    {
        await using var fixture = await Fixture.CreateAsync();
        var original = new ManagedCertificate { Id = "original", Domain = "VPN.Example.Test.", Status = "Expired" };
        fixture.Db.Certificates.Add(original);
        fixture.Db.Certificates.Add(new() { Id = "renewed", Domain = "vpn.example.test", Status = "Issued" });
        var legacy = Legacy("target", "original");
        var oldUpdatedAt = legacy.UpdatedAtUtc;
        fixture.Db.DeploymentTargets.Add(legacy);
        await fixture.Db.SaveChangesAsync();

        Assert.Equal(1, await fixture.Targets.BackfillSourceDomainsAsync(default));
        var firstConfiguration = legacy.ConfigurationJson;
        var firstUpdatedAt = legacy.UpdatedAtUtc;
        var configuration = JsonSerializer.Deserialize<DeploymentTargetConfiguration>(firstConfiguration, Json)!;
        Assert.Equal("vpn.example.test", configuration.SourceDomain);
        Assert.Empty(configuration.SourceCertificateId);
        Assert.Equal(8, legacy.ConfigRevision);
        Assert.True(firstUpdatedAt > oldUpdatedAt);
        Assert.Equal("existing-protected-credentials", legacy.ProtectedCredentials);
        Assert.Equal("vpn.example.test_bundle.crt", Assert.Single(configuration.Files).FileName);
        Assert.Equal("/ssl", Assert.Single(configuration.Files).Directory);
        Assert.Equal("systemctl reload nginx", Assert.Single(configuration.PostCommands).Command);

        // 仅删除隔离内存数据库中的旧证书，验证已转换绑定不再依赖该记录。
        fixture.Db.Certificates.Remove(original);
        await fixture.Db.SaveChangesAsync();
        Assert.Equal(0, await fixture.Targets.BackfillSourceDomainsAsync(default));
        fixture.Db.ChangeTracker.Clear();
        var stored = await fixture.Db.DeploymentTargets.SingleAsync();
        Assert.Equal(firstConfiguration, stored.ConfigurationJson);
        Assert.Equal(firstUpdatedAt, stored.UpdatedAtUtc);
        Assert.Equal(8, stored.ConfigRevision);
        Assert.Equal("existing-protected-credentials", stored.ProtectedCredentials);
        Assert.Equal("vpn.example.test", (await fixture.Targets.GetAsync(stored.Id, default)).Data!.Configuration.SourceDomain);
    }

    [Fact]
    public async Task BackfillLeavesUnresolvableAndNonSourceTargetsUntouched()
    {
        await using var fixture = await Fixture.CreateAsync();
        var missing = Legacy("missing", "missing-certificate");
        var oldConfiguration = missing.ConfigurationJson;
        var roleOnly = Legacy("role-only", "missing-certificate");
        var roleConfiguration = JsonSerializer.Deserialize<DeploymentTargetConfiguration>(roleOnly.ConfigurationJson, Json)!;
        roleConfiguration.SourceFormat = "";
        roleOnly.ConfigurationJson = JsonSerializer.Serialize(roleConfiguration, Json);
        fixture.Db.DeploymentTargets.AddRange(missing, roleOnly);
        await fixture.Db.SaveChangesAsync();

        Assert.Equal(0, await fixture.Targets.BackfillSourceDomainsAsync(default));

        Assert.Equal(oldConfiguration, missing.ConfigurationJson);
        Assert.Equal(7, missing.ConfigRevision);
        Assert.Equal(7, roleOnly.ConfigRevision);
        Assert.Equal("existing-protected-credentials", missing.ProtectedCredentials);
    }

    [Theory]
    [InlineData("other.example.test")]
    [InlineData("sub.vpn.example.test")]
    [InlineData("*.example.test")]
    [InlineData("https://vpn.example.test")]
    [InlineData("vpn.example.test/path")]
    [InlineData("vpn.example.test,other.example.test")]
    [InlineData("192.0.2.10")]
    public async Task ExplicitDomainMustBeValidAndMatchAnIssuedPrimaryDomain(string domain)
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Db.Certificates.Add(new() { Id = "original", Domain = "vpn.example.test", Status = "Issued" });
        await fixture.Db.SaveChangesAsync();
        var input = Input();
        input.Configuration.SourceDomain = domain;
        input.Configuration.SourceCertificateId = "original";

        var result = await fixture.Targets.SaveAsync(null, input, default);

        Assert.False(result.Success);
        Assert.Equal("VALIDATION", result.Code);
        Assert.Empty(await fixture.Db.DeploymentTargets.ToListAsync());
    }

    private static DeploymentTargetInput Input() => new()
    {
        Name = "Linux domain target", ExecutorKey = "linux.files.ssh.v1", Endpoint = "192.0.2.10", Port = 22,
        Username = "root", AuthenticationMode = "Password", Password = "test-credential",
        Configuration = new()
        {
            SourceFormat = "nginx", Files = [new("FullChain", "server.crt", "/ssl", "source/bundle.crt")]
        }
    };

    private static DeploymentTarget Legacy(string id, string certificateId) => new()
    {
        Id = id, Name = "Legacy target", ExecutorKey = "linux.files.ssh.v1", Endpoint = "192.0.2.10", Port = 22,
        Username = "root", AuthenticationMode = "Password", ProtectedCredentials = "existing-protected-credentials",
        ConfigRevision = 7, UpdatedAtUtc = new(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc),
        ConfigurationJson = JsonSerializer.Serialize(new DeploymentTargetConfiguration
        {
            SourceCertificateId = certificateId, SourceFormat = "nginx",
            Files = [new("FullChain", "vpn.example.test_bundle.crt", "/ssl", "source/bundle.crt")],
            PostCommands = [new("systemctl reload nginx")]
        }, Json)
    };

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, DeploymentTargetService targets) : IAsyncDisposable
    {
        public AppDbContext Db { get; } = db;
        public DeploymentTargetService Targets { get; } = targets;

        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            var resolver = new DeploymentExecutorResolver([new ConfigurationExecutor()]);
            return new(connection, db, new(db, resolver, new EphemeralDataProtectionProvider(), new GuidIdGenerator()));
        }

        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }

    private sealed class ConfigurationExecutor : IDeploymentExecutor
    {
        public DeploymentExecutorDescriptor Descriptor { get; } = new("linux.files.ssh.v1", "Linux", "Linux", "Linux", "SSH",
            AuthenticationModes: ["Password"]);
        public Task<ApiResult<DeploymentConnectionTest>> TestAsync(DeploymentTargetContext target, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<DeploymentTargetPlan>> PlanAsync(DeploymentTargetContext target, CertificateMaterialMetadata material, DeploymentSelection selection, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<DeploymentExecutionResult>> ExecuteAsync(DeploymentExecutionContext context, CancellationToken ct) => throw new NotSupportedException();
        public Task<ApiResult<DeploymentInspection>> InspectAsync(DeploymentInspectionContext context, CancellationToken ct) => throw new NotSupportedException();
    }
}
