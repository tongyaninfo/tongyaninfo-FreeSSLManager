using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Renci.SshNet.Common;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Deployment;
using SslManager.Api.Service.impl.Deployment.Executors;

namespace SslManager.Tests;

/// <summary>只读浏览、临时连接和已保存凭据复用的边界测试，不连接真实服务器。</summary>
public sealed class RemoteDirectoryBrowsingTests
{
    [Fact]
    public async Task UnsavedConnectionBrowsesMetadataWithoutSavingOrReadingFileContents()
    {
        await using var fixture = await Fixture.CreateAsync();
        var request = Request();
        request.Password = "temporary-password";
        var context = await fixture.Targets.GetBrowseContextAsync(request, default);
        Assert.True(context.Success, context.Message);
        fixture.Transport.Session.Entries.Add(new("private.key", "/ssl/private.key", false, false, true, 1700, DateTime.UtcNow, true));
        var listed = await fixture.Browser.BrowseAsync(context.Data!, "/ssl/", default);
        Assert.True(listed.Success, listed.Message);
        Assert.Equal("/ssl", listed.Data!.Path);
        Assert.Equal("/", listed.Data.ParentPath);
        Assert.Single(listed.Data.Entries);
        Assert.Equal(1000, fixture.Transport.Session.LastLimit);
        Assert.Equal(0, fixture.Transport.Session.ContentOrWriteCalls);
        Assert.Equal(1, fixture.Transport.Session.DisposeCalls);
        Assert.Empty(await fixture.Db.DeploymentTargets.ToListAsync());
        Assert.DoesNotContain("temporary-password", JsonSerializer.Serialize(listed));
        Assert.DoesNotContain("temporary-password", JsonSerializer.Serialize(context));
    }

    [Fact]
    public async Task SavedPasswordIsOnlyReusedForTheSameConnectionAndRevision()
    {
        await using var fixture = await Fixture.CreateAsync();
        var saved = await fixture.SaveAsync();
        var request = ForSaved(saved);
        request.Endpoint = "ssh://linux.example.test:22";
        request.Port = 0;
        var result = await fixture.Targets.GetBrowseContextAsync(request, default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("saved-password", result.Data!.Credentials.Password);
        Assert.Equal(saved.ConfigRevision, (await fixture.Targets.GetAsync(saved.Id, default)).Data!.ConfigRevision);
        Assert.DoesNotContain("saved-password", (await fixture.Db.DeploymentTargets.SingleAsync()).ProtectedCredentials);
    }

    [Theory]
    [InlineData("host")]
    [InlineData("port")]
    [InlineData("username")]
    [InlineData("authentication")]
    [InlineData("fingerprint")]
    public async Task ChangedConnectionCannotReceiveSavedCredentials(string changed)
    {
        await using var fixture = await Fixture.CreateAsync();
        var request = ForSaved(await fixture.SaveAsync());
        switch (changed)
        {
            case "host": request.Endpoint = "another.example.test"; break;
            case "port": request.Port = 2222; break;
            case "username": request.Username = "other-user"; break;
            case "authentication": request.AuthenticationMode = "PrivateKey"; break;
            case "fingerprint": request.HostKeyFingerprint = "SHA256:changed"; break;
        }
        var result = await fixture.Targets.GetBrowseContextAsync(request, default);
        Assert.False(result.Success);
        Assert.Equal("CREDENTIALS_REQUIRED", result.Code);
        Assert.Null(result.Data);
        Assert.Equal(0, fixture.Transport.ConnectCalls);
    }

    [Theory]
    [InlineData(null)]
    [InlineData(99)]
    public async Task MissingOrStaleRevisionPreventsSavedCredentialReuse(int? revision)
    {
        await using var fixture = await Fixture.CreateAsync();
        var request = ForSaved(await fixture.SaveAsync());
        request.ConfigRevision = revision;
        Assert.Equal("CONFLICT", (await fixture.Targets.GetBrowseContextAsync(request, default)).Code);
        Assert.Equal(0, fixture.Transport.ConnectCalls);
    }

    [Fact]
    public async Task ExplicitNewCredentialsCanBrowseEditedConnectionWithoutChangingTheSavedTarget()
    {
        await using var fixture = await Fixture.CreateAsync();
        var saved = await fixture.SaveAsync();
        var request = ForSaved(saved);
        request.Endpoint = "new.example.test";
        request.Password = "new-password";
        var result = await fixture.Targets.GetBrowseContextAsync(request, default);
        Assert.True(result.Success, result.Message);
        Assert.Equal("new-password", result.Data!.Credentials.Password);
        Assert.Equal("new.example.test", result.Data.Endpoint);
        var original = (await fixture.Targets.GetContextAsync(saved.Id, default)).Data!;
        Assert.Equal("linux.example.test", original.Endpoint);
        Assert.Equal("saved-password", original.Credentials.Password);
        Assert.Equal(saved.ConfigRevision, original.ConfigRevision);
    }

    [Fact]
    public async Task PrivateKeyPassphraseIsOnlyReusedWithTheSavedKey()
    {
        await using var fixture = await Fixture.CreateAsync();
        var input = Input();
        input.AuthenticationMode = "PrivateKey";
        input.Password = "";
        input.PrivateKey = "saved-private-key";
        input.PrivateKeyPassphrase = "saved-passphrase";
        var saved = (await fixture.Targets.SaveAsync(null, input, default)).Data!;
        var request = ForSaved(saved);
        request.AuthenticationMode = "PrivateKey";
        var reused = await fixture.Targets.GetBrowseContextAsync(request, default);
        Assert.True(reused.Success, reused.Message);
        Assert.Equal("saved-private-key", reused.Data!.Credentials.PrivateKey);
        Assert.Equal("saved-passphrase", reused.Data.Credentials.PrivateKeyPassphrase);
        request.PrivateKey = "new-private-key";
        var supplied = await fixture.Targets.GetBrowseContextAsync(request, default);
        Assert.True(supplied.Success, supplied.Message);
        Assert.Equal("new-private-key", supplied.Data!.Credentials.PrivateKey);
        Assert.Empty(supplied.Data.Credentials.PrivateKeyPassphrase);
    }

    [Fact]
    public async Task NewConnectionRequiresCredentialsAndDisabledTargetsCannotReuseThem()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.Equal("CREDENTIALS_REQUIRED", (await fixture.Targets.GetBrowseContextAsync(Request(), default)).Code);
        var saved = await fixture.SaveAsync();
        await fixture.Targets.SetStatusAsync(saved.Id, false, default);
        Assert.Equal("FORBIDDEN", (await fixture.Targets.GetBrowseContextAsync(ForSaved(saved), default)).Code);
    }

    [Theory]
    [InlineData("relative/path")]
    [InlineData("/ssl/../etc")]
    [InlineData("/ssl//nested")]
    [InlineData("/ssl\n")]
    public async Task InvalidPathsAreRejectedBeforeConnecting(string path)
    {
        var transport = new FakeTransport();
        var result = await new RemoteDirectoryBrowserService(transport).BrowseAsync(Context(), path, default);
        Assert.False(result.Success);
        Assert.Equal("CONFIGURATION_INVALID", result.Code);
        Assert.Equal(0, transport.ConnectCalls);
    }

    [Theory]
    [InlineData("/ssl", true)]
    [InlineData("/", true)]
    [InlineData("/ssl", false)]
    public async Task SymbolicLinkDirectoriesAndNonDirectoriesAreRejected(string path, bool symbolicLink)
    {
        var transport = new FakeTransport();
        transport.Session.States[path] = new(true, IsDirectory: false, IsSymbolicLink: symbolicLink);
        var result = await new RemoteDirectoryBrowserService(transport).BrowseAsync(Context(), "/ssl", default);
        Assert.False(result.Success);
        Assert.Equal(symbolicLink ? "SYMBOLIC_LINK_UNSUPPORTED" : "PATH_NOT_DIRECTORY", result.Code);
        Assert.Equal(0, transport.Session.ListCalls);
        Assert.Equal(1, transport.Session.DisposeCalls);
    }

    [Fact]
    public async Task MissingDirectoryAndPermissionFailureReturnUsefulErrorsWithoutLeakingRemoteText()
    {
        var transport = new FakeTransport();
        var browser = new RemoteDirectoryBrowserService(transport);
        Assert.Equal("DIRECTORY_NOT_FOUND", (await browser.BrowseAsync(Context(), "/missing", default)).Code);
        transport.Session.ListException = new SftpPermissionDeniedException("DO-NOT-EXPOSE-REMOTE-DETAILS");
        var denied = await browser.BrowseAsync(Context(), "/ssl", default);
        Assert.Equal("PERMISSION_DENIED", denied.Code);
        Assert.DoesNotContain("DO-NOT-EXPOSE", JsonSerializer.Serialize(denied));
        Assert.Equal(0, transport.Session.ContentOrWriteCalls);
    }

    [Theory]
    [InlineData("HOST_IDENTITY_REQUIRED")]
    [InlineData("HOST_IDENTITY_CHANGED")]
    public async Task UntrustedHostReturnsStructuredFingerprintWithoutAListingOrSecrets(string code)
    {
        var transport = new FakeTransport { IdentityFailure = code };
        var result = await new RemoteDirectoryBrowserService(transport).BrowseAsync(Context(), "/ssl", default);
        Assert.False(result.Success);
        Assert.Equal(code, result.Code);
        Assert.Equal("SHA256:observed", result.Data!.ObservedFingerprint);
        Assert.Empty(result.Data.Entries);
        Assert.Equal(0, transport.Session.ListCalls);
        Assert.DoesNotContain("browser-secret", JsonSerializer.Serialize(result));
    }

    [Fact]
    public async Task ListingIsBoundedAndCanShowUnselectableSpecialFiles()
    {
        var transport = new FakeTransport();
        transport.Session.Entries.Add(new("link", "/ssl/link", false, true, false, 0, null, false));
        transport.Session.Entries.Add(new("socket", "/ssl/socket", false, false, false, 0, null, false));
        for (var index = 0; index < 1001; index++)
            transport.Session.Entries.Add(new("file-" + index, "/ssl/file-" + index, false, false, true, 1, null, true));
        var result = await new RemoteDirectoryBrowserService(transport).BrowseAsync(Context(), "/ssl", default);
        Assert.True(result.Success, result.Message);
        Assert.True(result.Data!.Truncated);
        Assert.Equal(1000, result.Data.Entries.Count);
        Assert.False(result.Data.Entries[0].CanSelect);
        Assert.False(result.Data.Entries[1].CanSelect);
        Assert.Equal(0, transport.Session.ContentOrWriteCalls);
    }

    [Fact]
    public async Task CancellationStopsListingAndDisposesTheSession()
    {
        var transport = new FakeTransport();
        transport.Session.WaitForCancellation = true;
        using var cancellation = new CancellationTokenSource();
        cancellation.CancelAfter(TimeSpan.FromMilliseconds(50));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new RemoteDirectoryBrowserService(transport).BrowseAsync(Context(), "/ssl", cancellation.Token));
        Assert.Equal(1, transport.Session.DisposeCalls);
        Assert.Equal(0, transport.Session.ContentOrWriteCalls);
    }

    [Fact]
    public async Task SavedSourceFormatIsNormalizedAndRequiresAnIssuedCertificateAndSourceFiles()
    {
        await using var fixture = await Fixture.CreateAsync();
        var input = Input();
        input.Configuration.SourceFormat = " Nginx ";
        input.Configuration.SourceCertificateId = "source-cert";
        input.Configuration.Files = [new("FullChain", "server.crt", "/ssl", "bundle.crt")];
        Assert.Equal("VALIDATION", (await fixture.Targets.SaveAsync(null, input, default)).Code);
        fixture.Db.Certificates.Add(new() { Id = "source-cert", Domain = "vpn.example.test", Status = "Issued" });
        await fixture.Db.SaveChangesAsync();
        var saved = await fixture.Targets.SaveAsync(null, input, default);
        Assert.True(saved.Success, saved.Message);
        Assert.Equal("nginx", saved.Data!.Configuration.SourceFormat);
        input.Configuration.Files = [new("FullChain", "server.crt", "/ssl")];
        Assert.Equal("VALIDATION", (await fixture.Targets.SaveAsync(null, input, default)).Code);
        input.Configuration.Files = [new("FullChain", "server.crt", "relative", "bundle.crt")];
        Assert.Equal("VALIDATION", (await fixture.Targets.SaveAsync(null, input, default)).Code);
    }

    private static DeploymentTargetInput Input() => new()
    {
        Name = "Linux test", ExecutorKey = "linux.files.ssh.v1", Endpoint = "linux.example.test", Port = 22,
        Username = "root", AuthenticationMode = "Password", Password = "saved-password",
        Configuration = new() { HostKeyFingerprint = "SHA256:saved" }
    };
    private static RemoteBrowseRequest Request() => new()
    {
        Endpoint = "linux.example.test", Port = 22, Username = "root", HostKeyFingerprint = "SHA256:saved", Path = "/ssl"
    };
    private static RemoteBrowseRequest ForSaved(DeploymentTargetView target)
    {
        var request = Request();
        request.TargetId = target.Id;
        request.ConfigRevision = target.ConfigRevision;
        return request;
    }
    private static DeploymentTargetContext Context() => new()
    {
        ExecutorKey = "linux.files.ssh.v1", Endpoint = "linux.example.test", Username = "root",
        AuthenticationMode = "Password", Credentials = new() { Password = "browser-secret" }
    };

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, DeploymentTargetService targets,
        RemoteDirectoryBrowserService browser, FakeTransport transport) : IAsyncDisposable
    {
        public AppDbContext Db => db;
        public DeploymentTargetService Targets => targets;
        public RemoteDirectoryBrowserService Browser => browser;
        public FakeTransport Transport => transport;
        public async Task<DeploymentTargetView> SaveAsync()
        {
            var saved = await targets.SaveAsync(null, Input(), default);
            Assert.True(saved.Success, saved.Message);
            return saved.Data!;
        }
        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            var transport = new FakeTransport();
            var resolver = new DeploymentExecutorResolver([new LinuxSshDeploymentExecutor(new(transport))]);
            return new(connection, db, new(db, resolver, new EphemeralDataProtectionProvider(), new GuidIdGenerator()), new(transport), transport);
        }
        public async ValueTask DisposeAsync() { await db.DisposeAsync(); await connection.DisposeAsync(); }
    }

    private sealed class FakeTransport : IRemoteTransport
    {
        public FakeSession Session { get; } = new();
        public string IdentityFailure { get; set; } = "";
        public int ConnectCalls { get; private set; }
        public Task<ApiResult<IRemoteSession>> ConnectAsync(DeploymentTargetContext target, CancellationToken ct) =>
            Task.FromResult(ApiResult<IRemoteSession>.Ok(Session));
        public Task<ApiResult<RemoteConnectionAttempt>> ConnectWithIdentityAsync(DeploymentTargetContext target, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            ConnectCalls++;
            return Task.FromResult(string.IsNullOrEmpty(IdentityFailure)
                ? ApiResult<RemoteConnectionAttempt>.Ok(new(Session, "SHA256:observed"))
                : new(false, IdentityFailure, "Untrusted host " + target.Credentials.Password,
                    new RemoteConnectionAttempt(ObservedFingerprint: "SHA256:observed")));
        }
    }

    private sealed class FakeSession : IRemoteSession
    {
        public Dictionary<string, RemoteFileInfo> States { get; } = new()
        { ["/"] = new(true, IsDirectory: true), ["/ssl"] = new(true, IsDirectory: true) };
        public List<RemoteDirectoryEntry> Entries { get; } = [];
        public Exception? ListException { get; set; }
        public bool WaitForCancellation { get; set; }
        public int ListCalls { get; private set; }
        public int LastLimit { get; private set; }
        public int ContentOrWriteCalls { get; private set; }
        public int DisposeCalls { get; private set; }
        public Task<RemoteFileInfo> StatAsync(string path, CancellationToken ct) => Task.FromResult(States.GetValueOrDefault(path, new(false)));
        public async Task<RemoteDirectoryListing> ListDirectoryAsync(string path, int limit, CancellationToken ct)
        {
            ListCalls++;
            LastLimit = limit;
            if (WaitForCancellation) await Task.Delay(Timeout.Infinite, ct);
            if (ListException is not null) throw ListException;
            return new(path, RemotePathHelper.Parent(path), Entries.Take(limit).ToArray(), Entries.Count > limit);
        }
        public Task<byte[]> ReadAsync(string path, int byteLimit, CancellationToken ct) { ContentOrWriteCalls++; throw new NotSupportedException(); }
        public Task WriteNewAsync(string path, byte[] content, short? permissions, CancellationToken ct) { ContentOrWriteCalls++; throw new NotSupportedException(); }
        public Task CreateDirectoryAsync(string path, short? permissions, CancellationToken ct) { ContentOrWriteCalls++; throw new NotSupportedException(); }
        public Task MoveAsync(string source, string destination, CancellationToken ct) { ContentOrWriteCalls++; throw new NotSupportedException(); }
        public Task<RemoteCommandResult> ExecuteAsync(string command, int timeoutSeconds, CancellationToken ct) { ContentOrWriteCalls++; throw new NotSupportedException(); }
        public ValueTask DisposeAsync() { DisposeCalls++; return ValueTask.CompletedTask; }
    }
}
