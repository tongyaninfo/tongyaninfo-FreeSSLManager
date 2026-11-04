using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;

namespace SslManager.Tests;

/// <summary>显式自动注册使用内存 CA 和合成账户，验证密钥先保存、注册恢复与普通测试零注册。</summary>
public sealed class AcmeAccountRegistrationTests
{
    [Fact]
    public async Task ExplicitRegistrationPersistsOneKeyBeforeCallingCaAndReturnsReusablePublicDetails()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Ca.BeforeCreate = async thumbprint =>
        {
            var row = await fixture.RowAsync();
            Assert.Equal("Submitting", row.AcmeRegistrationStatus);
            Assert.NotEmpty(row.ProtectedAccessKeySecret);
            var key = fixture.Protector.Unprotect(row.ProtectedAccessKeySecret);
            Assert.Equal(thumbprint, AcmeProtocolClient.Thumbprint(key));
            Assert.DoesNotContain("PRIVATE KEY", row.ProtectedAccessKeySecret);
        };
        var registered = await fixture.Service.RegisterAsync("automatic", true);
        Assert.True(registered.Success, registered.Message);
        Assert.Equal(FakeCa.AccountUrl, registered.Data!.AccountUrl);
        Assert.Equal("Registered", registered.Data.Status);
        Assert.Equal(AcmeProtocolClient.StagingDirectory, registered.Data.DirectoryUrl);
        Assert.Equal(43, registered.Data.PublicKeyThumbprint.Length);
        Assert.NotNull(registered.Data.RegisteredAtUtc);
        Assert.DoesNotContain("PRIVATE KEY", JsonSerializer.Serialize(registered.Data));
        var store = new CloudAccountStore(fixture.Db, fixture.Protection, new GuidIdGenerator());
        var revealed = await store.RevealSecretsAsync("automatic", default);
        Assert.True(revealed.Success, revealed.Message);
        Assert.Equal(FakeCa.AccountUrl, revealed.Data!.AccessKeyId);
        Assert.Equal(registered.Data.PublicKeyThumbprint, AcmeProtocolClient.Thumbprint(revealed.Data.AccessKeySecret));
        Assert.Equal(1, fixture.Ca.CreateCalls);
        Assert.All(fixture.Ca.ValidSignatures, Assert.True);
    }

    [Fact]
    public async Task RepeatedAndConcurrentExplicitRequestsKeepTheSameAccountAndPrivateKey()
    {
        await using var fixture = await Fixture.CreateAsync();
        var first = await fixture.Service.RegisterAsync("automatic", true);
        var protectedKey = (await fixture.RowAsync()).ProtectedAccessKeySecret;
        var repeated = await Task.WhenAll(fixture.Service.RegisterAsync("automatic", true), fixture.Service.RegisterAsync("automatic", true));
        Assert.All(repeated, result => { Assert.True(result.Success, result.Message); Assert.Equal(first.Data, result.Data); });
        Assert.Equal(protectedKey, (await fixture.RowAsync()).ProtectedAccessKeySecret);
        Assert.Equal(1, fixture.Ca.CreateCalls);
        Assert.Equal(0, fixture.Ca.LookupCalls);
    }

    [Fact]
    public async Task LostAcceptedRegistrationIsRecoveredByLookupWithoutCreatingAnotherAccount()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Ca.LoseAcceptedResponse = true;
        var unknown = await fixture.Service.RegisterAsync("automatic", true);
        Assert.Equal("OutcomeUnknown", unknown.Code);
        Assert.Equal("Unknown", unknown.Data!.Status);
        var protectedKey = (await fixture.RowAsync()).ProtectedAccessKeySecret;
        var stored = new CloudAccountStore(fixture.Db, fixture.Protection, new GuidIdGenerator());
        var recoverableKey = await stored.RevealSecretsAsync("automatic", default);
        Assert.True(recoverableKey.Success, recoverableKey.Message);
        Assert.Equal("", recoverableKey.Data!.AccessKeyId);
        Assert.True(AcmeProtocolClient.IsValidAccountKey(recoverableKey.Data.AccessKeySecret));
        Assert.Equal(unknown.Data.PublicKeyThumbprint, AcmeProtocolClient.Thumbprint(recoverableKey.Data.AccessKeySecret));
        fixture.Ca.LoseAcceptedResponse = false;
        var restored = await fixture.Service.RegisterAsync("automatic", true);
        Assert.True(restored.Success, restored.Message);
        Assert.Equal(FakeCa.AccountUrl, restored.Data!.AccountUrl);
        Assert.Equal(protectedKey, (await fixture.RowAsync()).ProtectedAccessKeySecret);
        Assert.Equal(1, fixture.Ca.CreateCalls);
        Assert.Equal(1, fixture.Ca.LookupCalls);
    }

    [Fact]
    public async Task UnknownRegistrationWithoutAccountRemainsLookupOnlyAcrossRepeatedRequests()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Ca.LoseBeforeAcceptance = true;
        Assert.Equal("OutcomeUnknown", (await fixture.Service.RegisterAsync("automatic", true)).Code);
        var protectedKey = (await fixture.RowAsync()).ProtectedAccessKeySecret;
        fixture.Ca.LoseBeforeAcceptance = false;
        Assert.Equal("ACME_REGISTRATION_RESULT_UNKNOWN", (await fixture.Service.RegisterAsync("automatic", true)).Code);
        Assert.Equal("ACME_REGISTRATION_RESULT_UNKNOWN", (await fixture.Service.RegisterAsync("automatic", true)).Code);
        Assert.Equal("Unknown", (await fixture.RowAsync()).AcmeRegistrationStatus);
        Assert.Equal(protectedKey, (await fixture.RowAsync()).ProtectedAccessKeySecret);
        Assert.Equal(1, fixture.Ca.CreateCalls);
        Assert.Equal(2, fixture.Ca.LookupCalls);
    }

    [Fact]
    public async Task KnownRejectionCanBeExplicitlyRetriedUsingTheOriginalPersistedKey()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Ca.RejectFirstCreate = true;
        var rejected = await fixture.Service.RegisterAsync("automatic", true);
        Assert.False(rejected.Success);
        Assert.Equal("Failed", (await fixture.RowAsync()).AcmeRegistrationStatus);
        var original = (await fixture.RowAsync()).ProtectedAccessKeySecret;
        var retried = await fixture.Service.RegisterAsync("automatic", true);
        Assert.True(retried.Success, retried.Message);
        Assert.Equal(original, (await fixture.RowAsync()).ProtectedAccessKeySecret);
        Assert.Single(fixture.Ca.CreateThumbprints.Distinct());
        Assert.Equal(2, fixture.Ca.CreateCalls);
        Assert.Equal(1, fixture.Ca.LookupCalls);
    }

    [Fact]
    public async Task PreparedKeyAfterRestartIsLookedUpBeforeContinuingFirstRegistration()
    {
        await using var fixture = await Fixture.CreateAsync();
        using var preparedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var encrypted = fixture.Protector.Protect(preparedKey.ExportPkcs8PrivateKeyPem());
        await fixture.Db.CloudAccounts.ExecuteUpdateAsync(update => update.SetProperty(x => x.ProtectedAccessKeySecret, encrypted)
            .SetProperty(x => x.AcmeRegistrationStatus, "Prepared"));
        var restored = await fixture.Service.RegisterAsync("automatic", true);
        Assert.True(restored.Success, restored.Message);
        Assert.Equal(1, fixture.Ca.LookupCalls);
        Assert.Equal(encrypted, (await fixture.RowAsync()).ProtectedAccessKeySecret);
        Assert.Equal(1, fixture.Ca.CreateCalls);
    }

    [Fact]
    public async Task DirectoryFailureBeforeDispatchCanBeExplicitlyRetriedWithSameKeyAndOneCreate()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Ca.FailDirectoryOnce = true;
        var failed = await fixture.Service.RegisterAsync("automatic", true);
        Assert.False(failed.Success);
        var prepared = await fixture.RowAsync();
        Assert.Equal("Prepared", prepared.AcmeRegistrationStatus);
        Assert.NotEmpty(prepared.ProtectedAccessKeySecret);
        Assert.Equal(0, fixture.Ca.CreateCalls);
        var retried = await fixture.Service.RegisterAsync("automatic", true);
        Assert.True(retried.Success, retried.Message);
        Assert.Equal(prepared.ProtectedAccessKeySecret, (await fixture.RowAsync()).ProtectedAccessKeySecret);
        Assert.Equal(1, fixture.Ca.CreateCalls);
        Assert.Equal(1, fixture.Ca.LookupCalls);
    }

    [Fact]
    public async Task MissingTermsOrExistingModeCannotGenerateKeysOrRegister()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.Equal("ACME_TERMS_REQUIRED", (await fixture.Service.RegisterAsync("automatic", false)).Code);
        Assert.Equal("", (await fixture.RowAsync()).ProtectedAccessKeySecret);
        await fixture.Db.CloudAccounts.ExecuteUpdateAsync(update => update.SetProperty(x => x.AcmeAccountMode, "Existing"));
        Assert.Equal("ACME_REGISTRATION_NOT_ALLOWED", (await fixture.Service.RegisterAsync("automatic", true)).Code);
        Assert.Equal("", (await fixture.RowAsync()).ProtectedAccessKeySecret);
        Assert.Equal(0, fixture.Ca.TotalRequests);
    }

    [Fact]
    public async Task UnreadableOriginalKeyIsNotReplacedAndOrdinaryTestDoesNotRegister()
    {
        await using var fixture = await Fixture.CreateAsync();
        var corrupted = "synthetic-unreadable-original-key";
        await fixture.Db.CloudAccounts.ExecuteUpdateAsync(update => update.SetProperty(x => x.ProtectedAccessKeySecret, corrupted)
            .SetProperty(x => x.AcmeRegistrationStatus, "Prepared"));
        var rejected = await fixture.Service.RegisterAsync("automatic", true);
        Assert.Equal("ACME_ACCOUNT_KEY_UNREADABLE", rejected.Code);
        Assert.Equal(corrupted, (await fixture.RowAsync()).ProtectedAccessKeySecret);
        Assert.Equal(0, fixture.Ca.TotalRequests);
    }

    [Fact]
    public async Task RegisteredAutomaticAccountCanBeTestedThroughExistingCredentialPathWithoutFurtherRegistration()
    {
        await using var fixture = await Fixture.CreateAsync();
        var registered = await fixture.Service.RegisterAsync("automatic", true);
        Assert.True(registered.Success, registered.Message);
        var store = new CloudAccountStore(fixture.Db, fixture.Protection, new GuidIdGenerator());
        var credentials = await store.GetCredentialsAsync("automatic", default);
        Assert.True(credentials.Success, credentials.Message);
        var signing = new AcmeCloudService(new(fixture.Ca), new CertificateIssuanceStore(fixture.Db, fixture.Protection), fixture.Db, new NeverPropagation());
        var test = await signing.TestAsync(credentials.Data!);
        Assert.True(test.Success, test.Message);
        Assert.Equal(1, fixture.Ca.CreateCalls);
        Assert.Equal(0, fixture.Ca.LookupCalls);
        Assert.Equal(1, fixture.Ca.AccountReadCalls);
    }

    [Fact]
    public async Task ConfigurationUpdateDuringRegistrationCannotReplaceOriginalKeyOrInvalidateItsReceipt()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Ca.BeforeCreate = async _ =>
        {
            fixture.Db.ChangeTracker.Clear();
            var original = await fixture.RowAsync();
            var originalPem = fixture.Protector.Unprotect(original.ProtectedAccessKeySecret);
            var store = new CloudAccountStore(fixture.Db, fixture.Protection, new GuidIdGenerator());
            using var replacement = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var changed = await store.UpdateAsync("automatic", Input(replacement.ExportPkcs8PrivateKeyPem()), default);
            Assert.False(changed.Success);
            Assert.Equal(original.ProtectedAccessKeySecret, (await fixture.RowAsync()).ProtectedAccessKeySecret);
            // 提交中连同一公钥的配置保存也停止，不能让一次外部注册的本地快照发生漂移。
            using var sameKey = ECDsa.Create(); sameKey.ImportFromPem(originalPem);
            var equivalent = await store.UpdateAsync("automatic", Input(sameKey.ExportECPrivateKeyPem()), default);
            Assert.False(equivalent.Success);
            Assert.Equal(original.ProtectedAccessKeySecret, (await fixture.RowAsync()).ProtectedAccessKeySecret);
        };
        var registered = await fixture.Service.RegisterAsync("automatic", true);
        Assert.True(registered.Success, registered.Message);
        Assert.Equal(FakeCa.AccountUrl, registered.Data!.AccountUrl);
        Assert.Equal(1, fixture.Ca.CreateCalls);
        fixture.Db.ChangeTracker.Clear();
        var completed = await fixture.RowAsync();
        var store = new CloudAccountStore(fixture.Db, fixture.Protection, new GuidIdGenerator());
        var equivalentAfterRegistration = await store.UpdateAsync("automatic", Input(fixture.Protector.Unprotect(completed.ProtectedAccessKeySecret)), default);
        Assert.True(equivalentAfterRegistration.Success, equivalentAfterRegistration.Message);
        Assert.Equal(completed.ProtectedAccessKeySecret, (await fixture.RowAsync()).ProtectedAccessKeySecret);
        static CloudAccountInput Input(string pem) => new() { Name = "Synthetic Automatic ACME", Provider = "Acme", AcmeAccountMode = "Automatic",
            Enabled = true, UseForCertificates = true, UseForDns = false, ContactEmail = "synthetic@example.com",
            AcmeDirectoryUrl = AcmeProtocolClient.StagingDirectory, AccessKeySecret = pem };
    }

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, IDataProtectionProvider protection,
        FakeCa ca, AcmeAccountRegistrationService service) : IAsyncDisposable
    {
        public AppDbContext Db => db;
        public IDataProtectionProvider Protection => protection;
        public IDataProtector Protector => protection.CreateProtector("SslManager.CloudAccount.v1", "automatic");
        public FakeCa Ca => ca;
        public AcmeAccountRegistrationService Service => service;
        public Task<CloudAccount> RowAsync() => db.CloudAccounts.AsNoTracking().SingleAsync();
        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            db.CloudAccounts.Add(new() { Id = "automatic", Name = "Synthetic Automatic ACME", Provider = "Acme", AcmeAccountMode = "Automatic",
                AcmeRegistrationStatus = "New", Enabled = true, UseForCertificates = true, UseForDns = false,
                ContactEmail = "synthetic@example.com", AcmeDirectoryUrl = AcmeProtocolClient.StagingDirectory });
            await db.SaveChangesAsync();
            var protection = new EphemeralDataProtectionProvider(); var ca = new FakeCa();
            return new(connection, db, protection, ca, new(db, protection, new(ca)));
        }
        public async ValueTask DisposeAsync() { await db.DisposeAsync(); await connection.DisposeAsync(); }
    }

    private sealed class NeverPropagation : IAcmeDnsPropagationChecker
    { public Task<bool> IsVisibleAsync(IReadOnlyList<DnsChallenge> challenges, CancellationToken ct = default) => throw new NotSupportedException(); }

    private sealed class FakeCa : IHttpClientFactory
    {
        public const string Base = "https://acme-staging-v02.api.letsencrypt.org";
        public const string AccountUrl = Base + "/acme/acct/321";
        public int CreateCalls { get; private set; }
        public int LookupCalls { get; private set; }
        public int AccountReadCalls { get; private set; }
        public int TotalRequests { get; private set; }
        public bool LoseAcceptedResponse { get; set; }
        public bool LoseBeforeAcceptance { get; set; }
        public bool RejectFirstCreate { get; set; }
        public bool FailDirectoryOnce { get; set; }
        public Func<string, Task>? BeforeCreate { get; set; }
        public List<bool> ValidSignatures { get; } = [];
        public List<string> CreateThumbprints { get; } = [];
        private string registeredThumbprint = "";
        private JsonElement registeredJwk;
        public HttpClient CreateClient(string name) => new(new Handler(this));
        private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
        {
            TotalRequests++;
            if (request.Method == HttpMethod.Get)
            {
                if (FailDirectoryOnce) { FailDirectoryOnce = false; return Response(new { type = "urn:ietf:params:acme:error:serverInternal" }, HttpStatusCode.ServiceUnavailable); }
                return Response(new { newNonce = Base + "/nonce", newOrder = Base + "/new-order", newAccount = Base + "/new-account", revokeCert = Base + "/revoke" });
            }
            if (request.Method == HttpMethod.Head) return Response(new { });
            // Boulder 按完整请求头校验 JWS 媒体类型，不能附带 StringContent 默认添加的 charset。
            Assert.Equal("application/jose+json", request.Content?.Headers.ContentType?.ToString());
            using var jws = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            var encodedHeader = jws.RootElement.GetProperty("protected").GetString()!;
            var encodedPayload = jws.RootElement.GetProperty("payload").GetString()!;
            using var header = JsonDocument.Parse(Decode(encodedHeader));
            using var payload = JsonDocument.Parse(encodedPayload == "" ? Encoding.UTF8.GetBytes("{}") : Decode(encodedPayload));
            var path = request.RequestUri!.AbsolutePath;
            var jwk = path == "/new-account" ? header.RootElement.GetProperty("jwk") : registeredJwk;
            Assert.Equal("ES256", header.RootElement.GetProperty("alg").GetString());
            using var key = ECDsa.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = Decode(jwk.GetProperty("x").GetString()!), Y = Decode(jwk.GetProperty("y").GetString()!) } });
            ValidSignatures.Add(key.VerifyData(Encoding.ASCII.GetBytes(encodedHeader + "." + encodedPayload),
                Decode(jws.RootElement.GetProperty("signature").GetString()!), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
            var thumbprint = AcmeProtocolClient.Encode(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new { crv = "P-256", kty = "EC",
                x = jwk.GetProperty("x").GetString(), y = jwk.GetProperty("y").GetString() })));
            if (path == "/new-account")
            {
                Assert.False(header.RootElement.TryGetProperty("kid", out _));
                if (payload.RootElement.TryGetProperty("onlyReturnExisting", out var existing) && existing.GetBoolean())
                {
                    LookupCalls++;
                    return registeredThumbprint == thumbprint ? Response(new { status = "valid" }, location: AccountUrl)
                        : Response(new { type = "urn:ietf:params:acme:error:accountDoesNotExist" }, HttpStatusCode.BadRequest);
                }
                CreateCalls++; CreateThumbprints.Add(thumbprint);
                Assert.True(payload.RootElement.GetProperty("termsOfServiceAgreed").GetBoolean());
                Assert.Equal("mailto:synthetic@example.com", payload.RootElement.GetProperty("contact")[0].GetString());
                if (BeforeCreate is not null) await BeforeCreate(thumbprint);
                if (RejectFirstCreate) { RejectFirstCreate = false; return Response(new { type = "urn:ietf:params:acme:error:malformed" }, HttpStatusCode.BadRequest); }
                if (LoseBeforeAcceptance) throw new HttpRequestException("synthetic registration transport interruption");
                registeredThumbprint = thumbprint; registeredJwk = jwk.Clone();
                if (LoseAcceptedResponse) throw new HttpRequestException("synthetic lost accepted registration response");
                return Response(new { status = "valid" }, HttpStatusCode.Created, AccountUrl);
            }
            if (path == "/acme/acct/321")
            { AccountReadCalls++; Assert.Equal("", encodedPayload); Assert.Equal(AccountUrl, header.RootElement.GetProperty("kid").GetString()); return Response(new { status = "valid" }); }
            throw new InvalidOperationException("Unexpected synthetic registration path.");
        }
        private static HttpResponseMessage Response(object value, HttpStatusCode code = HttpStatusCode.OK, string? location = null)
        {
            var response = new HttpResponseMessage(code) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };
            response.Headers.Add("Replay-Nonce", "synthetic_nonce");
            if (location is not null) response.Headers.Location = new Uri(location);
            return response;
        }
        private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
        private sealed class Handler(FakeCa ca) : HttpMessageHandler
        { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => ca.SendAsync(request); }
    }
}
