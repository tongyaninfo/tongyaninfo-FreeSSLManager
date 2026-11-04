using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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

/// <summary>ACME 使用合成 CA、内存数据库及私钥；验证恢复、JWS 和 DNS 接受顺序，不访问真实云端。</summary>
public sealed class AcmeIssuanceTests
{
    [Fact]
    public async Task IssuanceMaterialIsEncryptedStableAndCannotBeReplacedAfterKeyLoss()
    {
        await using var fixture = await Fixture.CreateAsync();
        var first = await fixture.Store.GetOrCreateAsync("local", "Acme", "test.example.com", "account");
        Assert.True(first.Success);
        var state = await fixture.Db.CertificateIssuanceStates.SingleAsync();
        Assert.DoesNotContain("PRIVATE KEY", state.ProtectedPayload);
        Assert.DoesNotContain(first.Data!.PrivateKeyPem, state.ProtectedPayload);
        var second = await fixture.Store.GetOrCreateAsync("local", "Acme", "test.example.com", "account");
        Assert.Equal(first.Data.PrivateKeyPem, second.Data!.PrivateKeyPem);
        Assert.Equal(first.Data.CsrPem, second.Data.CsrPem);
        Assert.DoesNotContain("PRIVATE KEY", JsonSerializer.Serialize(first.Data));
        var originalCiphertext = state.ProtectedPayload;
        var wrongKeys = new CertificateIssuanceStore(fixture.Db, new EphemeralDataProtectionProvider());
        var failed = await wrongKeys.GetOrCreateAsync("local", "Acme", "test.example.com", "account");
        Assert.Equal("CERTIFICATE_MATERIAL_UNREADABLE", failed.Code);
        Assert.Equal(originalCiphertext, state.ProtectedPayload);
        Assert.Equal("ISSUANCE_IDENTITY_MISMATCH", (await fixture.Store.GetOrCreateAsync("local", "Acme", "other.example.com", "account")).Code);
    }

    [Fact]
    public async Task LostNewOrderResponseDoesNotCreateAnotherOrderOrReplaceThePrivateKey()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Ca.LoseOrderResponse = true;
        var first = await fixture.Service.ApplyAsync(fixture.Account, fixture.Request);
        Assert.Equal("OutcomeUnknown", first.Code);
        var key = (await fixture.Store.GetAsync("local")).Data!.PrivateKeyPem;
        fixture.Ca.LoseOrderResponse = false;
        var repeated = await fixture.Service.ApplyAsync(fixture.Account, fixture.Request);
        Assert.Equal("OutcomeUnknown", repeated.Code);
        Assert.Equal(1, fixture.Ca.OrderSubmissions);
        Assert.Equal(key, (await fixture.Store.GetAsync("local")).Data!.PrivateKeyPem);
        Assert.Equal("OrderSubmitting", (await fixture.Db.CertificateIssuanceStates.SingleAsync()).Stage);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task MalformedOrServerErrorNewOrderResponseIsAlsoUnknownAndNeverResubmitted(bool malformed)
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Ca.MalformedOrderResponse = malformed;
        fixture.Ca.ServerErrorOrderResponse = !malformed;
        var first = await fixture.Service.ApplyAsync(fixture.Account, fixture.Request);
        Assert.Equal("OutcomeUnknown", first.Code);
        var second = await fixture.Service.ApplyAsync(fixture.Account, fixture.Request);
        Assert.Equal("OutcomeUnknown", second.Code);
        Assert.Equal(1, fixture.Ca.OrderSubmissions);
    }

    [Fact]
    public async Task LostFinalizeResponseResumesSameOrderAndCsrWithoutAnotherFinalize()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Propagation.Visible = true;
        var applied = await fixture.Service.ApplyAsync(fixture.Account, fixture.Request);
        Assert.True(applied.Success);
        var reference = applied.Data!.Certificate.Reference;
        await fixture.Service.ContinueApplicationAsync(fixture.Account, reference);
        var material = (await fixture.Store.GetAsync("local")).Data!;
        fixture.Ca.CertificatePem = SelfSigned(material.PrivateKeyPem);
        fixture.Ca.LoseFinalizeResponse = true;
        var lost = await fixture.Service.ContinueApplicationAsync(fixture.Account, reference);
        Assert.Equal("OutcomeUnknown", lost.Code);
        Assert.Equal("FinalizeSubmitting", (await fixture.Db.CertificateIssuanceStates.SingleAsync()).Stage);
        fixture.Ca.LoseFinalizeResponse = false;
        var recovered = await fixture.Service.ContinueApplicationAsync(fixture.Account, reference);
        Assert.True(recovered.Success, recovered.Message);
        Assert.Equal("Issued", recovered.Data!.Certificate.Status);
        Assert.Equal(1, fixture.Ca.OrderSubmissions);
        Assert.Equal(1, fixture.Ca.Finalizations);
        Assert.Equal(material.PrivateKeyPem, (await fixture.Store.GetAsync("local")).Data!.PrivateKeyPem);
        Assert.Equal(material.CsrPem, (await fixture.Store.GetAsync("local")).Data!.CsrPem);
    }

    [Fact]
    public async Task ReadOnlyRefreshNeverAcceptsChallengeAndWorkerWaitsForAuthoritativeDnsBeforeFinalizing()
    {
        await using var fixture = await Fixture.CreateAsync();
        var applied = await fixture.Service.ApplyAsync(fixture.Account, fixture.Request);
        Assert.True(applied.Success, applied.Message);
        var reference = applied.Data!.Certificate.Reference;
        var challenge = Assert.Single(applied.Data.Challenges);
        Assert.Equal("_acme-challenge.test.example.com", challenge.Name);
        Assert.Equal("TXT", challenge.Type);
        Assert.Equal(43, challenge.Value.Length);
        await fixture.Service.GetAsync(fixture.Account, reference);
        Assert.Equal(0, fixture.Ca.ChallengeSubmissions);
        Assert.Equal(0, fixture.Ca.Finalizations);
        var waiting = await fixture.Service.ContinueApplicationAsync(fixture.Account, reference);
        Assert.Equal("ACME_DNS_PROPAGATION_PENDING", waiting.Code);
        Assert.Equal(0, fixture.Ca.ChallengeSubmissions);
        fixture.Propagation.Visible = true;
        var accepted = await fixture.Service.ContinueApplicationAsync(fixture.Account, reference);
        Assert.True(accepted.Success, accepted.Message);
        Assert.Equal(1, fixture.Ca.ChallengeSubmissions);
        Assert.Equal(0, fixture.Ca.Finalizations);
        var material = (await fixture.Store.GetAsync("local")).Data!;
        fixture.Ca.CertificatePem = SelfSigned(material.PrivateKeyPem);
        var issued = await fixture.Service.ContinueApplicationAsync(fixture.Account, reference);
        Assert.True(issued.Success, issued.Message);
        Assert.Equal("Issued", issued.Data!.Certificate.Status);
        Assert.True(issued.Data.Certificate.HasPrivateKey);
        Assert.True(issued.Data.Certificate.IsStaging);
        Assert.Equal(1, fixture.Ca.Finalizations);
        Assert.Equal(material.PrivateKeyPem, (await fixture.Store.GetAsync("local")).Data!.PrivateKeyPem);
        var downloaded = await fixture.Service.DownloadAsync(fixture.Account, reference, "nginx");
        Assert.True(downloaded.Success, downloaded.Message);
        Assert.True(CertificateDownloadHelper.ValidateZip(downloaded.Data!.Content).Success);
        // 同步范围来自本地长期订单，不能因 ACME 无云列表而清空已签发证书。
        var synced = await fixture.Service.ListAsync(fixture.Account);
        Assert.True(synced.Success, synced.Message);
        Assert.Equal(reference.OrderId, Assert.Single(synced.Data!).Reference.OrderId);
        Assert.All(fixture.Ca.VerifiedRequests, Assert.True);
        Assert.Equal(0, fixture.Ca.AccountCreations);
    }

    [Fact]
    public async Task BadNonceIsRetriedWithNewNonceAndValidSignatureWithoutRepeatingAcceptedOrder()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var ca = new FakeCa { RejectNonceOnce = true, ImportedAccountKey = key.ExportPkcs8PrivateKeyPem() };
        var protocol = new AcmeProtocolClient(ca);
        var directory = await protocol.DirectoryAsync(AcmeProtocolClient.StagingDirectory);
        var response = await protocol.PostAsync(directory.Data!, FakeCa.AccountUrl, ca.ImportedAccountKey, FakeCa.AccountUrl, null);
        Assert.True(response.Success, response.Message);
        Assert.Equal(2, ca.AccountRequests);
        Assert.Equal(2, ca.SeenNonces.Distinct().Count());
        Assert.All(ca.VerifiedRequests, Assert.True);
        Assert.Equal(0, ca.OrderSubmissions);
        Assert.Equal(0, ca.AccountCreations);
    }

    [Fact]
    public async Task UnsafeDirectoryAndResourceAreRejectedBeforeAnyHttpRequest()
    {
        var ca = new FakeCa(); var protocol = new AcmeProtocolClient(ca);
        var directory = await protocol.DirectoryAsync("https://attacker.example/directory");
        Assert.Equal("ACME_DIRECTORY_NOT_ALLOWED", directory.Code);
        var injected = new AcmeDirectory(AcmeProtocolClient.StagingDirectory, FakeCa.Base + "/nonce", FakeCa.Base + "/new-order", FakeCa.Base + "/revoke");
        var result = await protocol.PostAsync(injected, "https://attacker.example/order", "unused", null, new { });
        Assert.Equal("ACME_UNSAFE_RESOURCE", result.Code);
        var nonceInjection = injected with { NewNonce = "http://127.0.0.1/private" };
        var blockedNonce = await protocol.PostAsync(nonceInjection, FakeCa.Base + "/order", "unused", null, new { });
        Assert.Equal("ACME_UNSAFE_RESOURCE", blockedNonce.Code);
        Assert.Equal(0, ca.TotalRequests);
    }

    [Fact]
    public async Task ImportedAccountIdentityIsRequiredAndNeverReplacedDuringRecovery()
    {
        await using var fixture = await Fixture.CreateAsync();
        var applied = await fixture.Service.ApplyAsync(fixture.Account, fixture.Request);
        Assert.True(applied.Success);
        var state = await fixture.Db.CertificateIssuanceStates.SingleAsync();
        var originalThumbprint = state.AccountKeyThumbprint;
        var before = fixture.Ca.TotalRequests;
        using var replacement = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var changedKey = await fixture.Service.GetAsync(fixture.Account with { AccessKeySecret = replacement.ExportPkcs8PrivateKeyPem() }, applied.Data!.Certificate.Reference);
        Assert.Equal("ACME_ACCOUNT_IDENTITY_CHANGED", changedKey.Code);
        var changedUrl = await fixture.Service.GetAsync(fixture.Account with { AccessKeyId = FakeCa.Base + "/acme/acct/other" }, applied.Data.Certificate.Reference);
        Assert.Equal("ACME_ACCOUNT_IDENTITY_CHANGED", changedUrl.Code);
        var changedDirectory = await fixture.Service.GetAsync(fixture.Account with { AcmeDirectoryUrl = AcmeProtocolClient.ProductionDirectory }, applied.Data.Certificate.Reference);
        Assert.Equal("ACME_ACCOUNT_IDENTITY_CHANGED", changedDirectory.Code);
        Assert.Equal(originalThumbprint, state.AccountKeyThumbprint);
        Assert.Equal(before, fixture.Ca.TotalRequests);
        using var sameKey = ECDsa.Create(); sameKey.ImportFromPem(fixture.Account.AccessKeySecret);
        var equivalentPem = await fixture.Service.GetAsync(fixture.Account with { AccessKeySecret = sameKey.ExportECPrivateKeyPem() }, applied.Data.Certificate.Reference);
        Assert.True(equivalentPem.Success, equivalentPem.Message);
        Assert.Equal(0, fixture.Ca.AccountCreations);
    }

    [Fact]
    public async Task TestUsesOnlyReadOnlyExistingAccountValidationAndMissingCredentialsNeverRegister()
    {
        await using var fixture = await Fixture.CreateAsync();
        var valid = await fixture.Service.TestAsync(fixture.Account);
        Assert.True(valid.Success, valid.Message);
        Assert.Equal(1, fixture.Ca.AccountRequests);
        Assert.Equal(0, fixture.Ca.OrderSubmissions);
        var missing = await fixture.Service.TestAsync(fixture.Account with { AccessKeySecret = "" });
        Assert.Equal("ACME_ACCOUNT_KEY_INVALID", missing.Code);
        var missingApply = await fixture.Service.ApplyAsync(fixture.Account with { AccessKeySecret = "" }, fixture.Request);
        Assert.Equal("ACME_ACCOUNT_KEY_INVALID", missingApply.Code);
        var emptyList = await fixture.Service.ListAsync(fixture.Account);
        Assert.True(emptyList.Success);
        Assert.Empty(emptyList.Data!);
        Assert.Equal(0, fixture.Ca.AccountCreations);
    }

    [Fact]
    public async Task AccountMaintenancePayloadIsRejectedBeforeAnyHttpRequest()
    {
        var ca = new FakeCa(); var client = new AcmeProtocolClient(ca);
        var directory = new AcmeDirectory(AcmeProtocolClient.StagingDirectory, FakeCa.Base + "/nonce", FakeCa.Base + "/new-order", FakeCa.Base + "/revoke");
        var result = await client.PostAsync(directory, FakeCa.AccountUrl, "unused", FakeCa.AccountUrl,
            new { contact = new[] { "mailto:changed@example.com" } });
        Assert.Equal("ACME_ACCOUNT_READ_ONLY", result.Code);
        Assert.Equal(0, ca.TotalRequests);
    }

    [Theory]
    [InlineData("RSA", 2048, "RS256")]
    [InlineData("RSA", 3072, "RS256")]
    [InlineData("RSA", 4096, "RS256")]
    [InlineData("EC", 256, "ES256")]
    [InlineData("EC", 384, "ES384")]
    public async Task ImportedRsaAndEcAccountKeysProduceValidJwsWithoutNewAccount(string algorithm, int size, string joseAlgorithm)
    {
        string pem;
        if (algorithm == "RSA") { using var rsa = RSA.Create(size); pem = rsa.ExportRSAPrivateKeyPem(); }
        else { using var ec = ECDsa.Create(size == 256 ? ECCurve.NamedCurves.nistP256 : ECCurve.NamedCurves.nistP384); pem = ec.ExportECPrivateKeyPem(); }
        Assert.True(AcmeProtocolClient.IsValidAccountKey(pem));
        Assert.Equal(43, AcmeProtocolClient.Thumbprint(pem).Length);
        var ca = new FakeCa { ImportedAccountKey = pem };
        var client = new AcmeProtocolClient(ca);
        var directory = await client.DirectoryAsync(AcmeProtocolClient.StagingDirectory);
        var response = await client.PostAsync(directory.Data!, FakeCa.AccountUrl, pem, FakeCa.AccountUrl, null);
        Assert.True(response.Success, response.Message);
        Assert.Equal(new[] { joseAlgorithm }, ca.JoseAlgorithms);
        Assert.All(ca.VerifiedRequests, Assert.True);
        Assert.Equal(0, ca.AccountCreations);
    }

    [Fact]
    public void PublicKeysPasswordsAndUnsupportedKeySizesCannotBeUsedAsAccountCredentials()
    {
        using var rsa = RSA.Create(1024); using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP521);
        Assert.False(AcmeProtocolClient.IsValidAccountKey(rsa.ExportRSAPrivateKeyPem()));
        Assert.False(AcmeProtocolClient.IsValidAccountKey(ec.ExportPkcs8PrivateKeyPem()));
        Assert.False(AcmeProtocolClient.IsValidAccountKey(rsa.ExportSubjectPublicKeyInfoPem()));
        Assert.False(AcmeProtocolClient.IsValidAccountKey("synthetic-password-or-api-token"));
    }

    [Fact]
    public async Task ForeignAccountOrMixedCertificateReferenceCannotReadAnOrder()
    {
        await using var fixture = await Fixture.CreateAsync();
        var applied = await fixture.Service.ApplyAsync(fixture.Account, fixture.Request);
        Assert.True(applied.Success);
        var reference = applied.Data!.Certificate.Reference;
        var state = await fixture.Db.CertificateIssuanceStates.SingleAsync(); state.RemoteCertificateId = "expected-certificate";
        await fixture.Db.SaveChangesAsync();
        var before = fixture.Ca.TotalRequests;
        Assert.Equal("NOT_FOUND", (await fixture.Service.GetAsync(fixture.Account with { Id = "foreign-account" }, reference)).Code);
        Assert.Equal("NOT_FOUND", (await fixture.Service.GetAsync(fixture.Account, reference with { CertificateId = "different-certificate" })).Code);
        Assert.Equal(before, fixture.Ca.TotalRequests);
    }

    private static string SelfSigned(string keyPem)
    {
        using var key = RSA.Create(); key.ImportFromPem(keyPem);
        var request = new CertificateRequest("CN=test.example.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var names = new SubjectAlternativeNameBuilder(); names.AddDnsName("test.example.com"); request.CertificateExtensions.Add(names.Build());
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(10));
        return cert.ExportCertificatePem();
    }

    private sealed class Fixture(SqliteConnection connection, AppDbContext db, CertificateIssuanceStore store, FakeCa ca,
        AcmeCloudService service, Propagation propagation, string accountKey) : IAsyncDisposable
    {
        public AppDbContext Db => db;
        public CertificateIssuanceStore Store => store;
        public FakeCa Ca => ca;
        public AcmeCloudService Service => service;
        public Propagation Propagation => propagation;
        public CloudAccountCredentials Account => new("account", "Synthetic ACME", "Acme", FakeCa.AccountUrl, accountKey, true, true, false,
            "", "synthetic@example.com", "", AcmeDirectoryUrl: AcmeProtocolClient.StagingDirectory);
        public CloudCertificateApplyRequest Request => new("test.example.com", "ManagedDns", true, LocalCertificateId: "local");
        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            var protection = new EphemeralDataProtectionProvider(); var store = new CertificateIssuanceStore(db, protection);
            // 合成测试自行准备既有账户材料；产品实现不生成外部账户私钥。
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); var accountKey = key.ExportPkcs8PrivateKeyPem();
            var ca = new FakeCa { ImportedAccountKey = accountKey }; var propagation = new Propagation();
            var service = new AcmeCloudService(new(ca), store, db, propagation);
            return new(connection, db, store, ca, service, propagation, accountKey);
        }
        public async ValueTask DisposeAsync() { await db.DisposeAsync(); await connection.DisposeAsync(); }
    }

    private sealed class Propagation : IAcmeDnsPropagationChecker
    {
        public bool Visible { get; set; }
        public Task<bool> IsVisibleAsync(IReadOnlyList<DnsChallenge> challenges, CancellationToken ct = default)
        { Assert.NotEmpty(challenges); return Task.FromResult(Visible); }
    }

    private sealed class FakeCa : IHttpClientFactory
    {
        public const string Base = "https://acme-staging-v02.api.letsencrypt.org";
        public const string AccountUrl = Base + "/acme/acct/1";
        public string ImportedAccountKey { get; set; } = "";
        public bool LoseOrderResponse { get; set; }
        public bool LoseFinalizeResponse { get; set; }
        public bool MalformedOrderResponse { get; set; }
        public bool ServerErrorOrderResponse { get; set; }
        public bool RejectNonceOnce { get; set; }
        public int TotalRequests { get; private set; }
        public int OrderSubmissions { get; private set; }
        public int AccountRequests { get; private set; }
        public int AccountCreations { get; private set; }
        public int ChallengeSubmissions { get; private set; }
        public int Finalizations { get; private set; }
        public string CertificatePem { get; set; } = "";
        public List<bool> VerifiedRequests { get; } = [];
        public List<string> SeenNonces { get; } = [];
        public List<string> JoseAlgorithms { get; } = [];
        private string status = "pending";
        private int nonce;
        public HttpClient CreateClient(string name) => new(new Handler(this));

        private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
        {
            TotalRequests++;
            var path = request.RequestUri!.AbsolutePath;
            if (request.Method == HttpMethod.Head) return Response(new { }, nonceValue: "nonce_" + ++nonce);
            if (request.Method == HttpMethod.Get) return Response(new { newNonce = Base + "/nonce", newAccount = Base + "/new-account", newOrder = Base + "/new-order", revokeCert = Base + "/revoke" });
            // 与 Boulder 保持相同的完整请求头约束，覆盖签发及 POST-as-GET 的所有签名请求。
            Assert.Equal("application/jose+json", request.Content?.Headers.ContentType?.ToString());
            if (path == "/new-account") { AccountCreations++; throw new InvalidOperationException("产品不得注册或维护外部 ACME 账户。"); }
            using var signed = JsonDocument.Parse(await request.Content!.ReadAsStringAsync());
            var encodedHeader = signed.RootElement.GetProperty("protected").GetString()!;
            var encodedPayload = signed.RootElement.GetProperty("payload").GetString()!;
            using var header = JsonDocument.Parse(Decode(encodedHeader));
            SeenNonces.Add(header.RootElement.GetProperty("nonce").GetString()!);
            Assert.False(header.RootElement.TryGetProperty("jwk", out _));
            Assert.Equal(AccountUrl, header.RootElement.GetProperty("kid").GetString());
            var algorithm = header.RootElement.GetProperty("alg").GetString()!; JoseAlgorithms.Add(algorithm);
            var input = Encoding.ASCII.GetBytes(encodedHeader + "." + encodedPayload);
            var signature = Decode(signed.RootElement.GetProperty("signature").GetString()!);
            bool validSignature;
            if (algorithm == "RS256") { using var rsa = RSA.Create(); rsa.ImportFromPem(ImportedAccountKey); validSignature = rsa.VerifyData(input, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1); }
            else { using var ec = ECDsa.Create(); ec.ImportFromPem(ImportedAccountKey); validSignature = ec.VerifyData(input, signature,
                algorithm == "ES384" ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation); }
            VerifiedRequests.Add(header.RootElement.GetProperty("url").GetString() == request.RequestUri.AbsoluteUri && validSignature);
            using var payload = JsonDocument.Parse(encodedPayload == "" ? Encoding.UTF8.GetBytes("{}") : Decode(encodedPayload));
            if (path == "/acme/acct/1")
            {
                AccountRequests++;
                Assert.Equal("", encodedPayload); // 账户只允许 POST-as-GET，绝不更新账户资料。
                if (RejectNonceOnce) { RejectNonceOnce = false; return Response(new { type = "urn:ietf:params:acme:error:badNonce" }, HttpStatusCode.BadRequest, nonceValue: "nonce_retry"); }
                return Response(new { status = "valid" });
            }
            if (path == "/new-order")
            {
                OrderSubmissions++;
                if (LoseOrderResponse) throw new HttpRequestException("synthetic network interruption");
                if (MalformedOrderResponse) return new(HttpStatusCode.Created) { Content = new StringContent("{malformed") };
                if (ServerErrorOrderResponse) return Response(new { type = "urn:ietf:params:acme:error:serverInternal" }, HttpStatusCode.InternalServerError);
                return Response(Order(), HttpStatusCode.Created, Base + "/order/1");
            }
            if (path == "/order/1") { Assert.Equal("", encodedPayload); return Response(Order()); }
            if (path == "/auth/1")
            {
                Assert.Equal("", encodedPayload);
                return Response(new { identifier = new { type = "dns", value = "test.example.com" }, status = status == "pending" ? "pending" : "valid",
                    challenges = new[] { new { type = "dns-01", url = Base + "/challenge/1", token = "01234567890123456789012345678901", status = "pending" } } });
            }
            if (path == "/challenge/1") { ChallengeSubmissions++; status = "ready"; return Response(new { status = "processing" }); }
            if (path == "/finalize/1")
            {
                Assert.True(payload.RootElement.GetProperty("csr").GetString()!.Length > 100); Finalizations++; status = "valid";
                if (LoseFinalizeResponse) throw new HttpRequestException("synthetic finalize interruption");
                return Response(Order());
            }
            if (path == "/certificate/1") return new(HttpStatusCode.OK) { Content = new StringContent(CertificatePem, Encoding.UTF8, "application/pem-certificate-chain") };
            throw new InvalidOperationException("Unexpected synthetic CA path: " + path);
        }
        private object Order() => new { status, identifiers = new[] { new { type = "dns", value = "test.example.com" } },
            authorizations = new[] { Base + "/auth/1" }, finalize = Base + "/finalize/1", certificate = status == "valid" ? Base + "/certificate/1" : "" };
        private static HttpResponseMessage Response(object value, HttpStatusCode code = HttpStatusCode.OK, string? location = null, string nonceValue = "nonce_response")
        {
            var response = new HttpResponseMessage(code) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };
            response.Headers.Add("Replay-Nonce", nonceValue);
            if (location is not null) response.Headers.Location = new Uri(location);
            return response;
        }
        private static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
        private sealed class Handler(FakeCa ca) : HttpMessageHandler
        { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => ca.SendAsync(request); }
    }
}
