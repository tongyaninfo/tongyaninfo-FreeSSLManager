using System.Net;
using System.Text;
using System.Text.Json;
using SslManager.Api.Common;
using SslManager.Api.Models;
using SslManager.Api.Service.impl;

namespace SslManager.Tests;

/// <summary>仅使用内存 HTTP 与合成凭据，覆盖 CF DNS 分页、写入未知与 DNS only 验证边界。</summary>
public sealed class CloudflareProviderTests
{
    private const string ZoneId = "11111111111111111111111111111111";
    private const string RecordId = "22222222222222222222222222222222";

    [Fact]
    public async Task ZonePaginationIsCompleteAndUsesOnlyBearerToken()
    {
        using var fixture = new Fixture(request =>
        {
            var page = request.Uri.Query.Contains("page=2", StringComparison.Ordinal) ? 2 : 1;
            return Page(new[] { new { id = page == 1 ? ZoneId : RecordId, name = page == 1 ? "example.com" : "example.net", status = "active", name_servers = new[] { "ns.example.net" } } }, page, 2, 2);
        });
        var result = await fixture.Service.ListZonesAsync(Account());
        Assert.True(result.Success);
        Assert.Equal(2, result.Data!.Count);
        Assert.Equal("ns.example.net", result.Data[0].NameServers.Single());
        Assert.All(fixture.Factory.Requests, request =>
        {
            Assert.Equal("Bearer synthetic-cf-token", request.Authorization);
            Assert.False(request.HasLegacyAuth);
            Assert.Equal("api.cloudflare.com", request.Uri.Host);
        });
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task UnstableOrDuplicatePageDoesNotReturnPartialSnapshot(bool duplicate)
    {
        using var fixture = new Fixture(request =>
        {
            var page = request.Uri.Query.Contains("page=2", StringComparison.Ordinal) ? 2 : 1;
            return Page(new[] { new { id = duplicate || page == 1 ? ZoneId : RecordId, name = "example.com", status = "active" } }, page, page == 2 && !duplicate ? 3 : 2, 2);
        });
        var result = await fixture.Service.ListZonesAsync(Account());
        Assert.False(result.Success);
        Assert.Equal("CloudPaginationIncomplete", result.Code);
        Assert.Null(result.Data);
    }

    [Fact]
    public async Task DnsOnlyCnameCreationKeepsExactIdentityAndDoesNotUseProxyAsEnabledState()
    {
        using var fixture = new Fixture(request => request.Method == HttpMethod.Post
            ? Envelope(new { id = RecordId, name = "_validation.app.example.com", type = "CNAME", content = "ca.example.net", ttl = 600, proxied = false })
            : Zones());
        var result = await fixture.Service.CreateRecordAsync(Account(), "example.com", new("_validation.app", "CNAME", "ca.example.net"));
        Assert.True(result.Success);
        Assert.Equal(RecordId, result.Data!.Id);
        Assert.Equal("Enabled", result.Data.Status);
        var mutation = fixture.Factory.Requests.Single(request => request.Method == HttpMethod.Post);
        Assert.False(mutation.Body.GetProperty("proxied").GetBoolean());
        Assert.Equal("_validation.app.example.com", mutation.Body.GetProperty("name").GetString());
        var count = fixture.Factory.Requests.Count;
        var disabled = await fixture.Service.SetRecordStatusAsync(Account(), "example.com", RecordId, false);
        Assert.False(disabled.Success);
        Assert.Equal("DNS_STATUS_UNSUPPORTED", disabled.Code);
        Assert.Equal(count, fixture.Factory.Requests.Count);
    }

    [Fact]
    public async Task EditingExistingAddressPreservesItsProxySetting()
    {
        using var fixture = new Fixture(request =>
        {
            if (request.Uri.AbsolutePath.EndsWith("/zones", StringComparison.Ordinal)) return Zones();
            if (request.Method == HttpMethod.Patch) Assert.True(request.Body.GetProperty("proxied").GetBoolean());
            return Envelope(new { id = RecordId, name = "app.example.com", type = "A", content = "192.0.2.42", ttl = 600, proxied = true });
        });
        var result = await fixture.Service.UpdateRecordAsync(Account(), "example.com", RecordId, new("app", "A", "192.0.2.42"));
        Assert.True(result.Success);
        Assert.True(result.Data!.Proxied);
        Assert.Equal("Enabled", result.Data.Status);
        Assert.Single(fixture.Factory.Requests, request => request.Method == HttpMethod.Patch);
    }

    [Fact]
    public async Task ProxiedCnameIsReportedSeparatelyFromEnabledAndTxtContentIsExact()
    {
        using var fixture = new Fixture(request => request.Uri.AbsolutePath.EndsWith("/zones", StringComparison.Ordinal) ? Zones()
            : Page(new object[]
            {
                new { id = RecordId, name = "_validation.app.example.com", type = "CNAME", content = "ca.example.net", ttl = 1, proxied = true },
                new { id = "33333333333333333333333333333333", name = "_acme-challenge.app.example.com", type = "TXT", content = "CaseSensitive+Token=", ttl = 600, proxied = false }
            }, total: 2));
        var result = await fixture.Service.ListRecordsAsync(Account(), "example.com");
        Assert.True(result.Success);
        Assert.True(result.Data![0].Proxied);
        Assert.Equal("Enabled", result.Data[0].Status);
        Assert.Equal("CaseSensitive+Token=", result.Data[1].Value);
        Assert.False(result.Data[1].Proxied);
    }

    [Fact]
    public async Task DnsTxtContentIsPreservedAndRecordDeletionChecksZoneIdentity()
    {
        var mutations = 0;
        using var fixture = new Fixture(request =>
        {
            if (request.Uri.AbsolutePath.EndsWith("/zones", StringComparison.Ordinal)) return Zones();
            if (request.Method == HttpMethod.Delete) { mutations++; return Envelope(new { id = RecordId }); }
            return Envelope(new { id = RecordId, name = "_acme-challenge.outside.example.net", type = "TXT", content = "caseSensitive+Token=", ttl = 1 });
        });
        var deleted = await fixture.Service.DeleteRecordAsync(Account(), "example.com", RecordId);
        Assert.False(deleted.Success);
        Assert.Equal(0, mutations);
    }

    [Fact]
    public async Task SuccessfulMutationWithoutMatchingReceiptRemainsUnknown()
    {
        using var fixture = new Fixture(request => request.Method == HttpMethod.Post
            ? Envelope(new { id = RecordId, name = "_acme-challenge.app.example.com", type = "TXT", content = "wrong-token", ttl = 600 }) : Zones());
        var result = await fixture.Service.CreateRecordAsync(Account(), "example.com", new("_acme-challenge.app", "TXT", "expected-token"));
        Assert.False(result.Success);
        Assert.Equal("OutcomeUnknown", result.Code);
        Assert.Single(fixture.Factory.Requests, request => request.Method == HttpMethod.Post);
    }

    [Fact]
    public async Task TransportFailureAfterWriteNeverRetriesOrExposesPayload()
    {
        using var fixture = new Fixture(request => request.Method == HttpMethod.Post ? throw new HttpRequestException("synthetic-cf-token private response") : Zones());
        var result = await fixture.Service.CreateRecordAsync(Account(), "example.com", new("_acme-challenge.app", "TXT", "secret-validation-value"));
        Assert.Equal("OutcomeUnknown", result.Code);
        Assert.DoesNotContain("synthetic-cf-token", result.Message);
        Assert.DoesNotContain("secret-validation-value", result.Message);
        Assert.Single(fixture.Factory.Requests, request => request.Method == HttpMethod.Post);
    }

    [Fact]
    public async Task CloudErrorOnlyReturnsSanitizedCodesAndAbsolutePathsCannotEscapeFixedHost()
    {
        using var fixture = new Fixture(_ => new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = new StringContent("{\"success\":false,\"errors\":[{\"code\":10000,\"message\":\"synthetic-cf-token PRIVATE KEY\"}]}") });
        var result = await fixture.Api.CallAsync(Account(), HttpMethod.Get, "/zones", null, false, default);
        Assert.Equal("Cloudflare.10000", result.Code);
        Assert.DoesNotContain("synthetic-cf-token", result.Message);
        Assert.DoesNotContain("PRIVATE KEY", result.Message);
        var escape = await fixture.Api.CallAsync(Account(), HttpMethod.Get, "/https://attacker.example/", null, false, default);
        Assert.Equal("InvalidInput", escape.Code);
        Assert.Single(fixture.Factory.Requests);
    }

    private static CloudAccountCredentials Account() => new("cf-account", "Cloudflare 测试", "Cloudflare", "", "synthetic-cf-token", true, false, true, "", "", "");
    private static HttpResponseMessage Zones() => Page(new[] { new { id = ZoneId, name = "example.com", status = "active" } });
    private static HttpResponseMessage Envelope(object result) => Json(new { success = true, result });
    private static HttpResponseMessage Page(object result, int page = 1, int total = 1, int pages = 1)
        => Json(new { success = true, result, result_info = new { page, per_page = 50, total_count = total, total_pages = pages } });
    private static HttpResponseMessage Json(object value) => new(HttpStatusCode.OK) { Content = new StringContent(JsonSerializer.Serialize(value), Encoding.UTF8, "application/json") };

    private sealed record Captured(HttpMethod Method, Uri Uri, JsonElement Body, string Authorization, bool HasLegacyAuth);
    private sealed class FakeFactory(Func<Captured, HttpResponseMessage> respond) : IHttpClientFactory
    {
        public List<Captured> Requests { get; } = [];
        public HttpClient CreateClient(string name) => new(new Handler(this, respond));
        private sealed class Handler(FakeFactory owner, Func<Captured, HttpResponseMessage> respond) : HttpMessageHandler
        {
            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var body = request.Content is null ? "{}" : await request.Content.ReadAsStringAsync(cancellationToken);
                using var document = JsonDocument.Parse(body);
                var captured = new Captured(request.Method, request.RequestUri!, document.RootElement.Clone(), request.Headers.Authorization?.ToString() ?? "",
                    request.Headers.Contains("X-Auth-Key") || request.Headers.Contains("X-Auth-Email") || request.Headers.Contains("X-Auth-User-Service-Key"));
                owner.Requests.Add(captured);
                return respond(captured);
            }
        }
    }

    private sealed class Fixture : IDisposable
    {
        public FakeFactory Factory { get; }
        public CloudflareApiClient Api { get; }
        public CloudflareCloudService Service { get; }
        public Fixture(Func<Captured, HttpResponseMessage> respond)
        {
            Factory = new FakeFactory(respond); Api = new(Factory); Service = new(Api);
        }
        public void Dispose() { }
    }

}
