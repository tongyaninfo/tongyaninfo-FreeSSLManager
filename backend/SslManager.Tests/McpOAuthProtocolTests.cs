using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Client;
using Microsoft.IdentityModel.Tokens;
using ModelContextProtocol.Protocol;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service;

namespace SslManager.Tests;

/// <summary>独立 TestServer、内存业务库及合成证书；真实标准框架端到端互通，不触达生产或外部云。</summary>
public sealed class McpOAuthProtocolTests
{
    [Theory]
    [InlineData("2026-07-28")]
    [InlineData("2025-11-25")]
    public async Task ReferenceOAuthTokensWorkWithOfficialSdkAndAreImmediatelyRevocable(string version)
    {
        await using var fixture = await Fixture.CreateAsync();
        var token = await fixture.TokenAsync();
        using var http = fixture.App.GetTestClient(); http.BaseAddress = new("https://ssl.example.com");
        var transport = new HttpClientTransport(new() { Endpoint = new("https://ssl.example.com/mcp"),
            TransportMode = HttpTransportMode.StreamableHttp, AdditionalHeaders = new Dictionary<string, string> { ["Authorization"] = "Bearer " + token } }, http);
        await using var client = await ModelContextProtocol.Client.McpClient.CreateAsync(transport, new() { ProtocolVersion = version });
        var tools = await client.ListToolsAsync(); Assert.Single(tools);
        var result = await client.CallToolAsync("ssl_system_status_get"); Assert.False(result.IsError);
        await using (var scope = fixture.App.Services.CreateAsyncScope())
        {
            var service = scope.ServiceProvider.GetRequiredService<IMcpClientService>();
            Assert.True((await service.RevokeAsync(fixture.Client.Id, default)).Success);
        }
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp"); request.Headers.Authorization = new("Bearer", token);
        request.Content = new StringContent("{}", System.Text.Encoding.UTF8, "application/json");
        using var rejected = await http.SendAsync(request); Assert.Equal(HttpStatusCode.Unauthorized, rejected.StatusCode);
    }

    [Fact]
    public async Task WrongResourceAndWrongClientSecretAreRejectedByOAuth()
    {
        await using var f = await Fixture.CreateAsync();
        using var http = f.App.GetTestClient(); http.BaseAddress = new("https://ssl.example.com");
        var badResource = await http.PostAsync("/oauth/mcp/token", new FormUrlEncodedContent(f.TokenFields("https://other.example.com/mcp")));
        Assert.Equal(HttpStatusCode.BadRequest, badResource.StatusCode);
        var fields = f.TokenFields("https://ssl.example.com/mcp"); fields["client_secret"] = "wrong-synthetic-secret";
        using var wrongSecret = await http.PostAsync("/oauth/mcp/token", new FormUrlEncodedContent(fields));
        Assert.Contains(wrongSecret.StatusCode, new[] { HttpStatusCode.BadRequest, HttpStatusCode.Unauthorized });
        using var error = JsonDocument.Parse(await wrongSecret.Content.ReadAsStringAsync());
        Assert.Equal("invalid_client", error.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task CookieCannotReplaceBearerAndInvalidOriginIsLogged()
    {
        await using var f = await Fixture.CreateAsync();
        using var http = f.App.GetTestClient(); http.BaseAddress = new("https://ssl.example.com");
        using var login = await http.GetAsync("/test/login");
        http.DefaultRequestHeaders.Add("Cookie", login.Headers.GetValues("Set-Cookie").First().Split(';')[0]);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/mcp");
        request.Headers.Add("Origin", "https://attacker.example.com"); request.Content = new StringContent("{}");
        using var rejected = await http.SendAsync(request); Assert.Equal(HttpStatusCode.Forbidden, rejected.StatusCode);
        using var noBearer = await http.PostAsync("/mcp", new StringContent("{}", System.Text.Encoding.UTF8, "application/json")); Assert.Equal(HttpStatusCode.Unauthorized, noBearer.StatusCode);
        await using var scope = f.App.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        Assert.Contains(await db.McpInvocationLogs.ToListAsync(), log => log.Code == "ORIGIN_FORBIDDEN" && log.Status == "Denied");
    }

    [Theory]
    [InlineData("http://ssl.example.com/mcp", "HTTPS_REQUIRED")]
    [InlineData("https://ssl.example.com:8443/mcp", "INVALID_HOST")]
    public async Task InsecureSchemeAndDifferentPublicPortAreRejected(string url, string code)
    {
        await using var f = await Fixture.CreateAsync();
        using var http = f.App.GetTestClient();
        using var response = await http.PostAsync(url, new StringContent("{}", System.Text.Encoding.UTF8, "application/json"));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync()); Assert.Equal(code, json.RootElement.GetProperty("code").GetString());
    }

    [Fact]
    public async Task AnotherLoggedInUserCannotAuthorizeTheBoundAdministratorsClient()
    {
        await using var f = await Fixture.CreateAsync();
        using var http = f.App.GetTestClient(); http.BaseAddress = new("https://ssl.example.com");
        var client = await f.CreatePublicClientAsync();
        using var login = await http.GetAsync("/test/login?user=viewer");
        http.DefaultRequestHeaders.Add("Cookie", login.Headers.GetValues("Set-Cookie").First().Split(';')[0]);
        var path = QueryHelpers.AddQueryString("/oauth/mcp/authorize", new Dictionary<string, string?> { ["client_id"] = client.ClientId,
            ["response_type"] = "code", ["redirect_uri"] = "https://client.example.com/callback", ["scope"] = "mcp.read",
            ["resource"] = "https://ssl.example.com/mcp", ["code_challenge_method"] = "S256", ["code_challenge"] = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32)) });
        using var response = await http.GetAsync(path);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var query = QueryHelpers.ParseQuery(response.Headers.Location!.Query);
        Assert.Equal("access_denied", query["error"].ToString()); Assert.False(query.ContainsKey("code"));
    }

    [Fact]
    public async Task AuthorizationCodeRequiresCsrfConsentAndPkceAndRefreshTokensRotate()
    {
        await using var f = await Fixture.CreateAsync();
        using var http = f.App.GetTestClient(); http.BaseAddress = new("https://ssl.example.com");
        var client = await f.CreatePublicClientAsync();
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var code = await f.AuthorizeCodeAsync(http, client, verifier, verifyCsrf: true);
        var fields = new Dictionary<string, string> { ["grant_type"] = "authorization_code", ["client_id"] = client.ClientId,
            ["code"] = code, ["redirect_uri"] = "https://client.example.com/callback", ["code_verifier"] = verifier, ["resource"] = "https://ssl.example.com/mcp" };
        using var response = await http.PostAsync("/oauth/mcp/token", new FormUrlEncodedContent(fields));
        var body = await response.Content.ReadAsStringAsync(); Assert.True(response.IsSuccessStatusCode, body);
        using var issued = JsonDocument.Parse(body); var refresh = issued.RootElement.GetProperty("refresh_token").GetString()!;
        fields = new() { ["grant_type"] = "refresh_token", ["client_id"] = client.ClientId, ["refresh_token"] = refresh, ["resource"] = "https://ssl.example.com/mcp" };
        using var renewed = await http.PostAsync("/oauth/mcp/token", new FormUrlEncodedContent(fields));
        var renewedBody = await renewed.Content.ReadAsStringAsync(); Assert.True(renewed.IsSuccessStatusCode, renewedBody);
        using var renewal = JsonDocument.Parse(renewedBody); Assert.NotEqual(refresh, renewal.RootElement.GetProperty("refresh_token").GetString());
        using var replayed = await http.PostAsync("/oauth/mcp/token", new FormUrlEncodedContent(fields));
        Assert.Equal(HttpStatusCode.BadRequest, replayed.StatusCode);
    }

    [Fact]
    public async Task AuthorizationCodeRejectsIncorrectPkceVerifier()
    {
        await using var f = await Fixture.CreateAsync();
        using var http = f.App.GetTestClient(); http.BaseAddress = new("https://ssl.example.com");
        var client = await f.CreatePublicClientAsync();
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var code = await f.AuthorizeCodeAsync(http, client, verifier);
        using var rejected = await http.PostAsync("/oauth/mcp/token", new FormUrlEncodedContent(new Dictionary<string, string>
        { ["grant_type"] = "authorization_code", ["client_id"] = client.ClientId, ["code"] = code,
            ["redirect_uri"] = "https://client.example.com/callback", ["code_verifier"] = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32)), ["resource"] = "https://ssl.example.com/mcp" }));
        Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode);
        using var error = JsonDocument.Parse(await rejected.Content.ReadAsStringAsync()); Assert.Equal("invalid_grant", error.RootElement.GetProperty("error").GetString());
    }

    [Fact]
    public async Task IndependentHttpClientPreservesStructuredBusinessFailure()
    {
        await using var f = await Fixture.CreateAsync(); var token = await f.TokenAsync();
        using var http = f.App.GetTestClient();
        using var listed = await RawAsync(http, token, "tools/list", new Dictionary<string, object?>());
        Assert.Single(listed.RootElement.GetProperty("result").GetProperty("tools").EnumerateArray());
        using var called = await RawAsync(http, token, "tools/call", new Dictionary<string, object?> { ["name"] = "ssl_system_status_get", ["arguments"] = new { } });
        Assert.True(called.RootElement.GetProperty("result").GetProperty("structuredContent").GetProperty("success").GetBoolean());
        await using (var scope = f.App.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>(); var settings = await db.McpSettings.SingleAsync();
            settings.AllowedToolsJson = "[]"; settings.ConfigRevision++; await db.SaveChangesAsync();
        }
        using var denied = await RawAsync(http, token, "tools/call", new Dictionary<string, object?> { ["name"] = "ssl_system_status_get", ["arguments"] = new { } });
        var result = denied.RootElement.GetProperty("result"); Assert.True(result.GetProperty("isError").GetBoolean());
        Assert.False(result.GetProperty("structuredContent").GetProperty("success").GetBoolean());
        Assert.Equal("FORBIDDEN", result.GetProperty("structuredContent").GetProperty("code").GetString());
    }

    [Theory]
    [InlineData("unsupported")]
    [InlineData("mismatch")]
    [InlineData("bad-params")]
    [InlineData("unknown-tool")]
    public async Task IndependentHttpClientGetsStandardProtocolErrors(string failure)
    {
        await using var f = await Fixture.CreateAsync(); var token = await f.TokenAsync(); using var http = f.App.GetTestClient();
        var parameters = new Dictionary<string, object?>(); var method = "tools/list";
        var headerVersion = failure == "unsupported" ? "2099-01-01" : "2026-07-28";
        var bodyVersion = failure == "mismatch" ? "2025-11-25" : headerVersion;
        if (failure == "bad-params") { method = "tools/call"; parameters["name"] = 123; parameters["arguments"] = new { }; }
        if (failure == "unknown-tool") { method = "tools/call"; parameters["name"] = "unknown_tool"; parameters["arguments"] = new { }; }
        using var result = await RawAsync(http, token, method, parameters, headerVersion, bodyVersion);
        Assert.True(result.RootElement.TryGetProperty("error", out var error)); Assert.True(error.GetProperty("code").GetInt32() < 0);
        Assert.False(result.RootElement.TryGetProperty("result", out _));
    }

    private static async Task<JsonDocument> RawAsync(HttpClient http, string token, string method, Dictionary<string, object?> parameters,
        string headerVersion = "2026-07-28", string? bodyVersion = null)
    {
        parameters["_meta"] = new Dictionary<string, object> { [MetaKeys.ProtocolVersion] = bodyVersion ?? headerVersion,
            [MetaKeys.ClientInfo] = new { name = "independent-http-test", version = "1.0" }, [MetaKeys.ClientCapabilities] = new { } };
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://ssl.example.com/mcp"); request.Headers.Authorization = new("Bearer", token);
        request.Headers.Add("MCP-Protocol-Version", headerVersion); request.Headers.Add("Mcp-Method", method);
        if (method == "tools/call") request.Headers.Add("Mcp-Name", parameters.TryGetValue("name", out var name) ? name?.ToString() : "");
        request.Headers.Accept.Add(new("application/json")); request.Headers.Accept.Add(new("text/event-stream"));
        request.Content = new StringContent(JsonSerializer.Serialize(new { jsonrpc = "2.0", id = "raw-request", method, @params = parameters }), System.Text.Encoding.UTF8, "application/json");
        using var response = await http.SendAsync(request); var body = await response.Content.ReadAsStringAsync();
        if (response.Content.Headers.ContentType?.MediaType == "text/event-stream")
        { var data = body.Split('\n').Last(line => line.StartsWith("data:", StringComparison.Ordinal)); body = data[5..].Trim(); }
        return JsonDocument.Parse(body);
    }

    private sealed class Fixture(WebApplication app, SqliteConnection connection, McpClientView client, string secret) : IAsyncDisposable
    {
        public WebApplication App => app;
        public McpClientView Client => client;
        public Dictionary<string, string> TokenFields(string resource) => new() { ["grant_type"] = "client_credentials", ["client_id"] = client.ClientId,
            ["client_secret"] = secret, ["scope"] = "mcp.read", ["resource"] = resource };
        public async Task<string> TokenAsync()
        {
            using var http = app.GetTestClient(); http.BaseAddress = new("https://ssl.example.com");
            using var result = await http.PostAsync("/oauth/mcp/token", new FormUrlEncodedContent(TokenFields("https://ssl.example.com/mcp")));
            var body = await result.Content.ReadAsStringAsync(); Assert.True(result.IsSuccessStatusCode, body);
            using var json = JsonDocument.Parse(body); var token = json.RootElement.GetProperty("access_token").GetString()!;
            Assert.DoesNotContain(".", token); return token;
        }
        public async Task<McpClientView> CreatePublicClientAsync()
        {
            await using var scope = app.Services.CreateAsyncScope(); var clients = scope.ServiceProvider.GetRequiredService<IMcpClientService>();
            var result = await clients.CreateAsync(new() { Name = "合成PKCE客户端", BoundUserId = "admin", Scopes = ["mcp.read"],
                RedirectUris = ["https://client.example.com/callback"] }, default);
            Assert.True(result.Success, result.Message); var created = result.Data!.Client;
            Assert.True((await clients.SetStatusAsync(created.Id, new(true, created.ConfigRevision), default)).Success); return created;
        }
        public async Task<string> AuthorizeCodeAsync(HttpClient http, McpClientView client, string verifier, bool verifyCsrf = false)
        {
            using var login = await http.GetAsync("/test/login"); var cookies = new Dictionary<string, string>();
            void CopyCookies(HttpResponseMessage response)
            {
                if (response.Headers.TryGetValues("Set-Cookie", out var headers)) foreach (var header in headers)
                { var value = header.Split(';')[0]; cookies[value.Split('=')[0]] = value; }
                http.DefaultRequestHeaders.Remove("Cookie"); http.DefaultRequestHeaders.Add("Cookie", string.Join("; ", cookies.Values));
            }
            CopyCookies(login);
            var path = QueryHelpers.AddQueryString("/oauth/mcp/authorize", new Dictionary<string, string?> { ["client_id"] = client.ClientId,
                ["response_type"] = "code", ["redirect_uri"] = "https://client.example.com/callback", ["scope"] = "mcp.read offline_access",
                ["resource"] = "https://ssl.example.com/mcp", ["code_challenge_method"] = "S256",
                ["code_challenge"] = Base64UrlEncoder.Encode(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes(verifier))), ["state"] = "synthetic-state" });
            using var page = await http.GetAsync(path); var html = await page.Content.ReadAsStringAsync(); Assert.True(page.IsSuccessStatusCode, html); CopyCookies(page);
            var match = Regex.Match(html, "name=\"__RequestVerificationToken\" value=\"([^\"]+)\""); Assert.True(match.Success);
            var form = Regex.Matches(html, "<input type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]*)\">")
                .ToDictionary(input => WebUtility.HtmlDecode(input.Groups[1].Value), input => WebUtility.HtmlDecode(input.Groups[2].Value));
            form["decision"] = "allow";
            if (verifyCsrf)
            { var invalid = new Dictionary<string, string>(form); invalid.Remove("__RequestVerificationToken"); using var rejected = await http.PostAsync(path, new FormUrlEncodedContent(invalid)); Assert.Equal(HttpStatusCode.BadRequest, rejected.StatusCode); }
            using var approved = await http.PostAsync(path, new FormUrlEncodedContent(form));
            Assert.True(approved.StatusCode == HttpStatusCode.Redirect, await approved.Content.ReadAsStringAsync()); var query = QueryHelpers.ParseQuery(approved.Headers.Location!.Query);
            Assert.True(query.ContainsKey("code"), approved.Headers.Location.ToString()); return query["code"].ToString();
        }
        public static async Task<Fixture> CreateAsync()
        {
            // 合成 PFX 仅供隔离测试，保留临时目录，不生成或覆盖任何生产材料。
            var directory = Path.Combine(Path.GetTempPath(), "mcp-oauth-tests-" + Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
            using var rsa = RSA.Create(2048);
            var request = new CertificateRequest("CN=isolated-mcp-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(3));
            var pem = Path.Combine(directory, "synthetic.crt"); var key = Path.Combine(directory, "synthetic.key");
            await File.WriteAllTextAsync(pem, certificate.ExportCertificatePem()); await File.WriteAllTextAsync(key, rsa.ExportPkcs8PrivateKeyPem());
            // keeper 只保活此夹具的命名内存库，各请求使用独立连接以支持握手通知和审计并发。
            var connectionString = new SqliteConnectionStringBuilder { DataSource = "mcp-oauth-" + Guid.NewGuid().ToString("N"),
                Mode = SqliteOpenMode.Memory, Cache = SqliteCacheMode.Shared, Pooling = false, DefaultTimeout = 5 }.ConnectionString;
            var connection = new SqliteConnection(connectionString); await connection.OpenAsync();
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Development" }); builder.WebHost.UseTestServer();
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["Mcp:OAuth:Issuer"] = "https://ssl.example.com",
                ["Mcp:OAuth:CertificatePemPath"] = pem, ["Mcp:OAuth:PrivateKeyPemPath"] = key, ["AllowedHosts"] = "ssl.example.com" });
            builder.Services.AddSingleton<IIdGenerator, GuidIdGenerator>(); builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlite(connectionString));
            builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider(); builder.Services.AddAntiforgery();
            builder.Services.AddAuthentication("Cookies").AddCookie("Cookies"); builder.Services.AddControllers().AddApplicationPart(typeof(Program).Assembly);
            builder.Services.AddSslManagerMcp(builder.Configuration, false); builder.Services.AddScoped<IMcpToolDispatcher, TestDispatcher>();
            var app = builder.Build();
            app.Use((context, next) => { context.Connection.RemoteIpAddress = IPAddress.Loopback; return next(context); });
            app.UseRouting(); app.UseSslManagerMcpBoundary(); app.UseAuthentication(); app.UseAuthorization(); app.MapControllers(); app.MapSslManagerMcp();
            app.MapGet("/test/login", async (Microsoft.AspNetCore.Http.HttpContext context) =>
            {
                var user = context.Request.Query["user"] == "viewer" ? "viewer" : "admin";
                await context.SignInAsync("Cookies", new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, user),
                    new Claim(ClaimTypes.Name, user), new Claim(ClaimTypes.Role, user == "viewer" ? "viewer" : "admin") }, "Cookies")));
                return Microsoft.AspNetCore.Http.Results.Ok();
            });
            await using var scope = app.Services.CreateAsyncScope(); var db = scope.ServiceProvider.GetRequiredService<AppDbContext>(); await db.Database.EnsureCreatedAsync();
            db.Users.AddRange(new UserAccount { Id = "admin", Username = "admin", NormalizedUsername = "ADMIN", Role = "admin", Enabled = true },
                new UserAccount { Id = "viewer", Username = "viewer", NormalizedUsername = "VIEWER", Role = "viewer", Enabled = true }); await db.SaveChangesAsync();
            var settings = scope.ServiceProvider.GetRequiredService<IMcpConfigurationService>();
            var saved = await settings.SaveAsync(new() { Enabled = true, PublicBaseUrl = "https://ssl.example.com", AllowedCidrs = ["127.0.0.0/8"], AllowedTools = ["ssl_system_status_get"] }, default);
            Assert.True(saved.Success, saved.Message);
            var clients = scope.ServiceProvider.GetRequiredService<IMcpClientService>();
            var created = await clients.CreateAsync(new() { Name = "合成机器客户端", ClientType = "confidential", GrantType = "client_credentials", BoundUserId = "admin", Scopes = ["mcp.read"] }, default);
            Assert.True(created.Success, created.Message);
            var client = created.Data!.Client;
            var enabled = (await clients.SetStatusAsync(client.Id, new(true, client.ConfigRevision), default)).Data!;
            Assert.True((await clients.SaveRulesAsync(client.Id, new([new() { ToolNames = ["ssl_system_status_get"], Scopes = ["mcp.read"], AllowedCidrs = ["127.0.0.0/8"] }], enabled.ConfigRevision), default)).Success);
            await app.StartAsync(); return new(app, connection, client, created.Data.ClientSecret!);
        }
        public async ValueTask DisposeAsync() { await app.StopAsync(); await app.DisposeAsync(); await connection.DisposeAsync(); }
    }
    private sealed class TestDispatcher(IMcpAuthorizationService authorization) : IMcpToolDispatcher
    {
        public IReadOnlyList<McpToolDescriptor> Catalog => McpToolCatalog.All.Where(x => x.Name == "ssl_system_status_get").ToArray();
        public async Task<IReadOnlyList<McpToolDescriptor>> ListAsync(McpCallerContext caller, CancellationToken ct)
        { var allowed = await authorization.AuthorizeAsync(caller, "ssl_system_status_get", null, false, ct); return allowed.Success ? Catalog : []; }
        public async Task<ApiResult<object>> CallAsync(McpCallerContext caller, string toolName, JsonElement arguments, CancellationToken ct)
        { var allowed = await authorization.AuthorizeAsync(caller, toolName, null, false, ct); return allowed.Success ? ApiResult<object>.Ok(new { status = "test" }) : ApiResult<object>.Fail(allowed.Code, allowed.Message); }
    }
}
