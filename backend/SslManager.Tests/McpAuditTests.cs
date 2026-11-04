using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Data;
using SslManager.Api.Models.Mcp;
using SslManager.Api.Service;
using SslManager.Api.Service.impl.Mcp;

namespace SslManager.Tests;

/// <summary>严格白名单及真实内存SQLite账本；没有真实凭据、云端或业务数据库。</summary>
public sealed class McpAuditTests
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    [Fact]
    public void InputRetainsReviewedBusinessFieldsAndDropsFreeTextCredentialsAndMeta()
    {
        var value = JsonSerializer.SerializeToElement(new
        {
            accountId = "account-1", domain = "api.example.test", systemInstanceId = "prod-1", alias = "synthetic-secret-alias",
            idempotencyKey = "synthetic-secret-idempotency", password = "synthetic-secret-password", _meta = new { token = "synthetic-secret-meta" }
        });
        var result = McpAuditPayloads.Input("ssl_certificate_application_prepare", value);
        Assert.Equal("account-1", result.Value.GetProperty("accountId").GetString());
        Assert.Equal("prod-1", result.Value.GetProperty("systemInstanceId").GetString());
        Assert.DoesNotContain("synthetic-secret", result.Value.GetRawText());
        Assert.False(result.Truncated);
    }

    [Fact]
    public void OutputNeverRecordsDnsValuesRawMessagesSnapshotsPathsOrNestedJsonStrings()
    {
        var result = McpAuditPayloads.Output(JsonSerializer.SerializeToElement(new
        {
            success = false, code = "DNS_ERROR", message = "synthetic-secret-exception",
            data = new { items = new[] { new { id = "record-1", type = "TXT", value = "synthetic-secret-txt", status = "Pending",
                rawResponse = "synthetic-secret-response", summaryJson = "{\"token\":\"synthetic-secret-json\"}" } },
                privateKey = "-----BEGIN PRIVATE KEY-----synthetic-secret-pem", storagePath = "/private/synthetic-secret-path" }
        }));
        Assert.Equal("DNS_ERROR", result.Value.GetProperty("code").GetString());
        Assert.Equal("record-1", result.Value.GetProperty("data").GetProperty("items")[0].GetProperty("id").GetString());
        Assert.DoesNotContain("synthetic-secret", result.Value.GetRawText());
        Assert.False(result.Truncated);
    }

    [Fact]
    public void ShortNormalApiResultIsFilteredWithoutBudgetTruncationWarnings()
    {
        var input = McpAuditPayloads.Input("ssl_certificate_application_prepare", JsonSerializer.SerializeToElement(new
        { accountId = "account-1", domain = "api.example.test", alias = "synthetic-secret-alias", secret = "synthetic-secret-input" }));
        var output = McpAuditPayloads.Output(JsonSerializer.SerializeToElement(new
        {
            success = true, code = "OK", message = "操作成功", alias = "synthetic-secret-alias", secret = "synthetic-secret-output",
            data = new { service = "Free SSL Manager", availableTools = 22, systemName = "生产证书中心", systemInstanceId = "prod-instance" }
        }));
        Assert.False(input.Truncated); Assert.False(output.Truncated);
        Assert.DoesNotContain("synthetic-secret", input.Value.GetRawText()); Assert.DoesNotContain("synthetic-secret", output.Value.GetRawText());
        var context = McpAuditPayloads.Normalize(McpAuditPayloads.Write(new(Input: input.Value, Output: output.Value,
            InputCaptured: true, OutputCaptured: true, InputTruncated: input.Truncated, OutputTruncated: output.Truncated,
            Truncated: input.Truncated || output.Truncated)));
        using var parsed = JsonDocument.Parse(context);
        Assert.False(parsed.RootElement.GetProperty("inputTruncated").GetBoolean());
        Assert.False(parsed.RootElement.GetProperty("outputTruncated").GetBoolean());
        Assert.False(parsed.RootElement.GetProperty("truncated").GetBoolean());
    }

    [Fact]
    public void InvalidAndDuplicateFieldsDoNotMasqueradeAsBudgetTruncation()
    {
        using var raw = JsonDocument.Parse("{\"success\":true,\"code\":\"OK\",\"code\":\"DUPLICATE\",\"data\":{\"domain\":\"https://example.test/?token=synthetic-secret\",\"id\":\"invalid/identifier\"}}");
        var output = McpAuditPayloads.Output(raw.RootElement);
        Assert.False(output.Truncated); Assert.Equal("OK", output.Value.GetProperty("code").GetString());
        Assert.Equal(JsonValueKind.Null, output.Value.GetProperty("data").GetProperty("domain").ValueKind);
        Assert.Equal(JsonValueKind.Null, output.Value.GetProperty("data").GetProperty("id").ValueKind);
        Assert.DoesNotContain("synthetic-secret", output.Value.GetRawText());
    }

    [Fact]
    public void ActualByteAndDepthBudgetsStillSetTruncationFlags()
    {
        var input = McpAuditPayloads.Input("ssl_deployment_plan", JsonSerializer.SerializeToElement(new
        { targetIds = Enumerable.Range(0, 100).Select(_ => new string('a', 80)) }));
        Assert.True(input.Truncated); Assert.True(Encoding.UTF8.GetByteCount(input.Value.GetRawText()) <= McpAuditPayloads.MaxInputBytes);
        var output = McpAuditPayloads.Output(JsonSerializer.SerializeToElement(new { data = new { items = Enumerable.Range(0, 100)
            .Select(_ => new { status = new string('a', 100), phase = new string('b', 100), code = new string('c', 100), type = new string('d', 100) }) } }));
        Assert.True(output.Truncated); Assert.True(Encoding.UTF8.GetByteCount(output.Value.GetRawText()) <= McpAuditPayloads.MaxOutputBytes);
        using var deep = JsonDocument.Parse(string.Concat(Enumerable.Repeat("{\"items\":", 16)) + "null" + new string('}', 16));
        Assert.True(McpAuditPayloads.Output(deep.RootElement).Truncated);
    }

    [Fact]
    public void SnapshotsRespectUtf8BudgetAndPersistActualJsonNullSeparatelyFromMissing()
    {
        var input = McpAuditPayloads.Input("ssl_certificates_get", JsonSerializer.SerializeToElement<object?>(null));
        Assert.Equal(JsonValueKind.Null, input.Value.ValueKind);
        var many = Enumerable.Range(0, 500).Select(index => new { id = "id-" + index, status = "Issued", domain = "api.example.test" });
        var output = McpAuditPayloads.Output(JsonSerializer.SerializeToElement(new { data = new { items = many } }));
        Assert.True(Encoding.UTF8.GetByteCount(output.Value.GetRawText()) <= McpAuditPayloads.MaxOutputBytes);
        Assert.True(output.Truncated);
        var context = McpAuditPayloads.Normalize(McpAuditPayloads.Write(new(Input: input.Value, InputCaptured: true, Output: output.Value, OutputCaptured: true)));
        using var parsed = JsonDocument.Parse(context);
        Assert.True(parsed.RootElement.GetProperty("inputCaptured").GetBoolean());
        Assert.Equal(JsonValueKind.Null, parsed.RootElement.GetProperty("input").ValueKind);
        Assert.True(Encoding.UTF8.GetByteCount(context) <= McpAuditPayloads.MaxContextBytes);
    }

    [Fact]
    public async Task Http200BusinessErrorUpdatesOneStartedRowAndPreservesVerifiedKeyIdentity()
    {
        await using var fixture = await Fixture.CreateAsync();
        fixture.Db.McpApiKeys.Add(new() { Id = "key-1", ClientId = "client-1", Name = "受控Agent", Prefix = "sslm_prefix", SecretHash = "synthetic-hash" });
        await fixture.Db.SaveChangesAsync();
        var context = fixture.Context("tools/call", "ssl_certificates_get");
        var middleware = new McpAuditMiddleware(async http =>
        {
            var caller = McpBearerHandler.Caller(http);
            var id = await fixture.Logs.StartAsync(caller, "tools/call", "ssl_certificates_get", "synthetic-secret-request-id", "2025-11-25", default);
            Assert.Equal("Started", (await fixture.Db.McpInvocationLogs.SingleAsync()).Status);
            McpAuditCapture.SetOutput(http, JsonSerializer.SerializeToElement(new { success = false, code = "NOT_FOUND", message = "synthetic-secret-remote" }));
            await fixture.Logs.CompleteAsync(id, false, "NOT_FOUND", false, default);
            await http.Response.WriteAsJsonAsync(new { jsonrpc = "2.0", id = 1, result = new { isError = true } });
        }, NullLogger<McpAuditMiddleware>.Instance);
        await middleware.InvokeAsync(context, fixture.Logs, fixture.Db);
        var row = await fixture.Db.McpInvocationLogs.SingleAsync();
        Assert.Equal("Failed", row.Status); Assert.Equal(200, row.HttpStatus); Assert.Equal("NOT_FOUND", row.Code);
        Assert.Equal("ApiKey", row.AuthenticationType); Assert.Equal("key-1", row.ApiKeyId); Assert.Equal("受控Agent", row.ApiKeyName);
        Assert.DoesNotContain("synthetic-secret", JsonSerializer.Serialize(row, Json));
        using var snapshot = JsonDocument.Parse(row.ContextJson);
        Assert.Equal("生产证书中心", snapshot.RootElement.GetProperty("systemName").GetString());
        Assert.Equal("prod-instance", snapshot.RootElement.GetProperty("instanceId").GetString());
    }

    [Fact]
    public async Task InitializeAndProtocolErrorAreAuditedWithoutToolHandler()
    {
        await using var fixture = await Fixture.CreateAsync();
        var context = fixture.Context("initialize");
        var middleware = new McpAuditMiddleware(http => http.Response.WriteAsJsonAsync(new
        { jsonrpc = "2.0", id = 1, result = new { protocolVersion = "2025-11-25", serverInfo = new { name = "ssl", secret = "synthetic-secret" } } }), NullLogger<McpAuditMiddleware>.Instance);
        await middleware.InvokeAsync(context, fixture.Logs, fixture.Db);
        var row = await fixture.Db.McpInvocationLogs.SingleAsync();
        Assert.Equal("initialize", row.Method); Assert.Equal("Succeeded", row.Status); Assert.Equal(200, row.HttpStatus);
        Assert.Contains("test-agent", row.ContextJson); Assert.DoesNotContain("synthetic-secret", row.ContextJson);
        var context2 = fixture.Context("ping");
        var failure = new McpAuditMiddleware(http => http.Response.WriteAsJsonAsync(new
        { jsonrpc = "2.0", id = 1, error = new { code = -32602, message = "synthetic-secret", data = new { stack = "synthetic-secret" } } }), NullLogger<McpAuditMiddleware>.Instance);
        await failure.InvokeAsync(context2, fixture.Logs, fixture.Db);
        var failed = await fixture.Db.McpInvocationLogs.SingleAsync(x => x.Method == "ping");
        Assert.Equal("Failed", failed.Status); Assert.Equal("RPC_-32602", failed.Code); Assert.Equal(200, failed.HttpStatus);
        Assert.DoesNotContain("synthetic-secret", failed.ContextJson);
    }

    [Fact]
    public async Task UnauthenticatedFailuresRemainBoundedMinuteAggregates()
    {
        await using var fixture = await Fixture.CreateAsync();
        var middleware = new McpAuditMiddleware(http => { http.Response.StatusCode = 401; return Task.CompletedTask; }, NullLogger<McpAuditMiddleware>.Instance);
        for (var i = 0; i < 3; i++)
        {
            var context = fixture.Context("initialize"); context.User = new ClaimsPrincipal();
            await middleware.InvokeAsync(context, fixture.Logs, fixture.Db);
        }
        var row = await fixture.Db.McpInvocationLogs.SingleAsync();
        Assert.Equal("Denied", row.Status); Assert.Equal(3, row.OccurrenceCount);
    }

    [Fact]
    public async Task CancelledHttpRequestKeepsCancelledResultAnd2026MetadataStaysWhitelisted()
    {
        await using var fixture = await Fixture.CreateAsync();
        var context = fixture.Context("server/discover");
        context.Request.Headers.UserAgent = "test-agent/2.0";
        context.Request.Body = new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(new { jsonrpc = "2.0", id = 1, method = "server/discover",
            @params = new { _meta = new Dictionary<string, object> {
                ["io.modelcontextprotocol/clientInfo"] = new { name = "agent-2026", version = "2.0", secret = "synthetic-secret" },
                ["io.modelcontextprotocol/protocolVersion"] = "2026-07-28", ["authorization"] = "synthetic-secret" } } }));
        using var source = new CancellationTokenSource(); source.Cancel(); context.RequestAborted = source.Token;
        var middleware = new McpAuditMiddleware(_ => throw new OperationCanceledException(source.Token), NullLogger<McpAuditMiddleware>.Instance);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => middleware.InvokeAsync(context, fixture.Logs, fixture.Db));
        var row = await fixture.Db.McpInvocationLogs.SingleAsync();
        Assert.Equal("Cancelled", row.Status); Assert.Equal(499, row.HttpStatus); Assert.Equal("server/discover", row.Method);
        Assert.Equal("2026-07-28", row.ProtocolVersion);
        Assert.Contains("agent-2026", row.ContextJson); Assert.Contains("test-agent/2.0", row.ContextJson);
        Assert.DoesNotContain("synthetic-secret", row.ContextJson);
    }

    [Fact]
    public async Task StatisticsCountAggregatedDenialsAndSeparateToolsFromHandshakeAndFilterAtDatabase()
    {
        await using var fixture = await Fixture.CreateAsync();
        var now = DateTime.UtcNow;
        var empty = await fixture.Logs.StatisticsAsync(null, null, default);
        Assert.True(empty.Success); Assert.Equal(0, empty.Data!.TotalRequests); Assert.Null(empty.Data.AverageDurationMilliseconds); Assert.Empty(empty.Data.Trend);
        fixture.Db.McpInvocationLogs.AddRange(
            new() { Id = "success", Method = "tools/call", Status = "Succeeded", StartedAtUtc = now, FinishedAtUtc = now, DurationMilliseconds = 20, ApiKeyId = "key-1", HttpStatus = 200, AuthenticationType = "ApiKey" },
            new() { Id = "failed", Method = "tools/call", Status = "Failed", StartedAtUtc = now, FinishedAtUtc = now, DurationMilliseconds = 40, HttpStatus = 200 },
            new() { Id = "handshake", Method = "initialize", Status = "Succeeded", StartedAtUtc = now, FinishedAtUtc = now },
            new() { Id = "denials", Status = "Denied", StartedAtUtc = now, OccurrenceCount = 7 });
        await fixture.Db.SaveChangesAsync();
        var result = await fixture.Logs.StatisticsAsync(now.AddHours(-1), now.AddHours(1), default);
        Assert.True(result.Success, result.Message); Assert.Equal(10, result.Data!.TotalRequests); Assert.Equal(2, result.Data.ToolCalls);
        Assert.Equal(2, result.Data.Succeeded); Assert.Equal(1, result.Data.Failed); Assert.Equal(7, result.Data.Denied);
        Assert.Equal(30, result.Data.AverageDurationMilliseconds); Assert.Equal(10, Assert.Single(result.Data.Trend).Requests);
        var list = await fixture.Logs.ListAsync(new(ApiKeyId: "key-1", Method: "tools/call", HttpStatus: 200, AuthenticationType: "ApiKey"), default);
        Assert.True(list.Success); Assert.Equal("success", Assert.Single(list.Data!.Items).Id);
        Assert.False((await fixture.Logs.StatisticsAsync(now.AddDays(-91), now, default)).Success);
        Assert.False((await fixture.Logs.StatisticsAsync(null, DateTime.MinValue, default)).Success);
    }

    private sealed class Fixture(SqliteConnection connection, ServiceProvider provider, AppDbContext db, IHttpContextAccessor accessor) : IAsyncDisposable
    {
        public AppDbContext Db => db;
        public IMcpInvocationLogService Logs { get; } = new McpInvocationLogService(db, new TestIds(), accessor);
        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:"); await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            db.McpSettings.Add(new() { SystemName = "生产证书中心", InstanceId = "prod-instance" }); await db.SaveChangesAsync();
            var services = new ServiceCollection(); services.AddSingleton(db); services.AddSingleton<IIdGenerator, TestIds>(); services.AddHttpContextAccessor();
            var provider = services.BuildServiceProvider();
            return new(connection, provider, db, provider.GetRequiredService<IHttpContextAccessor>());
        }
        public DefaultHttpContext Context(string method, string? tool = null)
        {
            var context = new DefaultHttpContext { RequestServices = provider };
            context.Request.Path = "/mcp"; context.Request.Method = "POST"; context.Connection.RemoteIpAddress = IPAddress.Loopback;
            context.Request.Body = new MemoryStream(JsonSerializer.SerializeToUtf8Bytes(new { jsonrpc = "2.0", id = 1, method,
                @params = new { name = tool, arguments = new { certificateId = "cert-1" }, protocolVersion = "2025-11-25", clientInfo = new { name = "test-agent", version = "1.0" } } }));
            context.Response.Body = new MemoryStream();
            context.User = new(new ClaimsIdentity([new("mcp_client", "client-1"), new("sub", "user-1"),
                new("mcp_authentication_type", "ApiKey"), new("mcp_api_key_id", "key-1")], "McpBearer"));
            accessor.HttpContext = context; return context;
        }
        public async ValueTask DisposeAsync() { await db.DisposeAsync(); await provider.DisposeAsync(); await connection.DisposeAsync(); }
    }
    private sealed class TestIds : IIdGenerator
    { private int value; public string NewId() => "audit-" + Interlocked.Increment(ref value); }
}
