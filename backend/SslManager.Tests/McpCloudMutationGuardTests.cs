using System.Net;
using System.Security.Cryptography;
using SslManager.Api.Common;
using SslManager.Api.Common.Mcp;
using SslManager.Api.Models;
using SslManager.Api.Service;

namespace SslManager.Tests;

/// <summary>所有HTTP均由内存Handler承接；只读RPC POST不误判为写，真正云写必须在发送前检查原门禁。</summary>
public sealed class McpCloudMutationGuardTests
{
    private static readonly CloudAccountCredentials Account = new("account", "合成账号", "TencentCloud", "synthetic-key", "synthetic-secret", true, true, true, "", "", "");

    [Theory]
    [InlineData("Tencent")]
    [InlineData("Aliyun")]
    [InlineData("Cloudflare")]
    public async Task MutationIsDeniedBeforeHttpSendWhileReadOnlyPostStillWorks(string provider)
    {
        var handler = new MemoryHandler(); var factory = new MemoryFactory(handler); var checks = 0;
        using var scope = McpCloudMutationGuard.Enter(_ => { checks++; throw new McpExecutionDeniedException("API_KEY_REVOKED", "原调用已撤销。"); }, "original-operation");
        if (provider == "Tencent")
        {
            var api = new TencentCloudApiClient(factory);
            Assert.True((await api.CallAsync(Account, "ssl", "DescribeCertificates", new { }, false, default)).Success);
            await Assert.ThrowsAsync<McpExecutionDeniedException>(() => api.CallAsync(Account, "ssl", "RevokeCertificate", new { }, true, default));
        }
        else if (provider == "Aliyun")
        {
            var api = new AliyunApiClient(factory);
            Assert.True((await api.CallAsync(Account, "cas", "ListUserCertificateOrder", new Dictionary<string, string>(), false, default)).Success);
            await Assert.ThrowsAsync<McpExecutionDeniedException>(() => api.CallAsync(Account, "cas", "RevokeCertificate", new Dictionary<string, string>(), true, default));
        }
        else
        {
            var api = new CloudflareApiClient(factory);
            Assert.True((await api.CallAsync(Account, HttpMethod.Get, "/zones", null, false, default)).Success);
            await Assert.ThrowsAsync<McpExecutionDeniedException>(() => api.CallAsync(Account, HttpMethod.Post, "/zones/zone/dns_records", new { }, true, default));
        }
        Assert.Equal(1, checks); Assert.Equal(1, handler.Sends);
    }

    [Fact]
    public async Task AcmePostAsGetAndExistingAccountLookupStayReadOnlyButNewOrderIsGated()
    {
        var handler = new MemoryHandler(); var api = new AcmeProtocolClient(new MemoryFactory(handler));
        using var rsa = RSA.Create(2048); var key = rsa.ExportPkcs8PrivateKeyPem();
        var directory = new AcmeDirectory(AcmeProtocolClient.StagingDirectory,
            "https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce", "https://acme-staging-v02.api.letsencrypt.org/acme/new-order",
            "https://acme-staging-v02.api.letsencrypt.org/acme/revoke-cert", "https://acme-staging-v02.api.letsencrypt.org/acme/new-acct");
        var checks = 0;
        using var scope = McpCloudMutationGuard.Enter(_ => { checks++; throw new McpExecutionDeniedException("API_KEY_REVOKED", "原调用已撤销。"); });
        Assert.True((await api.PostAsync(directory, "https://acme-staging-v02.api.letsencrypt.org/acme/order/123", key,
            "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123", null)).Success);
        Assert.True((await api.FindExistingAccountAsync(directory, key)).Success);
        Assert.Equal(0, checks);
        var before = handler.Posts;
        await Assert.ThrowsAsync<McpExecutionDeniedException>(() => api.PostAsync(directory, directory.NewOrder, key,
            "https://acme-staging-v02.api.letsencrypt.org/acme/acct/123", new { identifiers = new[] { new { type = "dns", value = "example.test" } } }));
        Assert.Equal(1, checks); Assert.Equal(before, handler.Posts);
    }

    [Fact]
    public async Task NestedScopesPreserveAllChecksAndRestoreOriginalSource()
    {
        var outer = 0; var inner = 0;
        using (McpCloudMutationGuard.Enter(_ => { outer++; return Task.CompletedTask; }, "outer"))
        {
            using (McpCloudMutationGuard.Enter(_ => { inner++; return Task.CompletedTask; }, "inner"))
            {
                Assert.Equal("inner", McpCloudMutationGuard.CurrentOperationId);
                await McpCloudMutationGuard.CheckBeforeMutationAsync(default);
            }
            Assert.Equal("outer", McpCloudMutationGuard.CurrentOperationId);
            await McpCloudMutationGuard.CheckBeforeMutationAsync(default);
        }
        Assert.Null(McpCloudMutationGuard.CurrentOperationId);
        await McpCloudMutationGuard.CheckBeforeMutationAsync(default);
        Assert.Equal(2, outer); Assert.Equal(1, inner);
    }

    private sealed class MemoryFactory(MemoryHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, false);
    }
    private sealed class MemoryHandler : HttpMessageHandler
    {
        public int Sends { get; private set; }
        public int Posts { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Sends++; if (request.Method == HttpMethod.Post) Posts++;
            var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent("{\"Response\":{\"RequestId\":\"synthetic\"},\"success\":true,\"result\":[],\"status\":\"valid\"}") };
            response.Headers.TryAddWithoutValidation("Replay-Nonce", "synthetic-nonce");
            return Task.FromResult(response);
        }
    }
}
