using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SslManager.Api.Common;

namespace SslManager.Tests;

/// <summary>使用合成 CA 错误验证固定分类，原始 detail 不进入公开响应。</summary>
public sealed class AcmeProtocolErrorTests
{
    [Theory]
    [InlineData("invalidContact", "ACME_INVALID_CONTACT", "联系邮箱")]
    [InlineData("unsupportedContact", "ACME_UNSUPPORTED_CONTACT", "联系方式")]
    [InlineData("malformed", "ACME_MALFORMED", "请求格式")]
    [InlineData("badPublicKey", "ACME_BAD_PUBLIC_KEY", "账户公钥")]
    [InlineData("badSignatureAlgorithm", "ACME_BAD_SIGNATURE_ALGORITHM", "签名算法")]
    [InlineData("unauthorized", "ACME_UNAUTHORIZED", "账户授权")]
    [InlineData("userActionRequired", "ACME_USER_ACTION_REQUIRED", "服务条款")]
    [InlineData("accountDoesNotExist", "ACME_ACCOUNT_NOT_FOUND", "尚未注册")]
    [InlineData("rateLimited", "ACME_RATE_LIMITED", "频率受限")]
    public async Task RegistrationErrorsExposeOnlyKnownProblemCategories(string type, string code, string messagePart)
    {
        var result = await SubmitAsync(HttpStatusCode.BadRequest, "urn:ietf:params:acme:error:" + type);
        Assert.False(result.Success);
        Assert.Equal(code, result.Code);
        Assert.Contains(messagePart, result.Message);
        Assert.DoesNotContain("synthetic-secret", result.Message);
        Assert.DoesNotContain("CAA", result.Message);
    }

    [Theory]
    [InlineData("urn:ietf:params:acme:error:futureProblem")]
    [InlineData("https://untrusted.invalid/invalidContact")]
    [InlineData("urn:untrusted:invalidContact")]
    public async Task UnknownRegistrationErrorUsesRegistrationContextAndHttpStatus(string type)
    {
        var result = await SubmitAsync(HttpStatusCode.Forbidden, type);
        Assert.Equal("ACME_REJECTED", result.Code);
        Assert.Contains("账户注册或核对", result.Message);
        Assert.Contains("HTTP 403", result.Message);
        Assert.DoesNotContain("CAA", result.Message);
        Assert.DoesNotContain(type, result.Message);
        Assert.DoesNotContain("synthetic-secret", result.Message);
    }

    [Fact]
    public async Task ServerFailureRemainsUnknownEvenWhenBodyClaimsKnownRejection()
    {
        var result = await SubmitAsync(HttpStatusCode.ServiceUnavailable, "urn:ietf:params:acme:error:invalidContact");
        Assert.Equal("OutcomeUnknown", result.Code);
    }

    private static async Task<ApiResult<AcmeProtocolResponse>> SubmitAsync(HttpStatusCode status, string type)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var directory = new AcmeDirectory(AcmeProtocolClient.StagingDirectory, Base + "/nonce", Base + "/order", Base + "/revoke", Base + "/account");
        return await new AcmeProtocolClient(new Factory(status, type)).CreateAccountAsync(directory, key.ExportPkcs8PrivateKeyPem(), "synthetic@example.test");
    }

    private const string Base = "https://acme-staging-v02.api.letsencrypt.org";
    private sealed class Factory(HttpStatusCode status, string type) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(new Handler(status, type));
    }
    private sealed class Handler(HttpStatusCode status, string type) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var response = request.Method == HttpMethod.Head ? new HttpResponseMessage(HttpStatusCode.OK) : new HttpResponseMessage(status)
            {
                Content = new StringContent(JsonSerializer.Serialize(new { type, detail = "synthetic-secret contact and private material" }), Encoding.UTF8, "application/problem+json")
            };
            response.Headers.Add("Replay-Nonce", "synthetic_nonce");
            return Task.FromResult(response);
        }
    }
}
