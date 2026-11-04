using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using SslManager.Api.Models;

namespace SslManager.Api.Common;

/// <summary>证书下载全程内存处理，校验体积、ZIP 路径与证书私钥；不产生含密钥临时文件。</summary>
public static class CertificateDownloadHelper
{
    /// <summary>
    /// 生成面向用户的证书包文件名。域名来自本地绑定快照，任何路径字符都会被替换，
    /// 日期固定使用业务时区（Asia/Shanghai），避免服务器部署在 UTC 时出现前一天文件名。
    /// </summary>
    public static string BuildFileName(string? domain, string? format, string fallbackId, DateTimeOffset? now = null)
    {
        var safeDomain = SafePart(domain, fallbackId);
        var safeFormat = SafePart(format, "certificate").ToLowerInvariant();
        var localDate = TimeZoneInfo.ConvertTime(now ?? DateTimeOffset.UtcNow, ChinaTimeZone).ToString("yyyyMMdd");
        var extension = safeFormat == "pfx" ? "pfx" : "zip";
        return $"{safeDomain}-{safeFormat}-{localDate}.{extension}";
    }

    private static readonly TimeZoneInfo ChinaTimeZone = ResolveChinaTimeZone();
    private static TimeZoneInfo ResolveChinaTimeZone()
    {
        try { return TimeZoneInfo.FindSystemTimeZoneById("Asia/Shanghai"); }
        catch (TimeZoneNotFoundException) { return TimeZoneInfo.Utc; }
        catch (InvalidTimeZoneException) { return TimeZoneInfo.Utc; }
    }

    private static string SafePart(string? value, string fallback)
    {
        var text = (value ?? string.Empty).Trim();
        text = Regex.Replace(text, @"[^A-Za-z0-9._-]+", "_");
        text = text.Trim('.', ' ');
        return text.Length is > 0 and <= 180 ? text : fallback;
    }

    public static async Task<ApiResult<byte[]>> ReadLimitedAsync(HttpContent content, int limit, CancellationToken ct)
    {
        if (content.Headers.ContentLength > limit) return ApiResult<byte[]>.Fail("ResponseTooLarge", "云端响应超出安全体积限制。");
        await using var stream = await content.ReadAsStreamAsync(ct);
        using var output = new MemoryStream();
        var buffer = new byte[16384];
        int read;
        while ((read = await stream.ReadAsync(buffer, ct)) > 0)
        {
            if (output.Length + read > limit) return ApiResult<byte[]>.Fail("ResponseTooLarge", "云端响应超出安全体积限制。");
            await output.WriteAsync(buffer.AsMemory(0, read), ct);
        }
        return ApiResult<byte[]>.Ok(output.ToArray());
    }

    public static bool IsAllowedTencentUrl(string value, out Uri? uri)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out uri) || uri.Scheme != Uri.UriSchemeHttps || uri.Port != 443
            || !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment)) return false;
        var host = uri.IdnHost;
        return new[] { "myqcloud.com", "qcloud.com", "tencentcloudapi.com", "cloud.tencent.com" }.Any(suffix =>
            host.Equals(suffix, StringComparison.OrdinalIgnoreCase) || host.EndsWith('.' + suffix, StringComparison.OrdinalIgnoreCase));
    }

    public static async Task<ApiResult<CertificateDownload>> DownloadTencentAsync(IHttpClientFactory clients, string url, string id,
        string format, string requestId, CancellationToken ct)
    {
        if (!IsAllowedTencentUrl(url, out var uri)) return ApiResult<CertificateDownload>.Fail("UnsafeDownloadUrl", "已阻止非腾讯云 HTTPS 证书下载地址。");
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            using var response = await clients.CreateClient("CloudCertificateDownload").SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            // 命名客户端禁重定向；3xx 不继续跟随，临时链接不进入日志。
            if (!response.IsSuccessStatusCode) return ApiResult<CertificateDownload>.Fail("CertificateDownloadFailed", "证书下载失败。");
            var bytes = await ReadLimitedAsync(response.Content, 8 * 1024 * 1024, ct);
            if (!bytes.Success) return CloudJson.Fail<CertificateDownload, byte[]>(bytes);
            var check = ValidateZip(bytes.Data!);
            if (!check.Success) return CloudJson.Fail<CertificateDownload, bool>(check);
            return ApiResult<CertificateDownload>.Ok(new(bytes.Data!, "application/zip", $"{id}-{format}.zip", requestId));
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { return ApiResult<CertificateDownload>.Fail("CloudTimeout", "证书下载超时。"); }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException)
        { return ApiResult<CertificateDownload>.Fail("CertificateDownloadFailed", "证书下载或证书包解析失败。"); }
    }

    public static ApiResult<bool> ValidateZip(byte[] bytes)
    {
        try
        {
            using var stream = new MemoryStream(bytes);
            using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
            if (archive.Entries.Count is 0 or > 64) return InvalidZip();
            long total = 0;
            foreach (var entry in archive.Entries)
            {
                var path = entry.FullName.Replace('\\', '/');
                if (path.StartsWith('/') || path.Contains(':') || path.Split('/').Any(p => p is ".." or ".")) return InvalidZip();
                total += entry.Length;
                if (entry.Length > 2 * 1024 * 1024 || total > 8 * 1024 * 1024) return InvalidZip();
                // 流式读每个文件，验证真实解压体积与声明一致。
                using var input = entry.Open();
                var buffer = new byte[16384]; long actual = 0; int read;
                while ((read = input.Read(buffer)) > 0) { actual += read; if (actual > entry.Length || actual > 2 * 1024 * 1024) return InvalidZip(); }
                if (actual != entry.Length) return InvalidZip();
            }
            return ApiResult<bool>.Ok(true);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or ArgumentException)
        { return InvalidZip(); }
    }

    public static ApiResult<CertificateDownload> FromPem(string certificatePem, string privateKeyPem, string id, string format, string requestId)
    {
        if (string.IsNullOrWhiteSpace(certificatePem) || string.IsNullOrWhiteSpace(privateKeyPem))
            return ApiResult<CertificateDownload>.Fail("CertificateMaterialMissing", "云端未返回完整证书或私钥，无法下载。");
        if (certificatePem.Length + privateKeyPem.Length > 2 * 1024 * 1024)
            return ApiResult<CertificateDownload>.Fail("ResponseTooLarge", "证书材料体积异常。");
        if (format is not ("pem" or "nginx" or "apache" or "iis" or "pfx"))
            return ApiResult<CertificateDownload>.Fail("UnsupportedDownloadFormat", "阿里云支持 PEM、Nginx、Apache、IIS/PFX 下载。");
        try
        {
            using var certificate = X509Certificate2.CreateFromPem(certificatePem, privateKeyPem);
            if (!certificate.HasPrivateKey) return ApiResult<CertificateDownload>.Fail("CertificateMaterialInvalid", "证书材料不包含匹配的私钥。");
            if (format is "pfx" or "iis")
            {
                var chain = new X509Certificate2Collection();
                chain.ImportFromPem(certificatePem);
                var export = new X509Certificate2Collection(certificate);
                // 保留中间链；叶子证书已包含私钥，不重复添加叶子。
                foreach (var item in chain) if (item.Thumbprint != certificate.Thumbprint) export.Add(item);
                var content = export.Export(X509ContentType.Pkcs12, "");
                foreach (var item in chain) item.Dispose();
                if (content is null) return ApiResult<CertificateDownload>.Fail("CertificateMaterialInvalid", "PFX 转换失败。");
                if (format == "pfx") return ApiResult<CertificateDownload>.Ok(new(content, "application/x-pkcs12", $"{id}.pfx", requestId));
                // IIS 下载统一为 zip 包，避免响应文件名是 .zip 却实际返回裸 PFX。
                using var package = new MemoryStream();
                using (var archive = new ZipArchive(package, ZipArchiveMode.Create, leaveOpen: true))
                {
                    using var target = archive.CreateEntry("certificate.pfx").Open();
                    target.Write(content, 0, content.Length);
                }
                return ApiResult<CertificateDownload>.Ok(new(package.ToArray(), "application/zip", $"{id}-iis.zip", requestId));
            }
            using var output = new MemoryStream();
            using (var archive = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
            {
                Write(archive, "fullchain.pem", certificatePem);
                Write(archive, "private.key", privateKeyPem);
                if (format == "apache") Write(archive, "certificate.crt", certificate.ExportCertificatePem());
            }
            return ApiResult<CertificateDownload>.Ok(new(output.ToArray(), "application/zip", $"{id}-{format}.zip", requestId));
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException or IOException)
        { return ApiResult<CertificateDownload>.Fail("CertificateMaterialInvalid", "证书解析失败或私钥不匹配。"); }
    }
    private static void Write(ZipArchive zip, string path, string value)
    { using var writer = new StreamWriter(zip.CreateEntry(path).Open(), new UTF8Encoding(false)); writer.Write(value); }
    private static ApiResult<bool> InvalidZip() => ApiResult<bool>.Fail("InvalidCertificatePackage", "证书包结构、路径或解压体积异常。");
}
