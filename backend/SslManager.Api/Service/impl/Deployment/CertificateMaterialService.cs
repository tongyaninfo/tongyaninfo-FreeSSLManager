using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;

namespace SslManager.Api.Service.impl;

/// <summary>复用现有云下载能力，部署不再自行调用各厂商的证书接口。</summary>
public sealed class CertificateMaterialService(AppDbContext db, CertificateManagementService certificates)
    : ICertificateMaterialService
{
    public async Task<ApiResult<CertificateMaterial>> GetAsync(string certificateId, CancellationToken ct)
    {
        var source = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(x => x.Id == certificateId, ct);
        if (source is null) return ApiResult<CertificateMaterial>.Fail("NOT_FOUND", "证书不存在。");
        if (source.Status != "Issued") return ApiResult<CertificateMaterial>.Fail("INVALID_STATE", "仅已签发证书可以部署。");
        if (!source.CanDeploy) return ApiResult<CertificateMaterial>.Fail("CERTIFICATE_NOT_DEPLOYABLE", "此证书没有本地私钥或属于 ACME 测试环境，不能部署。");
        // 两个现有云适配器均支持 Nginx 包，其内容在内存中规范化。
        var package = await certificates.DownloadAsync(certificateId, "nginx", ct);
        if (!package.Success || package.Data is null)
            return ApiResult<CertificateMaterial>.Fail(package.Code, package.Message);
        return CertificateMaterialHelper.FromArchive(package.Data.Content, certificateId,
            CertificateManagementService.PrimaryDomain(source.Domain));
    }

    public async Task<ApiResult<CertificateSourcePackage>> GetSourceAsync(string certificateId, string format,
        CertificateMaterialMetadata expected, CancellationToken ct)
    {
        if (expected.CertificateId != certificateId)
            return ApiResult<CertificateSourcePackage>.Fail("SOURCE_CERTIFICATE_MISMATCH", "源证书与当前部署材料不一致。");
        format = format?.Trim().ToLowerInvariant() ?? "";
        if (format is not ("nginx" or "apache" or "iis" or "tomcat"))
            return ApiResult<CertificateSourcePackage>.Fail("SOURCE_FORMAT_UNSUPPORTED", "请选择 Nginx、Apache、IIS 或 Tomcat 源格式。");
        var package = await certificates.DownloadAsync(certificateId, format, ct);
        if (!package.Success || package.Data is null)
            return ApiResult<CertificateSourcePackage>.Fail(package.Code, package.Message);
        // 使用源包原文件，不能重新生成 PFX 或替换其配套密码文件。
        return CertificateSourcePackageHelper.FromArchive(package.Data.Content, format, expected);
    }
}
