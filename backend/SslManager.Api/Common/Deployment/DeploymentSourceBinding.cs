using SslManager.Api.Models;

namespace SslManager.Api.Common;

/// <summary>部署目标按主域名复用；证书 ID 只保留给旧任务快照兼容，不参与新目标绑定。</summary>
public static class DeploymentSourceBinding
{
    public static string NormalizeDomain(string? value) => value?.Trim().TrimEnd('.').ToLowerInvariant() ?? "";

    public static bool Matches(DeploymentTargetConfiguration configuration, CertificateMaterialMetadata material)
    {
        var domain = NormalizeDomain(configuration.SourceDomain);
        return domain.Length > 0
            ? domain == NormalizeDomain(material.Domain)
            : !string.IsNullOrEmpty(configuration.SourceCertificateId) &&
                configuration.SourceCertificateId == material.CertificateId;
    }

    /// <summary>优先保留精确源文件；续签包仅改变顶层目录时，允许按文件名和角色唯一匹配。</summary>
    public static ApiResult<CertificateSourceFile> ResolveSourceFile(CertificateSourcePackage package, DeploymentFileMapping mapping)
    {
        if (string.IsNullOrWhiteSpace(mapping.SourceFileName)) return Changed();
        var exact = package.Files.Where(file => file.Name == mapping.SourceFileName).ToArray();
        if (exact.Length == 1 && exact[0].Role == mapping.Role)
            return ApiResult<CertificateSourceFile>.Ok(exact[0]);
        // 原路径仍存在但类型变化时不改选其他文件；不能把完整链、私钥或容器互相替代。
        if (exact.Length > 0) return Changed();
        var name = FileName(mapping.SourceFileName);
        var candidates = package.Files.Where(file => file.Role == mapping.Role && FileName(file.Name) == name).ToArray();
        return candidates.Length == 1 ? ApiResult<CertificateSourceFile>.Ok(candidates[0]) : Changed();
    }

    private static string FileName(string name) => name[(name.LastIndexOf('/') + 1)..];

    private static ApiResult<CertificateSourceFile> Changed() => ApiResult<CertificateSourceFile>.Fail(
        "SOURCE_FILE_CHANGED", "选择的源文件不存在、类型已变化或存在多个同名文件，请重新读取该格式证书包并配置映射。");
}
