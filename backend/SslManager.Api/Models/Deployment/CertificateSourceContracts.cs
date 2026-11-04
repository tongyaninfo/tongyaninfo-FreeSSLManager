using System.Text.Json.Serialization;

namespace SslManager.Api.Models;

/// <summary>源格式包保留云端原始文件字节，供任务加密快照和文件部署使用。</summary>
public sealed record CertificateSourcePackage(string Format, IReadOnlyList<CertificateSourceFile> Files);

/// <summary>源文件内容不能直接序列化到 API；持久化时须使用专用加密快照。</summary>
public sealed record CertificateSourceFile(string Name, string Role, [property: JsonIgnore] byte[] Content,
    string Sha256, bool ContainsSecrets)
{
    public override string ToString() => $"CertificateSourceFile {Name} ({Role})";
}

/// <summary>浏览源格式包只提供文件元数据，不向页面发送私钥、密钥库或密码正文。</summary>
public sealed record CertificateSourceFileMetadata(string Name, string Role, long Size, string Sha256, bool ContainsSecrets);
public sealed record CertificateSourceListing(string CertificateId, string Domain, string Format,
    IReadOnlyList<CertificateSourceFileMetadata> Files);
