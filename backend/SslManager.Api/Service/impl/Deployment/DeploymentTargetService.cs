using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service.impl.Deployment.Transports;
using SslManager.Api.Service.impl.Deployment.Executors;
namespace SslManager.Api.Service.impl.Deployment;

/// <summary>连接资料与密文凭据统一保存，所有公开 DTO 明确移除秘密。</summary>
public sealed class DeploymentTargetService(AppDbContext db, IDeploymentExecutorResolver executors,
    IDataProtectionProvider protection, IIdGenerator ids) : IDeploymentTargetService
{
    internal static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    internal const string ConfigurationProtectionPurpose = "SslManager.Deployment.Target.v1";
    private IDataProtector Protector(string id) => protection.CreateProtector(ConfigurationProtectionPurpose, id);
    public async Task<ApiResult<PageResult<DeploymentTargetView>>> ListAsync(int page, int pageSize, string? search, CancellationToken ct)
    {
        page = Math.Max(page, 1); pageSize = Math.Clamp(pageSize, 1, 200);
        var query = db.DeploymentTargets.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(search)) query = query.Where(x => x.Name.Contains(search) || x.Description.Contains(search));
        var total = await query.CountAsync(ct);
        var rows = await query.OrderByDescending(x => x.CreatedAtUtc).Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return ApiResult<PageResult<DeploymentTargetView>>.Ok(new(rows.Select(ToView).ToArray(), total, page, pageSize));
    }
    public async Task<ApiResult<DeploymentTargetView>> GetAsync(string id, CancellationToken ct)
    {
        var row = await db.DeploymentTargets.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        return row is null ? ApiResult<DeploymentTargetView>.Fail("NOT_FOUND", "部署目标不存在。") : ApiResult<DeploymentTargetView>.Ok(ToView(row));
    }
    public async Task<ApiResult<DeploymentTargetView>> SaveAsync(string? id, DeploymentTargetInput input, CancellationToken ct)
    {
        var resolved = executors.Resolve(input.ExecutorKey);
        if (!resolved.Success || resolved.Data is null) return ApiResult<DeploymentTargetView>.Fail(resolved.Code, resolved.Message);
        var descriptor = resolved.Data.Descriptor;
        NormalizeConfiguration(input);
        var validation = Validate(input, descriptor);
        if (validation is not null) return ApiResult<DeploymentTargetView>.Fail("VALIDATION", validation);
        var sourceValidation = await ValidateSourceConfigurationAsync(db, input, true, ct);
        if (sourceValidation is not null) return ApiResult<DeploymentTargetView>.Fail("VALIDATION", sourceValidation);
        // 部署目标仅持久化域名；具体证书由每次部署计划固定，避免续签后仍绑定旧 ID。
        input.Configuration.SourceCertificateId = "";
        var existing = id is null ? null : await db.DeploymentTargets.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (id is not null && existing is null) return ApiResult<DeploymentTargetView>.Fail("NOT_FOUND", "部署目标不存在。");
        if (existing is not null && existing.ExecutorKey != input.ExecutorKey)
            return ApiResult<DeploymentTargetView>.Fail("CONFLICT", "已有目标不能原地更换执行器，请新建目标。");
        if (existing is not null && input.ConfigRevision.HasValue && input.ConfigRevision != existing.ConfigRevision)
            return ApiResult<DeploymentTargetView>.Fail("CONFLICT", "部署目标已被修改，请刷新后重试。");
        var now = DateTime.UtcNow;
        var row = existing ?? new DeploymentTarget { Id = ids.NewId(), CreatedAtUtc = now };
        DeploymentCredentials secret;
        try { secret = existing is null ? new() : ReadSecrets(row); }
        catch (CryptographicException) { return ApiResult<DeploymentTargetView>.Fail("CREDENTIALS_UNAVAILABLE", "部署凭据无法解密，请核对应用密钥备份。"); }
        if (!string.IsNullOrEmpty(input.Password)) secret.Password = input.Password;
        if (!string.IsNullOrEmpty(input.ApiToken)) secret.ApiToken = input.ApiToken;
        if (!string.IsNullOrEmpty(input.PrivateKey)) secret.PrivateKey = input.PrivateKey;
        if (!string.IsNullOrEmpty(input.PrivateKeyPassphrase)) secret.PrivateKeyPassphrase = input.PrivateKeyPassphrase;
        if (!string.IsNullOrEmpty(input.PfxPassword)) secret.PfxPassword = input.PfxPassword;
        var credentialsValidation = ValidateCredentials(input, secret);
        if (credentialsValidation is not null) return ApiResult<DeploymentTargetView>.Fail("VALIDATION", credentialsValidation);
        ApplyConfiguration(row, input, descriptor, secret, protection);
        row.ConfigRevision = existing is null ? 1 : row.ConfigRevision + 1; row.UpdatedAtUtc = now;
        row.LastTestAtUtc = null; row.LastTestSuccess = null; row.LastTestMessage = "配置已更新，请重新测试连接。";
        if (existing is null) db.DeploymentTargets.Add(row);
        try { await db.SaveChangesAsync(ct); }
        catch (DbUpdateConcurrencyException) { return ApiResult<DeploymentTargetView>.Fail("CONFLICT", "部署目标已被修改，请刷新后重试。"); }
        return ApiResult<DeploymentTargetView>.Ok(ToView(row), "部署目标已保存，留空凭据保留原值。");
    }

    /// <summary>将既有 Linux 源文件目标从证书 ID 转为域名；只更新配置，不读取或重写连接凭据。</summary>
    public async Task<int> BackfillSourceDomainsAsync(CancellationToken ct)
    {
        var rows = await db.DeploymentTargets.Where(row => row.ExecutorKey == "linux.files.ssh.v1").ToListAsync(ct);
        var pending = new List<(DeploymentTarget Row, DeploymentTargetConfiguration Configuration)>();
        foreach (var row in rows)
        {
            DeploymentTargetConfiguration? configuration;
            try { configuration = JsonSerializer.Deserialize<DeploymentTargetConfiguration>(row.ConfigurationJson, Json); }
            catch (JsonException) { continue; }
            if (configuration is null || string.IsNullOrWhiteSpace(configuration.SourceFormat) ||
                string.IsNullOrWhiteSpace(configuration.SourceCertificateId)) continue;
            pending.Add((row, configuration));
        }
        if (pending.Count == 0) return 0;
        var sourceIds = pending.Select(item => item.Configuration.SourceCertificateId.Trim()).Distinct().ToArray();
        var domains = await db.Certificates.AsNoTracking().Where(certificate => sourceIds.Contains(certificate.Id))
            .Select(certificate => new { certificate.Id, certificate.Domain }).ToDictionaryAsync(certificate => certificate.Id, certificate => certificate.Domain, ct);
        var now = DateTime.UtcNow;
        var updated = 0;
        foreach (var (row, configuration) in pending)
        {
            var domain = DeploymentSourceBinding.NormalizeDomain(configuration.SourceDomain);
            if (string.IsNullOrEmpty(domain) && domains.TryGetValue(configuration.SourceCertificateId.Trim(), out var previousDomain))
                domain = DeploymentSourceBinding.NormalizeDomain(CertificateManagementService.PrimaryDomain(previousDomain));
            // 无法确定旧绑定身份时保留原配置，不能猜测域名或清空约束。
            if (!ValidSourceDomain(domain)) continue;
            configuration.SourceDomain = domain;
            configuration.SourceCertificateId = "";
            row.ConfigurationJson = JsonSerializer.Serialize(configuration, Json);
            row.ConfigRevision++;
            row.UpdatedAtUtc = now;
            updated++;
        }
        await db.SaveChangesAsync(ct);
        return updated;
    }

    /// <summary>保存、启用和导入共享规范化，包内不能以旧证书 ID 代替可移植域名。</summary>
    internal static void NormalizeConfiguration(DeploymentTargetInput input)
    {
        if (input.Configuration is null) return;
        input.Configuration.SourceFormat = input.Configuration.SourceFormat?.Trim().ToLowerInvariant() ?? "";
        input.Configuration.SourceDomain = DeploymentSourceBinding.NormalizeDomain(input.Configuration.SourceDomain);
        input.Configuration.SourceCertificateId = input.Configuration.SourceCertificateId?.Trim() ?? "";
    }

    internal static async Task<string?> ValidateSourceConfigurationAsync(AppDbContext db, DeploymentTargetInput input,
        bool requireIssuedCertificate, CancellationToken ct)
    {
        var configuration = input.Configuration;
        if (string.IsNullOrEmpty(configuration.SourceFormat)) return null;
        if (input.ExecutorKey != "linux.files.ssh.v1" || configuration.SourceFormat is not ("nginx" or "apache" or "iis" or "tomcat"))
            return "所选证书来源格式仅支持 Linux 部署的 Nginx、Apache、IIS、Tomcat。";
        if (requireIssuedCertificate && string.IsNullOrEmpty(configuration.SourceDomain) && configuration.SourceCertificateId.Length is > 0 and <= 80)
        {
            var source = await db.Certificates.AsNoTracking().SingleOrDefaultAsync(certificate =>
                certificate.Id == configuration.SourceCertificateId && certificate.Status == "Issued", ct);
            if (source is not null) configuration.SourceDomain = DeploymentSourceBinding.NormalizeDomain(CertificateManagementService.PrimaryDomain(source.Domain));
        }
        if (!ValidSourceDomain(configuration.SourceDomain)) return "请选择有效的来源域名。";
        if (requireIssuedCertificate)
        {
            var issuedDomains = await db.Certificates.AsNoTracking().Where(certificate => certificate.Status == "Issued")
                .Select(certificate => certificate.Domain).Distinct().ToListAsync(ct);
            if (!issuedDomains.Any(domain => DeploymentSourceBinding.NormalizeDomain(CertificateManagementService.PrimaryDomain(domain)) == configuration.SourceDomain))
                return "来源域名没有已签发证书，请先签发或同步对应域名的证书。";
        }
        if (configuration.Files.Count == 0 || configuration.Files.Any(file =>
            string.IsNullOrWhiteSpace(file.SourceFileName) || file.SourceFileName.Length > 2048 || file.SourceFileName.Any(char.IsControl) ||
            file.Directory is null || file.Directory.Length > 2048 || file.Directory.Any(char.IsControl) ||
            !string.IsNullOrWhiteSpace(file.Directory) && !file.Directory.StartsWith('/')))
            return "请为每个部署文件选择来源文件，并填写有效的 Linux 绝对目录。";
        return null;
    }

    internal static DeploymentCredentials CredentialsFromInput(DeploymentTargetInput input) => new()
    {
        Password = input.Password ?? "", ApiToken = input.ApiToken ?? "", PrivateKey = input.PrivateKey ?? "",
        PrivateKeyPassphrase = input.PrivateKeyPassphrase ?? "", PfxPassword = input.PfxPassword ?? ""
    };

    internal static string? ValidateCredentials(DeploymentTargetInput input, DeploymentCredentials secret)
    {
        if (input.AuthenticationMode == "Password" && (string.IsNullOrWhiteSpace(input.Username) || string.IsNullOrEmpty(secret.Password)))
            return "请配置用户名和密码。";
        if (input.AuthenticationMode == "ApiToken" && string.IsNullOrWhiteSpace(secret.ApiToken)) return "请配置 API Token。";
        if (input.AuthenticationMode == "PrivateKey" && (string.IsNullOrWhiteSpace(input.Username) || string.IsNullOrWhiteSpace(secret.PrivateKey)))
            return "请配置用户名和 SSH 私钥。";
        return null;
    }

    internal static void ApplyConfiguration(DeploymentTarget row, DeploymentTargetInput input, DeploymentExecutorDescriptor descriptor,
        DeploymentCredentials secret, IDataProtectionProvider protection)
    {
        row.Name = input.Name.Trim(); row.Description = input.Description?.Trim() ?? ""; row.ExecutorKey = input.ExecutorKey;
        row.ExecutorRevision = descriptor.Revision; row.Endpoint = input.Endpoint.Trim().TrimEnd('/');
        var endpointPort = Uri.TryCreate(row.Endpoint, UriKind.Absolute, out var uri) ? uri.Port : 0;
        row.Port = input.Port > 0 ? input.Port : endpointPort > 0 ? endpointPort : 22;
        if (descriptor.TargetType == "Synology") row.Port = SynologyDsmApiClient.BaseUri(new() { Endpoint = row.Endpoint, Port = input.Port }).Port;
        row.Username = input.Username?.Trim() ?? ""; row.AuthenticationMode = input.AuthenticationMode; row.Enabled = input.Enabled;
        row.TlsFingerprint = input.TlsFingerprint?.Trim() ?? ""; row.ConfigurationJson = JsonSerializer.Serialize(input.Configuration, Json);
        row.ProtectedCredentials = protection.CreateProtector(ConfigurationProtectionPurpose, row.Id).Protect(JsonSerializer.Serialize(secret, Json));
    }

    /// <summary>只供管理员配置迁移在内存中映射，包含停用目标，不能用于普通列表响应。</summary>
    internal static DeploymentTargetInput ExportConfiguration(DeploymentTarget row, IDataProtectionProvider protection)
    {
        var secret = ReadSecrets(row, protection);
        return new()
        {
            Name = row.Name, Description = row.Description, ExecutorKey = row.ExecutorKey, Endpoint = row.Endpoint,
            Port = row.Port, Username = row.Username, AuthenticationMode = row.AuthenticationMode, Enabled = row.Enabled,
            TlsFingerprint = row.TlsFingerprint, Configuration = JsonSerializer.Deserialize<DeploymentTargetConfiguration>(row.ConfigurationJson, Json)
                ?? throw new JsonException(), Password = secret.Password, ApiToken = secret.ApiToken,
            PrivateKey = secret.PrivateKey, PrivateKeyPassphrase = secret.PrivateKeyPassphrase, PfxPassword = secret.PfxPassword
        };
    }

    private static bool ValidSourceDomain(string domain) => domain.Length <= 253 &&
        CertificateManagementService.IsValidDomain(domain.StartsWith("*.", StringComparison.Ordinal) ? domain[2..] : domain);

    public async Task<ApiResult<DeploymentTargetView>> SetStatusAsync(string id, bool enabled, CancellationToken ct)
    {
        var row = await db.DeploymentTargets.SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return ApiResult<DeploymentTargetView>.Fail("NOT_FOUND", "部署目标不存在。");
        if (enabled)
        {
            // 导入只允许保存禁用配置；启用时重新检查当前实例的来源证书和完整凭据。
            var resolved = executors.Resolve(row.ExecutorKey);
            if (!resolved.Success || resolved.Data is null) return ApiResult<DeploymentTargetView>.Fail(resolved.Code, resolved.Message);
            try
            {
                var input = ExportConfiguration(row, protection);
                NormalizeConfiguration(input);
                var validation = Validate(input, resolved.Data.Descriptor) ?? ValidateCredentials(input, CredentialsFromInput(input))
                    ?? await ValidateSourceConfigurationAsync(db, input, true, ct);
                if (validation is not null) return ApiResult<DeploymentTargetView>.Fail("VALIDATION", validation);
            }
            catch (Exception exception) when (exception is CryptographicException or JsonException)
            { return ApiResult<DeploymentTargetView>.Fail("CREDENTIALS_UNAVAILABLE", "目标配置或凭据无法读取，请核对配置及原密钥。"); }
        }
        row.Enabled = enabled; row.ConfigRevision++; row.UpdatedAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync(ct);
        return ApiResult<DeploymentTargetView>.Ok(ToView(row));
    }
    public async Task<ApiResult<DeploymentTargetContext>> GetContextAsync(string id, CancellationToken ct)
    {
        var row = await db.DeploymentTargets.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, ct);
        if (row is null) return ApiResult<DeploymentTargetContext>.Fail("NOT_FOUND", "部署目标不存在。");
        if (!row.Enabled) return ApiResult<DeploymentTargetContext>.Fail("FORBIDDEN", "部署目标已停用。");
        try { return ApiResult<DeploymentTargetContext>.Ok(new() { Id = row.Id, Name = row.Name, ExecutorKey = row.ExecutorKey,
            ExecutorRevision = row.ExecutorRevision, Endpoint = row.Endpoint, Port = row.Port, Username = row.Username,
            AuthenticationMode = row.AuthenticationMode, TlsFingerprint = row.TlsFingerprint, ConfigRevision = row.ConfigRevision,
            Configuration = JsonSerializer.Deserialize<DeploymentTargetConfiguration>(row.ConfigurationJson, Json) ?? new(), Credentials = ReadSecrets(row) }); }
        catch (CryptographicException) { return ApiResult<DeploymentTargetContext>.Fail("CREDENTIALS_UNAVAILABLE", "部署凭据无法解密，请核对应用密钥备份。"); }
    }
    public async Task<ApiResult<DeploymentTargetContext>> GetBrowseContextAsync(RemoteBrowseRequest request, CancellationToken ct)
    {
        if (request.ExecutorKey != "linux.files.ssh.v1")
            return ApiResult<DeploymentTargetContext>.Fail("BROWSE_UNSUPPORTED", "当前仅支持 Linux SSH 目录浏览。");
        if (string.IsNullOrWhiteSpace(request.Endpoint) || request.Endpoint.Length > 2048 ||
            string.IsNullOrWhiteSpace(request.Username) || request.Username.Length > 200 ||
            request.AuthenticationMode is not ("Password" or "PrivateKey") || request.Port is < 0 or > 65535 ||
            request.Password?.Length > 16384 || request.PrivateKey?.Length > 65536 || request.PrivateKeyPassphrase?.Length > 4096 ||
            request.HostKeyFingerprint?.Length > 256 || request.ConnectionTimeoutSeconds is < 1 or > 120 || request.OperationTimeoutSeconds is < 1 or > 120)
            return ApiResult<DeploymentTargetContext>.Fail("VALIDATION", "SSH 连接字段或超时设置不正确。");
        var credentials = new DeploymentCredentials
        {
            Password = request.Password ?? "", PrivateKey = request.PrivateKey ?? "",
            PrivateKeyPassphrase = request.PrivateKeyPassphrase ?? ""
        };
        var context = new DeploymentTargetContext
        {
            Id = request.TargetId ?? "", ExecutorKey = request.ExecutorKey, Endpoint = request.Endpoint.Trim(), Port = request.Port,
            Username = request.Username.Trim(), AuthenticationMode = request.AuthenticationMode, Credentials = credentials,
            Configuration = new()
            {
                HostKeyFingerprint = request.HostKeyFingerprint?.Trim() ?? "",
                ConnectionTimeoutSeconds = request.ConnectionTimeoutSeconds, OperationTimeoutSeconds = request.OperationTimeoutSeconds
            }
        };
        var endpoint = SshRemoteTransport.ParseEndpoint(context);
        if (!endpoint.Success) return ApiResult<DeploymentTargetContext>.Fail(endpoint.Code, endpoint.Message);
        var needsStoredCredential = request.AuthenticationMode == "Password" ? string.IsNullOrEmpty(credentials.Password) : string.IsNullOrEmpty(credentials.PrivateKey);
        if (needsStoredCredential)
        {
            if (string.IsNullOrWhiteSpace(request.TargetId))
                return ApiResult<DeploymentTargetContext>.Fail("CREDENTIALS_REQUIRED", "请填写当前 SSH 连接的密码或私钥。");
            var saved = await GetContextAsync(request.TargetId, ct);
            if (!saved.Success || saved.Data is null) return saved;
            var original = saved.Data;
            if (request.ConfigRevision != original.ConfigRevision)
                return ApiResult<DeploymentTargetContext>.Fail("CONFLICT", "已保存目标的配置已变化，请刷新后再浏览。");
            var originalEndpoint = SshRemoteTransport.ParseEndpoint(original);
            if (!originalEndpoint.Success || original.ExecutorKey != context.ExecutorKey ||
                original.AuthenticationMode != context.AuthenticationMode || original.Username != context.Username ||
                !string.Equals(originalEndpoint.Data.Host, endpoint.Data.Host, StringComparison.OrdinalIgnoreCase) || originalEndpoint.Data.Port != endpoint.Data.Port ||
                !string.IsNullOrWhiteSpace(original.Configuration.HostKeyFingerprint) &&
                !string.Equals(original.Configuration.HostKeyFingerprint.Trim(), context.Configuration.HostKeyFingerprint, StringComparison.Ordinal))
                return ApiResult<DeploymentTargetContext>.Fail("CREDENTIALS_REQUIRED", "SSH 连接身份已修改，请重新填写密码或私钥；不会向新连接发送已保存凭据。");
            // 仅连接身份与版本均一致时复用；新表单显式凭据永不写回数据库。
            if (context.AuthenticationMode == "Password") credentials.Password = original.Credentials.Password;
            else
            {
                credentials.PrivateKey = original.Credentials.PrivateKey;
                if (string.IsNullOrEmpty(credentials.PrivateKeyPassphrase)) credentials.PrivateKeyPassphrase = original.Credentials.PrivateKeyPassphrase;
            }
        }
        if (context.AuthenticationMode == "Password" ? string.IsNullOrEmpty(credentials.Password) : string.IsNullOrEmpty(credentials.PrivateKey))
            return ApiResult<DeploymentTargetContext>.Fail("CREDENTIALS_REQUIRED", "请填写当前 SSH 连接的密码或私钥。");
        return ApiResult<DeploymentTargetContext>.Ok(context);
    }
    public async Task<ApiResult<DeploymentConnectionTest>> TestAsync(string id, CancellationToken ct)
    {
        var context = await GetContextAsync(id, ct);
        if (!context.Success || context.Data is null) return ApiResult<DeploymentConnectionTest>.Fail(context.Code, context.Message);
        var executor = executors.Resolve(context.Data.ExecutorKey);
        if (!executor.Success || executor.Data is null) return ApiResult<DeploymentConnectionTest>.Fail(executor.Code, executor.Message);
        var result = await executor.Data.TestAsync(context.Data, ct);
        var row = await db.DeploymentTargets.SingleAsync(x => x.Id == id, ct);
        // 不把测试时的旧配置结果误写成当前配置已经验证。
        if (row.ConfigRevision == context.Data.ConfigRevision)
        {
            row.LastTestAtUtc = DateTime.UtcNow; row.LastTestSuccess = result.Success;
            row.LastTestMessage = DeploymentSafeText.Redact(result.Message, context.Data.Credentials);
            if (result.Success && result.Data is not null) row.ProductVersion = result.Data.ProductVersion;
            await db.SaveChangesAsync(ct);
        }
        return result.Success && result.Data is not null ? ApiResult<DeploymentConnectionTest>.Ok(result.Data with
        { Message = DeploymentSafeText.Redact(result.Data.Message, context.Data.Credentials) }, DeploymentSafeText.Redact(result.Message, context.Data.Credentials))
            : ApiResult<DeploymentConnectionTest>.Fail(result.Code, DeploymentSafeText.Redact(result.Message, context.Data.Credentials));
    }
    public async Task<ApiResult<DeploymentDiscovery>> DiscoverAsync(string id, CancellationToken ct)
    {
        var context = await GetContextAsync(id, ct);
        if (!context.Success || context.Data is null) return ApiResult<DeploymentDiscovery>.Fail(context.Code, context.Message);
        var resolved = executors.Resolve(context.Data.ExecutorKey);
        if (!resolved.Success || resolved.Data is not IDeploymentDiscoveryExecutor discovery)
            return ApiResult<DeploymentDiscovery>.Fail("DISCOVERY_UNSUPPORTED", "此目标不提供证书或站点发现。");
        return await discovery.DiscoverAsync(context.Data, ct);
    }
    private DeploymentCredentials ReadSecrets(DeploymentTarget row) => ReadSecrets(row, protection);
    private static DeploymentCredentials ReadSecrets(DeploymentTarget row, IDataProtectionProvider protection) => string.IsNullOrEmpty(row.ProtectedCredentials) ? new()
        : JsonSerializer.Deserialize<DeploymentCredentials>(protection.CreateProtector(ConfigurationProtectionPurpose, row.Id).Unprotect(row.ProtectedCredentials), Json) ?? new();
    private DeploymentTargetView ToView(DeploymentTarget row)
    {
        DeploymentCredentials secret;
        try { secret = ReadSecrets(row); } catch (CryptographicException) { secret = new(); }
        return new(row.Id, row.Name, row.Description, row.ExecutorKey, row.ExecutorRevision, row.Endpoint, row.Port,
            row.Username, row.AuthenticationMode, row.Enabled, row.TlsFingerprint, row.ConfigRevision,
            JsonSerializer.Deserialize<DeploymentTargetConfiguration>(row.ConfigurationJson, Json) ?? new(),
            !string.IsNullOrEmpty(secret.Password), !string.IsNullOrEmpty(secret.ApiToken), !string.IsNullOrEmpty(secret.PrivateKey),
            !string.IsNullOrEmpty(secret.PfxPassword), row.LastTestAtUtc, row.LastTestSuccess, row.LastTestMessage,
            row.ProductVersion, row.LastDeploymentAtUtc, row.LastDeploymentStatus);
    }
    internal static string? Validate(DeploymentTargetInput input, DeploymentExecutorDescriptor descriptor)
    {
        if (string.IsNullOrWhiteSpace(input.Name) || input.Name.Length > 100) return "目标名称不能为空，且不能超过 100 个字符。";
        if (string.IsNullOrWhiteSpace(input.Endpoint) || input.Endpoint.Length > 2048) return "请填写目标地址。";
        if (input.Port is < 0 or > 65535) return "端口必须为 1～65535。";
        if (input.TlsFingerprint?.Length > 256 || input.Password?.Length > 16384 || input.ApiToken?.Length > 16384 || input.PrivateKey?.Length > 65536
            || input.PrivateKeyPassphrase?.Length > 4096 || input.PfxPassword?.Length > 4096) return "凭据或指纹长度超出限制。";
        if (descriptor.AuthenticationModes is { Length: > 0 } modes && !modes.Contains(input.AuthenticationMode)) return "当前执行器不支持此认证方式。";
        if (input.Endpoint.Contains('\n') || input.Endpoint.Contains('\r')) return "目标地址包含无效字符。";
        if (Uri.TryCreate(input.Endpoint, UriKind.Absolute, out var uri) && (!string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment)))
            return "目标地址不能包含账号密码或锚点。";
        if (input.Configuration is null) return "部署配置不能为空。";
        if (descriptor.TargetType == "Synology")
        {
            try { _ = SynologyDsmApiClient.BaseUri(new() { Endpoint = input.Endpoint, Port = input.Port }); }
            catch (ArgumentException) { return "群晖管理地址必须是 HTTPS 地址，不能包含账号密码、查询参数或锚点。"; }
            if (input.Configuration.CertificateDescription is null || input.Configuration.CertificateDescription.Length > 200 ||
                input.Configuration.CertificateDescription.Any(char.IsControl)) return "群晖证书描述不能超过 200 个字符或包含控制字符。";
            if (input.Configuration.RemoteCertificateId is null || input.Configuration.RemoteCertificateId.Length > 128 ||
                input.Configuration.RemoteCertificateId.Any(char.IsControl)) return "群晖证书 ID 格式不正确。";
            if (input.Configuration.BindSites || input.Configuration.SiteIds is { Length: > 0 })
                return "群晖首版保留已有服务关联，不支持修改服务绑定。";
            if (input.Configuration.VerificationPort is < 1 or > 65535) return "HTTPS 验证端口必须为 1～65535。";
        }
        if (input.Configuration.Files is null || input.Configuration.PostCommands is null || input.Configuration.ValidationCommands is null || input.Configuration.SiteIds is null)
            return "文件、命令和站点配置必须为数组。";
        if (input.Configuration.Files.Count > 16 || input.Configuration.PostCommands.Count > 20 || input.Configuration.ValidationCommands.Count > 20) return "文件或命令数量超出限制。";
        if (input.Configuration.ConnectionTimeoutSeconds is < 1 or > 300 || input.Configuration.OperationTimeoutSeconds is < 1 or > 1800) return "连接或操作超时超出允许范围。";
        if (input.Configuration.PostCommands.Concat(input.Configuration.ValidationCommands).Any(x => x is null || string.IsNullOrWhiteSpace(x.Command) || x.Command.Length > 16000 || x.TimeoutSeconds is < 1 or > 1800)) return "命令内容、长度或超时超出允许范围。";
        if (input.Configuration.Files.Any(x => x is null || string.IsNullOrWhiteSpace(x.Role) || string.IsNullOrWhiteSpace(x.FileName))) return "文件角色和文件名不能为空。";
        // 保存、启用与配置导入复用执行器约束，避免把无效 Harbor 配置留到实际替换证书时才发现。
        if (descriptor.TargetType == "Harbor")
        {
            var harborValidation = HarborComposeSshDeploymentExecutor.ValidateConfiguration(input.Configuration);
            if (harborValidation is not null) return harborValidation;
        }
        if (JsonSerializer.Serialize(input.Configuration, Json).Length > 65536) return "部署配置超过允许大小。";
        return null;
    }
}
internal static class DeploymentSafeText
{
    internal static string Redact(string? value, DeploymentCredentials? credentials = null)
    {
        var text = value ?? "";
        if (credentials is not null)
            foreach (var secret in new[] { credentials.Password, credentials.ApiToken, credentials.PrivateKey, credentials.PrivateKeyPassphrase, credentials.PfxPassword })
                if (!string.IsNullOrEmpty(secret)) text = text.Replace(secret, "[REDACTED]", StringComparison.Ordinal);
        return text.Length > 4000 ? text[..4000] + "（已截断）" : text;
    }
}
