using System.Net.Mail;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SslManager.Api.Common;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;

return await CloudProbe.RunAsync(args);

/// <summary>手动、显式执行的隔离云验证；原业务库只读，私钥和下载包绝不明文落盘。</summary>
internal static class CloudProbe
{
    // 不内置任何真实测试域名；默认使用 RFC 2606 保留域名。真实执行必须用 --domain 指定自己持有的域名。
    private const string DefaultDomain = "example.com";
    private const string BaselineMigration = "20261102133402_AddMcpServices";
    private const string ProtectionPurpose = "SslManager.CloudAccount.v1";
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static async Task<int> RunAsync(string[] args)
    {
        ProbeOptions options;
        try { options = ProbeOptions.Parse(args); }
        catch (ArgumentException)
        {
            Console.Error.WriteLine("参数无效。使用 --help 查看说明；参数和秘密值不会回显。");
            return 2;
        }
        if (options.Help) { Help(); return 0; }
        if (options.ParserSelfTest)
        {
            // 仅在内存中检查合成文本，不打开真实凭据文件，也不初始化数据库或客户端。
            var passed = TokenParserSelfTest() && AcmeAccountParserSelfTest();
            Console.WriteLine(passed ? "CREDENTIALS_PARSER_SELF_TEST_PASSED" : "CREDENTIALS_PARSER_SELF_TEST_FAILED");
            return passed ? 0 : 1;
        }
        var domain = options.Domain ?? DefaultDomain;
        // 不带显式执行参数时连凭据、原库和输出目录都不打开，避免探测命令意外产生副作用。
        if (!options.Execute)
        {
            Console.WriteLine(JsonSerializer.Serialize(new { mode = "plan", target = options.Target, domain,
                resume = options.Resume, autoCleanup = options.AutoCleanup, writesEnabled = false,
                existingAcmeAccountFileRequired = options.Target != "tencent",
                note = "添加 --execute 后才读取凭据、初始化独立数据库并调用云服务。" }, Json));
            return 0;
        }
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(options.TimeoutMinutes));
        Console.CancelKeyPress += (_, value) => { value.Cancel = true; cancellation.Cancel(); };
        try { return await ExecuteAsync(options, domain, cancellation.Token); }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("本次等待已停止；原申请及加密材料保留，使用同一输出目录和 --resume 继续核对，不会重新创建申请。");
            return 3;
        }
        catch (ProbeException exception)
        {
            Console.Error.WriteLine("探测停止：" + SafeCode(exception.Code) + "。现场已保留，没有重试创建订单。");
            return 4;
        }
        catch (Exception exception)
        {
            // 异常正文可能包含连接信息、云响应或本地路径，控制台只输出异常类型。
            Console.Error.WriteLine("探测因基础设施异常停止：" + exception.GetType().Name + "。现场已保留，请检查独立库并使用 --resume。");
            return 5;
        }
    }

    private static async Task<int> ExecuteAsync(ProbeOptions options, string domain, CancellationToken ct)
    {
        // ACME 必须显式导入用户已有账号；缺少材料时在任何其他路径读取和目录初始化前停止。
        var acmeAccount = options.Target == "tencent" ? null : await ReadAcmeAccountFileAsync(options.AcmeAccountFile, options.Target, ct);
        var output = Path.GetFullPath(Required(options.OutputDirectory));
        var sourceDb = Path.GetFullPath(Required(options.SourceDb));
        var sourceKeys = Path.GetFullPath(Required(options.SourceKeys));
        var credentialsFile = Path.GetFullPath(Required(options.CredentialsFile));
        if (!File.Exists(sourceDb) || !Directory.Exists(sourceKeys) || !File.Exists(credentialsFile) ||
            Within(output, sourceKeys) || Within(sourceKeys, output) || Within(sourceDb, output) ||
            Within(credentialsFile, output)) throw new ProbeException("UNSAFE_OR_MISSING_PATH");
        var database = Path.Combine(output, "probe.db"); var keys = Path.Combine(output, "keys");
        var existing = File.Exists(database);
        if (existing && !options.Resume) throw new ProbeException("EXISTING_OUTPUT_REQUIRES_RESUME");
        if (!existing && options.Resume) throw new ProbeException("RESUME_DATABASE_MISSING");
        if (existing && (!Directory.Exists(keys) || Directory.GetFiles(keys, "*.xml").Length == 0))
            throw new ProbeException("RESUME_ORIGINAL_KEYS_MISSING");
        PrivateDirectory(output); PrivateDirectory(keys);

        var services = new ServiceCollection();
        services.AddLogging(logging => logging.ClearProviders());
        services.AddDataProtection().SetApplicationName("SslManager").PersistKeysToFileSystem(new DirectoryInfo(keys));
        services.AddDbContext<AppDbContext>(settings => settings.UseSqlite(new SqliteConnectionStringBuilder
        { DataSource = database, Mode = existing ? SqliteOpenMode.ReadWrite : SqliteOpenMode.ReadWriteCreate }.ConnectionString));
        services.AddSingleton<IIdGenerator, GuidIdGenerator>();
        services.AddScoped<ICloudAccountStore, CloudAccountStore>();
        services.AddScoped<ICertificateIssuanceStore, CertificateIssuanceStore>();
        services.AddScoped<DomainManagementService>(); services.AddScoped<CertificateManagementService>();
        services.AddScoped<TencentCloudService>(); services.AddScoped<AliyunCloudService>();
        services.AddScoped<CloudflareCloudService>(); services.AddScoped<AcmeCloudService>();
        services.AddScoped<ICloudProviderResolver, CloudProviderResolver>();
        services.AddScoped<IAcmeDnsPropagationChecker, AcmeDnsPropagationChecker>();
        services.AddSingleton<TencentCloudApiClient>(); services.AddSingleton<AliyunApiClient>();
        services.AddSingleton<CloudflareApiClient>(); services.AddSingleton<AcmeProtocolClient>();
        foreach (var name in new[] { "TencentCloudApi", "AliyunApi", "CloudflareApi", "AcmeProtocol", "AcmeDns", "CloudCertificateDownload" })
            services.AddHttpClient(name, client => client.Timeout = TimeSpan.FromSeconds(name == "CloudCertificateDownload" ? 60 : 30))
                .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false }).RemoveAllLoggers();
        await using var provider = services.BuildServiceProvider();
        await using var scope = provider.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var sourceBaseline = db.Database.GetMigrations().TakeWhile(id => string.CompareOrdinal(id, BaselineMigration) <= 0).ToArray();
        if (sourceBaseline.Length != 10 || sourceBaseline[^1] != BaselineMigration)
            throw new ProbeException("SOURCE_BASELINE_DEFINITION_INVALID");
        if (!existing)
        {
            // 仅对全新隔离库执行本构建的明确迁移终点，原业务连接从不交给 EF。
            var target = db.Database.GetMigrations().LastOrDefault() ?? throw new ProbeException("MIGRATIONS_MISSING");
            await db.GetService<IMigrator>().MigrateAsync(target, ct);
            SecureFile(database);
        }
        else
        {
            var applied = (await db.Database.GetAppliedMigrationsAsync(ct)).ToArray();
            var known = db.Database.GetMigrations().ToArray();
            if (!applied.SequenceEqual(known)) throw new ProbeException("RESUME_DATABASE_SCHEMA_MISMATCH");
        }

        var accountStore = scope.ServiceProvider.GetRequiredService<ICloudAccountStore>();
        var cfAccount = await GetAccountAsync(db, "Cloudflare", "probe-cloudflare", ct);
        if (cfAccount is null)
        {
            var token = await ReadCloudflareTokenAsync(credentialsFile, ct);
            cfAccount = Must(await accountStore.CreateAsync(new() { Name = "probe-cloudflare", Provider = "Cloudflare",
                AccessKeySecret = token, UseForCertificates = false, UseForDns = true }, ct)).Id;
        }
        string certificateAccount;
        if (options.Target == "tencent")
        {
            certificateAccount = await GetAccountAsync(db, "TencentCloud", "probe-tencent", ct) ?? "";
            if (certificateAccount.Length == 0)
            {
                var imported = await ReadSourceTencentAsync(sourceDb, sourceKeys, options.TencentAccountId, sourceBaseline, decryptKeys: true, ct);
                certificateAccount = Must(await accountStore.CreateAsync(new() { Name = "probe-tencent", Provider = "TencentCloud",
                    AccessKeyId = imported.AccessKeyId, AccessKeySecret = imported.AccessKeySecret,
                    ContactEmail = imported.Email, ContactName = imported.ContactName, ContactPhone = imported.ContactPhone,
                    UseForCertificates = true, UseForDns = false }, ct)).Id;
            }
        }
        else
        {
            var accountName = "probe-" + options.Target;
            certificateAccount = await GetAccountAsync(db, "Acme", accountName, ct) ?? "";
            if (certificateAccount.Length == 0)
            {
                if (!string.IsNullOrEmpty(options.Email) && (!MailAddress.TryCreate(options.Email, out var mail) || mail.Address != options.Email))
                    throw new ProbeException("ACME_CONTACT_EMAIL_INVALID");
                certificateAccount = Must(await accountStore.CreateAsync(new() { Name = accountName, Provider = "Acme",
                    ContactEmail = options.Email ?? "", UseForCertificates = true, UseForDns = false,
                    AccessKeyId = acmeAccount!.AccountUrl, AccessKeySecret = acmeAccount.AccountPrivateKeyPem,
                    AcmeDirectoryUrl = acmeAccount.DirectoryUrl }, ct)).Id;
            }
            else
            {
                var original = Must(await accountStore.GetCredentialsAsync(certificateAccount, ct));
                if (original.AcmeDirectoryUrl != acmeAccount!.DirectoryUrl || original.AccessKeyId != acmeAccount.AccountUrl ||
                    !SameAccountKey(original.AccessKeySecret, acmeAccount.AccountPrivateKeyPem))
                    throw new ProbeException("RESUME_ACME_ACCOUNT_IDENTITY_CHANGED");
            }
        }

        var domains = scope.ServiceProvider.GetRequiredService<DomainManagementService>();
        Must(await domains.SyncAsync(cfAccount, ct));
        var available = await db.Domains.AsNoTracking().Where(row => row.AccountId == cfAccount && row.Status == "active").ToListAsync(ct);
        var zone = available.Where(row => domain == row.Name || domain.EndsWith("." + row.Name, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(row => row.Name.Length).FirstOrDefault() ?? throw new ProbeException("ACTIVE_CLOUDFLARE_ZONE_MISSING");
        var service = scope.ServiceProvider.GetRequiredService<CertificateManagementService>();
        // 即使上次在返回前中断，也从同账号与域名的持久意图恢复，绝不再次下单。
        var certificate = await db.Certificates.Where(row => row.AccountId == certificateAccount && row.Domain == domain)
            .OrderByDescending(row => row.SyncedAtUtc).FirstOrDefaultAsync(ct);
        if (certificate is null)
        {
            var applied = await service.ApplyAsync(new(certificateAccount, domain, Alias: "CloudProbe " + options.Target,
                ValidationMode: "ManagedDns", AutoCleanup: options.AutoCleanup, DnsZoneId: zone.Id), ct);
            if (!applied.Success || applied.Data is null)
            {
                certificate = await db.Certificates.Where(row => row.AccountId == certificateAccount && row.Domain == domain)
                    .OrderByDescending(row => row.SyncedAtUtc).FirstOrDefaultAsync(ct);
                if (certificate is not null) await SaveSummaryAsync(output, options.Target, certificate, SafeCode(applied.Code), null, ct);
                throw new ProbeException(applied.Code);
            }
            certificate = applied.Data;
        }
        else if (options.AutoCleanupSpecified && certificate.AutoCleanup != options.AutoCleanup)
        {
            // 恢复严格沿用原申请的删除授权，不能通过命令行切换后扩大旧申请清理范围。
            throw new ProbeException("RESUME_AUTO_CLEANUP_CHANGED");
        }
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            await db.Entry(certificate).ReloadAsync(ct);
            var job = await db.CertificateJobs.Where(row => row.CertificateId == certificate.Id && row.Kind == "Apply")
                .OrderByDescending(row => row.CreatedAtUtc).FirstOrDefaultAsync(ct);
            if (job is null) throw new ProbeException("ORIGINAL_APPLICATION_JOB_MISSING");
            if (certificate.Status == "Submitting")
            {
                // 通用申请快照提交前中断时，Worker 可从已保存的 ACME OrderUrl 恢复同一订单。
                await service.ProcessJobAsync(job.Id, ct);
                await db.Entry(certificate).ReloadAsync(ct);
                await db.Entry(job).ReloadAsync(ct);
            }
            await SaveSummaryAsync(output, options.Target, certificate, "WAITING", null, ct);
            Console.WriteLine(JsonSerializer.Serialize(new { target = options.Target, localCertificateId = certificate.Id,
                status = SafeCode(certificate.Status), cleanupStatus = SafeCode(certificate.CleanupStatus), timeUtc = DateTime.UtcNow }));
            if (certificate.Status == "Issued" && (!certificate.AutoCleanup || certificate.CleanupStatus == "Completed" && job.Status == "Completed"))
            {
                var download = Must(await service.DownloadAsync(certificate.Id, "nginx", ct));
                // 下载包只在内存中检查，保留的材料由服务写入独立库密文；不把私钥 ZIP 写入输出目录。
                var material = Must(CertificateMaterialHelper.FromArchive(download.Content, certificate.Id, domain));
                CryptographicOperations.ZeroMemory(download.Content);
                await SaveSummaryAsync(output, options.Target, certificate, "VERIFIED", material.Metadata, ct);
                Console.WriteLine(JsonSerializer.Serialize(new { target = options.Target, status = "VERIFIED", domain,
                    fingerprint = material.Metadata.Fingerprint, isStaging = certificate.IsStaging,
                    autoCleanup = certificate.AutoCleanup, cleanupStatus = certificate.CleanupStatus, privateKeyWrittenAsPlaintext = false }));
                return 0;
            }
            if (certificate.Status is "SubmissionUnknown" or "Submitting" or "Failed" or "Cancelled" or "Revoked" or "Expired")
            {
                await SaveSummaryAsync(output, options.Target, certificate, "EXISTING_APPLICATION_" + certificate.Status.ToUpperInvariant(), null, ct);
                throw new ProbeException("EXISTING_APPLICATION_" + certificate.Status.ToUpperInvariant());
            }
            if (job.Status is "SubmissionUnknown" or "Failed") throw new ProbeException("ORIGINAL_APPLICATION_JOB_" + job.Status.ToUpperInvariant());
            if (job.Status == "Completed" && certificate.Status == "Issued" && certificate.AutoCleanup && certificate.CleanupStatus != "Completed")
                throw new ProbeException("ORIGINAL_CLEANUP_INCOMPLETE");
            if (job.NextRunAtUtc <= DateTime.UtcNow) await service.ProcessJobAsync(job.Id, ct);
            await Task.Delay(TimeSpan.FromSeconds(10), ct);
        }
    }

    private static async Task<SourceAccount> ReadSourceTencentAsync(string database, string keysDirectory, string? chosenId,
        IReadOnlyList<string> expectedHistory, bool decryptKeys, CancellationToken ct)
    {
        await using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database, Mode = SqliteOpenMode.ReadOnly }.ConnectionString);
        await connection.OpenAsync(ct);
        await using (var history = connection.CreateCommand())
        {
            history.CommandText = "SELECT MigrationId FROM __EFMigrationsHistory ORDER BY MigrationId";
            var migrations = new List<string>();
            await using var reader = await history.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) migrations.Add(reader.GetString(0));
            if (!migrations.SequenceEqual(expectedHistory, StringComparer.Ordinal))
                throw new ProbeException("SOURCE_DATABASE_BASELINE_MISMATCH");
        }
        await using var command = connection.CreateCommand();
        // 只选读取基线字段；来源库绝不交给新版本 AppDbContext，避免模型演进触发实际升级。
        command.CommandText = """
            SELECT a.Id,a.ProtectedAccessKeyId,a.ProtectedAccessKeySecret,a.ContactEmail,a.ContactName,a.ContactPhone
            FROM CloudAccounts a WHERE a.Provider='TencentCloud' AND a.Enabled=1 AND a.UseForCertificates=1
              AND ($chosen='' OR a.Id=$chosen) ORDER BY a.Id LIMIT 1
            """;
        command.Parameters.AddWithValue("$chosen", chosenId ?? "");
        await using var account = await command.ExecuteReaderAsync(ct);
        if (!await account.ReadAsync(ct)) throw new ProbeException("SOURCE_TENCENT_ACCOUNT_MISSING");
        var id = account.GetString(0); var email = account.GetString(3);
        if (!decryptKeys) return new("", "", email, account.GetString(4), account.GetString(5));
        if (Directory.GetFiles(keysDirectory, "*.xml").Length == 0) throw new ProbeException("SOURCE_KEYS_MISSING");
        var protection = DataProtectionProvider.Create(new DirectoryInfo(keysDirectory), builder =>
            builder.SetApplicationName("SslManager").DisableAutomaticKeyGeneration());
        var protector = protection.CreateProtector(ProtectionPurpose, id);
        return new(protector.Unprotect(account.GetString(1)), protector.Unprotect(account.GetString(2)), email, account.GetString(4), account.GetString(5));
    }

    private static async Task<string> ReadCloudflareTokenAsync(string path, CancellationToken ct)
    {
        var text = await File.ReadAllTextAsync(path, ct);
        return ParseCloudflareToken(text);
    }

    private static async Task<ImportedAcmeAccount> ReadAcmeAccountFileAsync(string? path, string target, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(path)) throw new ProbeException("ACME_ACCOUNT_FILE_REQUIRED");
        if (!Path.IsPathFullyQualified(path) || !File.Exists(path) || new FileInfo(path).Length > 65536)
            throw new ProbeException("ACME_ACCOUNT_FILE_INVALID");
        return ParseAcmeAccountFile(await File.ReadAllTextAsync(path, ct), target);
    }

    /// <summary>只校验用户提供的目录、账号 URL 与受支持原始私钥；不生成、注册或更新任何外部账号。</summary>
    private static ImportedAcmeAccount ParseAcmeAccountFile(string document, string target)
    {
        try
        {
            var settings = new JsonSerializerOptions(Json) { UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
            var account = JsonSerializer.Deserialize<ImportedAcmeAccount>(document, settings);
            var expected = target == "acme-staging" ? AcmeProtocolClient.StagingDirectory : AcmeProtocolClient.ProductionDirectory;
            if (account is null || account.DirectoryUrl != expected || string.IsNullOrWhiteSpace(account.AccountPrivateKeyPem) ||
                !AcmeProtocolClient.IsAllowedResource(account.DirectoryUrl, account.AccountUrl) ||
                !new Uri(account.AccountUrl).AbsolutePath.StartsWith("/acme/acct/", StringComparison.Ordinal))
                throw new ProbeException("ACME_ACCOUNT_FILE_IDENTITY_INVALID");
            _ = PublicAccountKey(account.AccountPrivateKeyPem);
            return account;
        }
        catch (Exception exception) when (exception is JsonException or CryptographicException or ArgumentException)
        { throw new ProbeException("ACME_ACCOUNT_FILE_INVALID"); }
    }

    private static bool SameAccountKey(string left, string right)
        => PublicAccountKey(left).AsSpan().SequenceEqual(PublicAccountKey(right));

    private static byte[] PublicAccountKey(string pem)
    {
        try
        {
            using var ec = ECDsa.Create(); ec.ImportFromPem(pem);
            var parameters = ec.ExportParameters(true);
            var supported = parameters.Curve.Oid.Value is "1.2.840.10045.3.1.7" or "1.3.132.0.34" && parameters.D is { Length: > 0 };
            if (parameters.D is not null) CryptographicOperations.ZeroMemory(parameters.D);
            if (!supported) throw new ProbeException("ACME_ACCOUNT_KEY_UNSUPPORTED");
            return ec.ExportSubjectPublicKeyInfo();
        }
        catch (Exception exception) when (exception is CryptographicException or ArgumentException)
        {
            using var rsa = RSA.Create(); rsa.ImportFromPem(pem);
            var parameters = rsa.ExportParameters(true);
            var supported = rsa.KeySize is 2048 or 3072 or 4096 && parameters.D is { Length: > 0 };
            foreach (var bytes in new[] { parameters.D, parameters.P, parameters.Q, parameters.DP, parameters.DQ, parameters.InverseQ })
                if (bytes is not null) CryptographicOperations.ZeroMemory(bytes);
            if (!supported) throw new ProbeException("ACME_ACCOUNT_KEY_UNSUPPORTED");
            return rsa.ExportSubjectPublicKeyInfo();
        }
    }

    private static bool AcmeAccountParserSelfTest()
    {
        // 合成测试密钥仅用于内存解析验证，从不作为真实外部 ACME 账号资料保存或提交。
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var account = new ImportedAcmeAccount(AcmeProtocolClient.StagingDirectory,
            "https://acme-staging-v02.api.letsencrypt.org/acme/acct/12345", key.ExportPkcs8PrivateKeyPem());
        try
        {
            var read = ParseAcmeAccountFile(JsonSerializer.Serialize(account, Json), "acme-staging");
            if (read.AccountUrl != account.AccountUrl || !SameAccountKey(read.AccountPrivateKeyPem, account.AccountPrivateKeyPem)) return false;
            using var p384 = ECDsa.Create(ECCurve.NamedCurves.nistP384);
            using var rsa = RSA.Create(2048);
            foreach (var pem in new[] { p384.ExportPkcs8PrivateKeyPem(), rsa.ExportPkcs8PrivateKeyPem() })
                _ = ParseAcmeAccountFile(JsonSerializer.Serialize(account with { AccountPrivateKeyPem = pem }, Json), "acme-staging");
            var rejected = new[]
            {
                JsonSerializer.Serialize(account with { DirectoryUrl = AcmeProtocolClient.ProductionDirectory }, Json),
                JsonSerializer.Serialize(account with { AccountUrl = "https://untrusted.invalid/acme/acct/12345" }, Json),
                JsonSerializer.Serialize(account with { AccountPrivateKeyPem = key.ExportSubjectPublicKeyInfoPem() }, Json),
                "{\"directoryUrl\":\"unsupported\",\"unknownSecret\":\"synthetic\"}"
            };
            foreach (var document in rejected)
            {
                try { ParseAcmeAccountFile(document, "acme-staging"); return false; }
                catch (ProbeException) { }
            }
            return true;
        }
        catch (ProbeException) { return false; }
    }

    /// <summary>只接受 API 令牌段内完整 Token= 行，不假设真实令牌恒为某一种长度，也不读取 R2 密钥。</summary>
    private static string ParseCloudflareToken(string text)
    {
        var section = Regex.Match(text, @"(?m)^\s*\[API\s*令牌\]\s*$");
        if (!section.Success) throw new ProbeException("CLOUDFLARE_TOKEN_SECTION_MISSING");
        var tail = text[(section.Index + section.Length)..];
        var next = Regex.Match(tail, @"(?m)^\s*\[[^\]\r\n]+\]\s*$");
        if (next.Success) tail = tail[..next.Index];
        var token = Regex.Match(tail, @"(?m)^[ \t]*Token[ \t]*=[ \t]*(?<quote>`?)(?<token>[A-Za-z0-9_-]{35,256})\k<quote>[ \t]*\r?$");
        if (!token.Success) throw new ProbeException("CLOUDFLARE_API_TOKEN_MISSING");
        return token.Groups["token"].Value;
    }

    private static bool TokenParserSelfTest()
    {
        var synthetic = new string('A', 51) + "_-";
        var accepted = new (string Input, string Expected)[]
        {
            ("[API 令牌]\nToken=" + synthetic + "\n[R2 S3 兼容凭证]\nToken=" + new string('B', 53), synthetic),
            ("[API 令牌]\r\nToken=`" + synthetic + "`\r\n[R2 S3 兼容凭证]\r\n", synthetic),
            ("[API 令牌]\nToken=" + new string('C', 35), new string('C', 35)),
            ("[API 令牌]\nToken=" + new string('D', 256), new string('D', 256))
        };
        foreach (var test in accepted)
        {
            try { if (ParseCloudflareToken(test.Input) != test.Expected) return false; }
            catch (ProbeException) { return false; }
        }
        var rejected = new[]
        {
            "[API 令牌]\nToken=" + new string('A', 34),
            "[API 令牌]\nToken=" + new string('A', 257),
            "[API 令牌]\nOther=" + synthetic + "\n[R2 S3 兼容凭证]\nToken=" + synthetic,
            "[R2 S3 兼容凭证]\nToken=" + synthetic,
            "[API 令牌]\nToken=" + synthetic + " trailing-comment",
            "[API 令牌]\nToken=`" + synthetic,
            "[API 令牌]\nToken=" + new string('密', 53)
        };
        foreach (var test in rejected)
        {
            try { ParseCloudflareToken(test); return false; }
            catch (ProbeException) { }
        }
        return true;
    }

    private static Task<string?> GetAccountAsync(AppDbContext db, string provider, string name, CancellationToken ct) =>
        db.CloudAccounts.Where(row => row.Provider == provider && row.Name == name).Select(row => row.Id).SingleOrDefaultAsync(ct);

    private static async Task SaveSummaryAsync(string directory, string target, ManagedCertificate certificate, string code, CertificateMaterialMetadata? material, CancellationToken ct)
    {
        var path = Path.Combine(directory, "summary.json");
        var summary = File.Exists(path) ? JsonSerializer.Deserialize<Dictionary<string, ProbeSummary>>(await File.ReadAllTextAsync(path, ct), Json) ?? [] : [];
        summary.TryGetValue(target, out var previous);
        summary[target] = new(target, certificate.Domain, certificate.Id, certificate.Provider,
            certificate.CertificateId, SafeCode(certificate.Status), SafeCode(code), certificate.IsStaging,
            certificate.HasPrivateKey, certificate.AutoCleanup, SafeCode(certificate.CleanupStatus), certificate.NotBeforeUtc, certificate.NotAfterUtc,
            material?.Fingerprint ?? previous?.Fingerprint, DateTime.UtcNow);
        await File.WriteAllTextAsync(path, JsonSerializer.Serialize(summary, Json), ct);
        SecureFile(path);
    }

    private static T Must<T>(ApiResult<T> result) => result.Success && result.Data is not null ? result.Data : throw new ProbeException(result.Code);
    private static string Required(string? value) => string.IsNullOrWhiteSpace(value) ? throw new ProbeException("REQUIRED_PATH_MISSING") : value;
    private static string SafeCode(string value) => Regex.IsMatch(value, @"^[A-Za-z0-9_.:-]{1,160}$") ? value : "UNCLASSIFIED";
    private static bool Within(string candidate, string root)
    {
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        return candidate.Equals(root, comparison) || candidate.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, comparison);
    }
    private static void PrivateDirectory(string path)
    {
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(path);
        else Directory.CreateDirectory(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    }
    private static void SecureFile(string path)
    { if (!OperatingSystem.IsWindows()) File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
    private static void Help() => Console.WriteLine("""
        CloudProbe: 显式手动执行的隔离证书申请验证。
        --run tencent|acme-staging|acme-production [--domain <本次验证域名>]
        --domain 未指定时使用 RFC 2606 保留域名 example.com；真实执行请传入自己持有且已接入的域名，工具不内置任何真实测试域名。
        --credentials-file <Cloudflare凭据Markdown绝对路径>
        --source-db <原业务SQLite绝对路径> --source-keys <原DataProtection密钥目录>
        --output-directory <独立探测目录> [--email <ACME邮箱>] [--tencent-account-id <来源账号ID>]
        ACME 另须 --acme-account-file <包含 directoryUrl/accountUrl/accountPrivateKeyPem 的用户既有账号 JSON>
        账号私钥支持 RSA 2048/3072/4096 或 EC P-256/P-384；不会生成替代账号私钥。
        [--timeout-minutes 30] [--auto-cleanup [true|false]] [--resume] [--execute]
        --self-test-credentials-parser 只用内存合成文本检查 CF 令牌及既有 ACME 账号解析，不读取文件或调用云端。
        没有 --execute 时仅输出计划，不读取凭据或数据库，也不创建文件。
        三类验证可共用一个输出目录，后续执行必须加 --resume，已有申请始终复用。
        验证记录默认保留；--auto-cleanup 仅授权现有 Worker 精确清理本轮拥有的临时 DNS。
        不会部署、吊销、删除证书，也不写出明文私钥 ZIP。
        不会创建、注册或维护外部 ACME 账号；缺少用户既有账号材料时立即停止。
        """);

    private sealed class ProbeException(string code) : Exception { public string Code { get; } = code; }
    private sealed record SourceAccount(string AccessKeyId, string AccessKeySecret, string Email, string ContactName, string ContactPhone)
    { public override string ToString() => "SourceAccount { 凭据已隐藏 }"; }
    private sealed record ImportedAcmeAccount(string DirectoryUrl, string AccountUrl, string AccountPrivateKeyPem)
    { public override string ToString() => "ImportedAcmeAccount { 既有账号私钥已隐藏 }"; }
    private sealed record ProbeSummary(string Target, string Domain, string LocalCertificateId, string Provider,
        string RemoteCertificateId, string Status, string Code, bool IsStaging, bool HasPrivateKey, bool AutoCleanup, string CleanupStatus, DateTime? NotBeforeUtc,
        DateTime? NotAfterUtc, string? Fingerprint, DateTime UpdatedAtUtc);

    private sealed class ProbeOptions
    {
        public string Target { get; private set; } = "";
        public string? CredentialsFile { get; private set; }
        public string? SourceDb { get; private set; }
        public string? SourceKeys { get; private set; }
        public string? OutputDirectory { get; private set; }
        public string? Email { get; private set; }
        public string? AcmeAccountFile { get; private set; }
        public string? TencentAccountId { get; private set; }
        public string? Domain { get; private set; }
        public int TimeoutMinutes { get; private set; } = 30;
        public bool Execute { get; private set; }
        public bool Resume { get; private set; }
        public bool AutoCleanup { get; private set; }
        public bool AutoCleanupSpecified { get; private set; }
        public bool Help { get; private set; }
        public bool ParserSelfTest { get; private set; }
        public static ProbeOptions Parse(string[] args)
        {
            var options = new ProbeOptions();
            for (var index = 0; index < args.Length; index++)
            {
                var key = args[index];
                if (key == "--help") { options.Help = true; continue; }
                if (key == "--self-test-credentials-parser") { options.ParserSelfTest = true; continue; }
                if (key == "--execute") { options.Execute = true; continue; }
                if (key == "--resume") { options.Resume = true; continue; }
                if (key == "--auto-cleanup")
                {
                    options.AutoCleanupSpecified = true;
                    if (index + 1 < args.Length && bool.TryParse(args[index + 1], out var cleanup))
                    { options.AutoCleanup = cleanup; index++; }
                    else options.AutoCleanup = true;
                    continue;
                }
                if (++index >= args.Length || args[index].StartsWith("--", StringComparison.Ordinal)) throw new ArgumentException();
                var value = args[index];
                switch (key)
                {
                    case "--run": options.Target = value; break;
                    case "--credentials-file": options.CredentialsFile = value; break;
                    case "--source-db": options.SourceDb = value; break;
                    case "--source-keys": options.SourceKeys = value; break;
                    case "--output-directory": options.OutputDirectory = value; break;
                    case "--email": options.Email = value; break;
                    case "--acme-account-file": options.AcmeAccountFile = value; break;
                    case "--tencent-account-id": options.TencentAccountId = value; break;
                    case "--domain": options.Domain = value; break;
                    case "--timeout-minutes" when int.TryParse(value, out var minutes) && minutes is >= 1 and <= 120:
                        options.TimeoutMinutes = minutes; break;
                    default: throw new ArgumentException();
                }
            }
            if (!options.Help && !options.ParserSelfTest && options.Target is not ("tencent" or "acme-staging" or "acme-production")) throw new ArgumentException();
            // 只接受最普通的 ASCII 域名写法，避免把路径或 URL 当作域名传入。
            if (!options.Help && !options.ParserSelfTest && options.Domain is not null &&
                (options.Domain.Length > 253 || !options.Domain.Contains('.') || options.Domain.Any(ch => char.IsWhiteSpace(ch) || !(char.IsAsciiLetterOrDigit(ch) || ch is '.' or '-'))))
                throw new ArgumentException();
            return options;
        }
    }
}
