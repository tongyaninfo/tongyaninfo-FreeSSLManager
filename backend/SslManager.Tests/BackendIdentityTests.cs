using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using SslManager.Api.Common;
using SslManager.Api.Controllers;
using SslManager.Api.Data;
using SslManager.Api.Models;
using SslManager.Api.Service;
using SslManager.Api.Service.impl;
using Xunit;

namespace SslManager.Tests;

/// <summary>本地内存数据库验证身份约束、密钥存储和主动查看审计，不调用真实云账号。</summary>
public sealed class BackendIdentityTests
{
    [Fact]
    public async Task SetupCreatesOnlyOneAdministratorAndStoresPasswordHash()
    {
        await using var fixture = await Fixture.CreateAsync();
        var first = await fixture.Identity.SetupAsync(new() { Username = "admin", Password = "test-pass", DisplayName = "管理员" }, default);
        var second = await fixture.Identity.SetupAsync(new() { Username = "another", Password = "test-pass" }, default);
        Assert.True(first.Success);
        Assert.Equal("admin", first.Data!.Role);
        Assert.False(second.Success);
        Assert.Equal("CONFLICT", second.Code);
        var stored = await fixture.Db.Users.SingleAsync();
        Assert.NotEqual("test-pass", stored.PasswordHash);
        Assert.Equal(PasswordVerificationResult.Success,
            new PasswordHasher<UserAccount>().VerifyHashedPassword(stored, stored.PasswordHash, "test-pass"));
    }

    [Fact]
    public async Task LastAdministratorCannotBeDisabledOrDowngraded()
    {
        await using var fixture = await Fixture.CreateAsync();
        var setup = await fixture.Identity.SetupAsync(new() { Username = "admin", Password = "test-pass" }, default);
        var id = setup.Data!.Id;
        var disabled = await fixture.Identity.UpdateUserAsync(id, new() { Username = "admin", Role = "admin", Enabled = false }, default);
        var downgraded = await fixture.Identity.UpdateUserAsync(id, new() { Username = "admin", Role = "viewer", Enabled = true }, default);
        Assert.Equal("CONFLICT", disabled.Code);
        Assert.Equal("CONFLICT", downgraded.Code);
        Assert.True((await fixture.Db.Users.SingleAsync()).Enabled);
        await fixture.Identity.CreateUserAsync(new() { Username = "admin2", Password = "other-pass", Role = "admin" }, default);
        var allowed = await fixture.Identity.UpdateUserAsync(id, new() { Username = "admin", Role = "viewer", Enabled = false }, default);
        Assert.True(allowed.Success);
        Assert.Equal("UNAUTHORIZED", (await fixture.Identity.GetCurrentUserAsync(id, default)).Code);
    }

    [Fact]
    public async Task UsernamesAreUniqueIgnoringCaseAndEmptyResetPreservesPassword()
    {
        await using var fixture = await Fixture.CreateAsync();
        var setup = await fixture.Identity.SetupAsync(new() { Username = "Admin", Password = "test-pass" }, default);
        var duplicate = await fixture.Identity.CreateUserAsync(new() { Username = "admin", Password = "other-pass", Role = "viewer" }, default);
        Assert.Equal("CONFLICT", duplicate.Code);
        Assert.True((await fixture.Identity.UpdateUserAsync(setup.Data!.Id, new() { Username = "Admin", Role = "admin", DisplayName = "更新名称" }, default)).Success);
        Assert.True((await fixture.Identity.LoginAsync(new() { Username = "ADMIN", Password = "test-pass" }, default)).Success);
        Assert.Equal("UNAUTHORIZED", (await fixture.Identity.LoginAsync(new() { Username = "Admin", Password = "bad-pass" }, default)).Code);
    }

    [Fact]
    public async Task AuthenticatedUserCanChangePasswordOnlyWithCurrentPassword()
    {
        await using var fixture = await Fixture.CreateAsync();
        var setup = await fixture.Identity.SetupAsync(new() { Username = "admin", Password = "old-pass" }, default);
        var userId = setup.Data!.Id;

        var wrong = await fixture.Identity.ChangePasswordAsync(userId,
            new() { CurrentPassword = "wrong-pass", NewPassword = "new-pass" }, default);
        Assert.Equal("VALIDATION", wrong.Code);
        Assert.True((await fixture.Identity.LoginAsync(new() { Username = "admin", Password = "old-pass" }, default)).Success);

        var same = await fixture.Identity.ChangePasswordAsync(userId,
            new() { CurrentPassword = "old-pass", NewPassword = "old-pass" }, default);
        Assert.Equal("VALIDATION", same.Code);

        var changed = await fixture.Identity.ChangePasswordAsync(userId,
            new() { CurrentPassword = "old-pass", NewPassword = "new-pass" }, default);
        Assert.True(changed.Success);
        Assert.False((await fixture.Identity.LoginAsync(new() { Username = "admin", Password = "old-pass" }, default)).Success);
        Assert.True((await fixture.Identity.LoginAsync(new() { Username = "admin", Password = "new-pass" }, default)).Success);
    }

    [Fact]
    public async Task CloudSecretsAreEncryptedMaskedAndNotSerializedByInternalCredentials()
    {
        await using var fixture = await Fixture.CreateAsync();
        var created = await fixture.Accounts.CreateAsync(Input(), default);
        Assert.True(created.Success);
        var stored = await fixture.Db.CloudAccounts.SingleAsync();
        Assert.DoesNotContain("example-access-key", stored.ProtectedAccessKeyId);
        Assert.DoesNotContain("example-secret-key", stored.ProtectedAccessKeySecret);
        var credentials = await fixture.Accounts.GetCredentialsAsync(created.Data!.Id, default);
        Assert.Equal("example-access-key", credentials.Data!.AccessKeyId);
        Assert.Equal("example-secret-key", credentials.Data.AccessKeySecret);
        var page = await fixture.Accounts.ListAsync(1, 20, default);
        var publicJson = JsonSerializer.Serialize(page);
        Assert.DoesNotContain("example-access-key", publicJson);
        Assert.DoesNotContain("example-secret-key", publicJson);
        Assert.Contains("********", page.Data!.Items[0].AccessKeyIdMasked);
        Assert.DoesNotContain("example-secret-key", JsonSerializer.Serialize(credentials));
        Assert.DoesNotContain("example-secret-key", credentials.Data.ToString());
    }

    [Fact]
    public async Task EmptyKeysKeepExistingValuesAndWhitespaceDoesNotOverwrite()
    {
        await using var fixture = await Fixture.CreateAsync();
        var created = await fixture.Accounts.CreateAsync(Input(), default);
        var update = Input();
        update.AccessKeyId = "";
        update.AccessKeySecret = "";
        update.Name = "已修改名称";
        Assert.True((await fixture.Accounts.UpdateAsync(created.Data!.Id, update, default)).Success);
        update.AccessKeySecret = "   ";
        Assert.Equal("VALIDATION", (await fixture.Accounts.UpdateAsync(created.Data.Id, update, default)).Code);
        var secret = await fixture.Accounts.RevealSecretsAsync(created.Data.Id, default);
        Assert.Equal("example-access-key", secret.Data!.AccessKeyId);
        Assert.Equal("example-secret-key", secret.Data.AccessKeySecret);
        update.AccessKeySecret = "";
        update.Provider = "Aliyun";
        Assert.Equal("CONFLICT", (await fixture.Accounts.UpdateAsync(created.Data.Id, update, default)).Code);
    }

    [Fact]
    public async Task AliyunContactIdIsPersistedAndPassedToInternalCredentials()
    {
        await using var fixture = await Fixture.CreateAsync();
        var input = Input();
        input.Provider = "Aliyun";
        input.AliyunContactId = "519580";
        var created = await fixture.Accounts.CreateAsync(input, default);

        Assert.True(created.Success);
        Assert.Equal("519580", created.Data!.AliyunContactId);
        Assert.Equal("519580", (await fixture.Accounts.GetCredentialsAsync(created.Data.Id, default)).Data!.AliyunContactId);
        Assert.Equal("519580", (await fixture.Accounts.ListAsync(1, 20, default)).Data!.Items[0].AliyunContactId);
    }

    [Fact]
    public async Task TencentAccountDoesNotRetainAliyunContactId()
    {
        await using var fixture = await Fixture.CreateAsync();
        var input = Input();
        input.AliyunContactId = "519580";
        var created = await fixture.Accounts.CreateAsync(input, default);

        Assert.True(created.Success);
        Assert.Equal("", created.Data!.AliyunContactId);
        Assert.Equal("", (await fixture.Accounts.GetCredentialsAsync(created.Data.Id, default)).Data!.AliyunContactId);
    }

    [Fact]
    public async Task AdministratorRevealIncludesNoCacheAndAuditEvenForDisabledAccount()
    {
        await using var fixture = await Fixture.CreateAsync();
        var input = Input();
        input.Enabled = false;
        var created = await fixture.Accounts.CreateAsync(input, default);
        var context = new DefaultHttpContext { User = new ClaimsPrincipal(new ClaimsIdentity([
            new Claim(ClaimTypes.NameIdentifier, "admin-id"), new Claim(ClaimTypes.Name, "admin"),
            new Claim(ClaimTypes.Role, "admin")], "test")) };
        var controller = new CloudAccountsController(fixture.Accounts, fixture.Db, new GuidIdGenerator(), new UnusedProviderResolver())
            { ControllerContext = new ControllerContext { HttpContext = context } };
        var response = Assert.IsType<OkObjectResult>(await controller.RevealSecrets(created.Data!.Id, default));
        var result = Assert.IsType<ApiResult<CloudAccountSecrets>>(response.Value);
        Assert.Equal("example-secret-key", result.Data!.AccessKeySecret);
        Assert.Equal("no-store", context.Response.Headers.CacheControl.ToString());
        Assert.Equal("no-cache", context.Response.Headers.Pragma.ToString());
        var audit = await fixture.Db.AuditLogs.SingleAsync();
        Assert.Equal("RevealCloudSecrets", audit.Action);
        Assert.Equal(created.Data.Id, audit.ResourceId);
        Assert.Equal("admin-id", audit.UserId);
        Assert.Equal("admin", audit.Username);
        Assert.DoesNotContain("example-secret-key", JsonSerializer.Serialize(audit));
        Assert.Equal("FORBIDDEN", (await fixture.Accounts.GetCredentialsAsync(created.Data.Id, default)).Code);
        Assert.Empty((await fixture.Accounts.ListOptionsAsync(default)).Data!);
    }

    [Fact]
    public async Task InvalidAndVeryLargePagesReturnBusinessResultsWithoutOverflow()
    {
        await using var fixture = await Fixture.CreateAsync();
        Assert.Equal("VALIDATION", (await fixture.Accounts.ListAsync(0, 20, default)).Code);
        Assert.Equal("VALIDATION", (await fixture.Accounts.ListAsync(1, 101, default)).Code);
        Assert.Empty((await fixture.Accounts.ListAsync(int.MaxValue, 100, default)).Data!.Items);
    }

    private static CloudAccountInput Input() => new() { Name = "测试账号", Provider = "TencentCloud",
        AccessKeyId = "example-access-key", AccessKeySecret = "example-secret-key" };

    private sealed class UnusedProviderResolver : ICloudProviderResolver
    {
        public ApiResult<ICloudCertificateService> ResolveCertificate(string provider) =>
            ApiResult<ICloudCertificateService>.Fail("UNUSED", "测试未覆盖云联系人接口");
        public ApiResult<IDnsProvider> ResolveDns(string provider) =>
            ApiResult<IDnsProvider>.Fail("UNUSED", "测试未覆盖 DNS 接口");
    }

    private sealed class Fixture(SqliteConnection connection, AppDbContext db) : IAsyncDisposable
    {
        public AppDbContext Db { get; } = db;
        public IdentityService Identity { get; } = new(db, new PasswordHasher<UserAccount>(), new GuidIdGenerator());
        public CloudAccountStore Accounts { get; } = new(db, new EphemeralDataProtectionProvider(), new GuidIdGenerator());
        public static async Task<Fixture> CreateAsync()
        {
            var connection = new SqliteConnection("Data Source=:memory:");
            await connection.OpenAsync();
            var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseSqlite(connection).Options);
            await db.Database.EnsureCreatedAsync();
            return new(connection, db);
        }
        public async ValueTask DisposeAsync()
        {
            await Db.DisposeAsync();
            await connection.DisposeAsync();
        }
    }
}
