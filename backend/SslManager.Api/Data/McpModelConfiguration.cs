using Microsoft.EntityFrameworkCore;
using SslManager.Api.Models.Mcp;

namespace SslManager.Api.Data;

public sealed partial class AppDbContext
{
    private readonly SslManager.Api.Common.IIdGenerator oauthIds = idGenerator ?? new SslManager.Api.Common.GuidIdGenerator();
    private readonly HashSet<object> assignedOAuthIds = new(ReferenceEqualityComparer.Instance);
    public DbSet<McpSettings> McpSettings => Set<McpSettings>();
    public DbSet<McpClient> McpClients => Set<McpClient>();
    public DbSet<McpApiKey> McpApiKeys => Set<McpApiKey>();
    public DbSet<McpAllowRule> McpAllowRules => Set<McpAllowRule>();
    public DbSet<McpInvocationLog> McpInvocationLogs => Set<McpInvocationLog>();
    public DbSet<McpOperation> McpOperations => Set<McpOperation>();

    /// <summary>OAuth 框架创建的实体也统一经过项目 ID 入口，不保留框架构造器的独立 ID 算法。</summary>
    private void AssignOAuthIds()
    {
        foreach (var entry in ChangeTracker.Entries().Where(x => x.State == EntityState.Added))
        {
            if (entry.Entity is not (McpOAuthApplication or McpOAuthAuthorization or McpOAuthScope or McpOAuthToken)
                || !assignedOAuthIds.Add(entry.Entity)) continue;
            switch (entry.Entity)
            {
                case McpOAuthApplication row: row.Id = oauthIds.NewId(); break;
                case McpOAuthAuthorization row: row.Id = oauthIds.NewId(); break;
                case McpOAuthScope row: row.Id = oauthIds.NewId(); break;
                case McpOAuthToken row: row.Id = oauthIds.NewId(); break;
            }
        }
    }
    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    { AssignOAuthIds(); return base.SaveChanges(acceptAllChangesOnSuccess); }
    public override Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    { AssignOAuthIds(); return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken); }

    partial void ConfigureMcp(ModelBuilder model)
    {
        // 四张标准 OAuth 表使用专用前缀，业务表不存储或复制令牌秘密。
        model.UseOpenIddict<McpOAuthApplication, McpOAuthAuthorization, McpOAuthScope, McpOAuthToken, string>();
        model.Entity<McpOAuthApplication>().ToTable("McpOAuthApplications");
        model.Entity<McpOAuthAuthorization>().ToTable("McpOAuthAuthorizations");
        model.Entity<McpOAuthScope>().ToTable("McpOAuthScopes");
        model.Entity<McpOAuthToken>().ToTable("McpOAuthTokens");
        model.Entity<McpSettings>().ToTable("McpSettings", table => table.HasCheckConstraint("CK_McpSettings_Singleton", "Id = 'default'"));
        model.Entity<McpSettings>().Property(x => x.ConfigRevision).IsConcurrencyToken();
        model.Entity<McpClient>().HasIndex(x => x.ClientId).IsUnique();
        model.Entity<McpClient>().HasIndex(x => x.OAuthApplicationId).IsUnique();
        model.Entity<McpClient>().Property(x => x.ConfigRevision).IsConcurrencyToken();
        model.Entity<McpApiKey>().HasIndex(x => x.ClientId);
        model.Entity<McpApiKey>().HasIndex(x => x.Prefix).IsUnique();
        model.Entity<McpApiKey>().Property(x => x.ConfigRevision).IsConcurrencyToken();
        model.Entity<McpAllowRule>().HasIndex(x => x.ClientId);
        model.Entity<McpInvocationLog>().HasIndex(x => x.StartedAtUtc);
        model.Entity<McpInvocationLog>().HasIndex(x => new { x.ClientId, x.StartedAtUtc });
        model.Entity<McpInvocationLog>().HasIndex(x => new { x.ToolName, x.StartedAtUtc });
        model.Entity<McpInvocationLog>().HasIndex(x => x.OperationId);
        model.Entity<McpInvocationLog>().HasIndex(x => new { x.ApiKeyId, x.StartedAtUtc });
        model.Entity<McpInvocationLog>().HasIndex(x => new { x.StartedAtUtc, x.Code, x.Status }).IsUnique()
            .HasFilter("Status = 'Denied' AND ClientId = ''");
        model.Entity<McpOperation>().HasIndex(x => new { x.ClientId, x.IdempotencyKey }).IsUnique();
        model.Entity<McpOperation>().HasIndex(x => new { x.Status, x.NextRunAtUtc });
        model.Entity<McpOperation>().HasIndex(x => x.CertificateId);
        model.Entity<McpOperation>().HasIndex(x => x.BatchId);
        model.Entity<McpOperation>().Property(x => x.Version).IsConcurrencyToken();
        model.Entity<McpOperation>().Property(x => x.LeaseToken).IsConcurrencyToken();
    }
}
