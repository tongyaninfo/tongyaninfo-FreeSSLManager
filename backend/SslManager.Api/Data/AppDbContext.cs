using Microsoft.EntityFrameworkCore;
using SslManager.Api.Models;
using SslManager.Api.Models.Mail;

namespace SslManager.Api.Data;

public sealed partial class AppDbContext(DbContextOptions<AppDbContext> options, SslManager.Api.Common.IIdGenerator? idGenerator = null) : DbContext(options)
{
    public DbSet<UserAccount> Users => Set<UserAccount>();
    public DbSet<CloudAccount> CloudAccounts => Set<CloudAccount>();
    public DbSet<ManagedDomain> Domains => Set<ManagedDomain>();
    public DbSet<ManagedCertificate> Certificates => Set<ManagedCertificate>();
    public DbSet<ValidationRecord> ValidationRecords => Set<ValidationRecord>();
    public DbSet<CertificateJob> CertificateJobs => Set<CertificateJob>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
    public DbSet<DeploymentTarget> DeploymentTargets => Set<DeploymentTarget>();
    public DbSet<DeploymentBatch> DeploymentBatches => Set<DeploymentBatch>();
    public DbSet<DeploymentTask> DeploymentTasks => Set<DeploymentTask>();
    public DbSet<DeploymentTaskStep> DeploymentTaskSteps => Set<DeploymentTaskStep>();
    public DbSet<DeploymentBinding> DeploymentBindings => Set<DeploymentBinding>();
    public DbSet<DeploymentMaterialSnapshot> DeploymentMaterialSnapshots => Set<DeploymentMaterialSnapshot>();
    public DbSet<CertificateSchedule> CertificateSchedules => Set<CertificateSchedule>();
    public DbSet<CertificateScheduleRun> CertificateScheduleRuns => Set<CertificateScheduleRun>();
    public DbSet<MailSettings> MailSettings => Set<MailSettings>();
    public DbSet<MailMessage> MailMessages => Set<MailMessage>();
    public DbSet<ExpiryReminderSettings> ExpiryReminderSettings => Set<ExpiryReminderSettings>();
    public DbSet<CertificateExpiryAlert> CertificateExpiryAlerts => Set<CertificateExpiryAlert>();

    protected override void OnModelCreating(ModelBuilder model)
    {
        ConfigureMcp(model);
        ConfigureIssuance(model);
        model.Entity<CloudAccount>().Property(x => x.AcmeDirectoryUrl).HasDefaultValue("https://acme-v02.api.letsencrypt.org/directory");
        model.Entity<CloudAccount>().Property(x => x.AcmeAccountMode).HasDefaultValue("Existing");
        model.Entity<ManagedCertificate>().Property(x => x.HasPrivateKey).HasDefaultValue(true);
        model.Entity<UserAccount>().HasIndex(x => x.NormalizedUsername).IsUnique();
        model.Entity<ManagedDomain>().HasIndex(x => new { x.AccountId, x.ZoneId }).IsUnique();
        model.Entity<ManagedCertificate>().HasIndex(x => new { x.AccountId, x.ApiVersion, x.CertificateId }).IsUnique().HasFilter("CertificateId <> ''");
        model.Entity<ManagedCertificate>().HasIndex(x => new { x.AccountId, x.ApiVersion, x.OrderId }).IsUnique().HasFilter("OrderId <> ''");
        model.Entity<ValidationRecord>().HasIndex(x => new { x.CertificateId, x.Name, x.Type, x.Value }).IsUnique();
        model.Entity<CertificateJob>().HasIndex(x => new { x.CertificateId, x.Kind });
        model.Entity<AuditLog>().HasIndex(x => x.CreatedAtUtc);
        model.Entity<DeploymentTarget>().Property(x => x.ConfigRevision).IsConcurrencyToken();
        model.Entity<DeploymentBatch>().HasIndex(x => x.IdempotencyKey).IsUnique().HasFilter("IdempotencyKey <> ''");
        model.Entity<DeploymentTask>().HasIndex(x => new { x.Status, x.CreatedAtUtc });
        model.Entity<DeploymentTask>().HasIndex(x => new { x.ResourceKey, x.Status });
        model.Entity<DeploymentTask>().HasIndex(x => x.BatchId);
        model.Entity<DeploymentTaskStep>().HasIndex(x => new { x.TaskId, x.CreatedAtUtc });
        model.Entity<DeploymentBinding>().HasIndex(x => new { x.TargetId, x.ResourceKey }).IsUnique();
        // 数据库约束保证同域名启用计划、活跃轮次和原定触发点不会重复。
        model.Entity<CertificateSchedule>().HasIndex(x => new { x.AccountId, x.Domain }).IsUnique().HasFilter("Enabled = 1");
        model.Entity<CertificateSchedule>().HasIndex(x => new { x.Enabled, x.NextRunAtUtc });
        model.Entity<CertificateSchedule>().Property(x => x.ConfigRevision).IsConcurrencyToken();
        model.Entity<CertificateScheduleRun>().HasIndex(x => new { x.ScheduleId, x.TriggerKey }).IsUnique();
        model.Entity<CertificateScheduleRun>().HasIndex(x => x.ScheduleId).IsUnique().HasFilter("Active = 1");
        model.Entity<CertificateScheduleRun>().HasIndex(x => new { x.Active, x.NextCheckAtUtc });
        model.Entity<CertificateScheduleRun>().Property(x => x.LeaseToken).IsConcurrencyToken();
        // 只保存一套发信配置；请求键唯一约束保证网络重试不会重复提交 SMTP。
        model.Entity<MailSettings>().ToTable("MailSettings", table => table.HasCheckConstraint("CK_MailSettings_Singleton", "Id = 'default'"));
        model.Entity<MailMessage>().HasIndex(x => x.RequestId).IsUnique();
        model.Entity<MailMessage>().HasIndex(x => x.CreatedAtUtc);
        model.Entity<MailMessage>().HasIndex(x => new { x.Status, x.CreatedAtUtc });
        model.Entity<ExpiryReminderSettings>().ToTable("ExpiryReminderSettings", table =>
            table.HasCheckConstraint("CK_ExpiryReminderSettings_Singleton", "Id = 'default'"));
        model.Entity<ExpiryReminderSettings>().Property(x => x.UpdatedAtUtc).IsConcurrencyToken();
        model.Entity<CertificateExpiryAlert>().HasIndex(x => new { x.CertificateId, x.NotAfterUtc }).IsUnique();
        model.Entity<CertificateExpiryAlert>().HasIndex(x => new { x.Status, x.NextReminderAtUtc });
        model.Entity<CertificateExpiryAlert>().HasIndex(x => x.PendingRequestId);
        model.Entity<CertificateExpiryAlert>().Property(x => x.LeaseToken).IsConcurrencyToken();
        model.Entity<CertificateExpiryAlert>().Property(x => x.UpdatedAtUtc).IsConcurrencyToken();
    }

    partial void ConfigureMcp(ModelBuilder model);
    partial void ConfigureIssuance(ModelBuilder model);
}
