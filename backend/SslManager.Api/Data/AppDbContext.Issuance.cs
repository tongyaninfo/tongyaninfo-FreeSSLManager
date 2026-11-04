using Microsoft.EntityFrameworkCore;
using SslManager.Api.Models;

namespace SslManager.Api.Data;

public sealed partial class AppDbContext
{
    public DbSet<CertificateIssuanceState> CertificateIssuanceStates => Set<CertificateIssuanceState>();

    partial void ConfigureIssuance(ModelBuilder model)
    {
        model.Entity<CertificateIssuanceState>().HasIndex(x => new { x.AccountId, x.Provider });
        model.Entity<CertificateIssuanceState>().HasIndex(x => x.OrderUrl).IsUnique().HasFilter("OrderUrl <> ''");
    }
}
