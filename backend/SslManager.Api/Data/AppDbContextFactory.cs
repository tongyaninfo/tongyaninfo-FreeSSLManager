using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SslManager.Api.Data;

/// <summary>生成迁移时只构建模型，不启动后台任务或访问云平台。</summary>
public sealed class AppDbContextFactory : IDesignTimeDbContextFactory<AppDbContext>
{
    public AppDbContext CreateDbContext(string[] args) => DesignTimeAppDbContextFactory.Create();
}
