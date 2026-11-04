using Microsoft.EntityFrameworkCore;

namespace SslManager.Api.Data;

/// <summary>生成和检查迁移只使用内存连接，不执行 Program，不触及正在使用的业务库和密钥。</summary>
internal static class DesignTimeAppDbContextFactory
{
    public static AppDbContext Create() => new(new DbContextOptionsBuilder<AppDbContext>()
        .UseSqlite("Data Source=:memory:").Options);
}
