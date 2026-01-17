using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace FtpReverseProxy.Data;

/// <summary>
/// Factory for creating DbContext at design-time (migrations)
/// Uses PostgreSQL by default for migrations
/// </summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<FtpProxyDbContext>
{
    public FtpProxyDbContext CreateDbContext(string[] args)
    {
        var optionsBuilder = new DbContextOptionsBuilder<FtpProxyDbContext>();

        // Default connection string for design-time (migrations)
        // This can be overridden by environment variable
        var connectionString = Environment.GetEnvironmentVariable("FTP_PROXY_CONNECTION_STRING")
            ?? "Host=localhost;Database=ftpproxy;Username=postgres;Password=postgres";

        optionsBuilder.UseNpgsql(connectionString);

        return new FtpProxyDbContext(optionsBuilder.Options);
    }
}
