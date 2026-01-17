using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Data.Repositories;
using FtpReverseProxy.Data.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace FtpReverseProxy.Data;

/// <summary>
/// Configuration options for data services
/// </summary>
public class DataServiceOptions
{
    /// <summary>
    /// Database provider: "PostgreSQL" or "SqlServer"
    /// </summary>
    public string Provider { get; set; } = "PostgreSQL";

    /// <summary>
    /// Database connection string
    /// </summary>
    public string ConnectionString { get; set; } = string.Empty;

    /// <summary>
    /// Whether to use Redis for distributed caching
    /// </summary>
    public bool UseRedis { get; set; }

    /// <summary>
    /// Redis connection string
    /// </summary>
    public string RedisConnectionString { get; set; } = "localhost:6379";
}

/// <summary>
/// Extension methods for registering data services
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds FTP Proxy data services with configuration options
    /// </summary>
    public static IServiceCollection AddFtpProxyData(
        this IServiceCollection services,
        Action<DataServiceOptions> configure)
    {
        var options = new DataServiceOptions();
        configure(options);

        // Configure database provider
        if (options.Provider.Equals("SqlServer", StringComparison.OrdinalIgnoreCase))
        {
            services.AddDbContext<FtpProxyDbContext>(opts =>
                opts.UseSqlServer(options.ConnectionString));
        }
        else
        {
            services.AddDbContext<FtpProxyDbContext>(opts =>
                opts.UseNpgsql(options.ConnectionString));
        }

        // Configure caching
        if (options.UseRedis)
        {
            services.AddStackExchangeRedisCache(opts =>
            {
                opts.Configuration = options.RedisConnectionString;
                opts.InstanceName = "FtpProxy:";
            });
        }
        else
        {
            services.AddDistributedMemoryCache();
        }

        return services.AddFtpProxyDataServices();
    }

    /// <summary>
    /// Adds FTP Proxy data services with SQL Server
    /// </summary>
    public static IServiceCollection AddFtpProxyDataSqlServer(
        this IServiceCollection services,
        string connectionString)
    {
        services.AddDbContext<FtpProxyDbContext>(options =>
            options.UseSqlServer(connectionString));

        return services.AddFtpProxyDataServices();
    }

    /// <summary>
    /// Adds FTP Proxy data services with PostgreSQL
    /// </summary>
    public static IServiceCollection AddFtpProxyDataPostgreSql(
        this IServiceCollection services,
        string connectionString)
    {
        services.AddDbContext<FtpProxyDbContext>(options =>
            options.UseNpgsql(connectionString));

        return services.AddFtpProxyDataServices();
    }

    /// <summary>
    /// Adds Redis distributed caching
    /// </summary>
    public static IServiceCollection AddFtpProxyRedisCache(
        this IServiceCollection services,
        string connectionString)
    {
        services.AddStackExchangeRedisCache(options =>
        {
            options.Configuration = connectionString;
            options.InstanceName = "FtpProxy:";
        });

        return services;
    }

    /// <summary>
    /// Adds in-memory distributed caching (for development/testing)
    /// </summary>
    public static IServiceCollection AddFtpProxyMemoryCache(this IServiceCollection services)
    {
        services.AddDistributedMemoryCache();
        return services;
    }

    private static IServiceCollection AddFtpProxyDataServices(this IServiceCollection services)
    {
        // Repositories
        services.AddScoped<IBackendServerRepository, BackendServerRepository>();
        services.AddScoped<IRouteMappingRepository, RouteMappingRepository>();

        // Services
        services.AddScoped<IRoutingService, CachedRoutingService>();
        services.AddScoped<ICredentialMapper, CredentialMapper>();

        return services;
    }
}
