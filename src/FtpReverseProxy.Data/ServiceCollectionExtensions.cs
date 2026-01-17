using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Data.Repositories;
using FtpReverseProxy.Data.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace FtpReverseProxy.Data;

/// <summary>
/// Extension methods for registering data services
/// </summary>
public static class ServiceCollectionExtensions
{
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
