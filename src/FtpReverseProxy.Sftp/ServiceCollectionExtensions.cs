using FtpReverseProxy.Core.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Sftp;

/// <summary>
/// Extension methods for registering SFTP services
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds SFTP proxy services to the service collection
    /// </summary>
    public static IServiceCollection AddSftpProxyServices(this IServiceCollection services, string? keyDirectory = null)
    {
        services.AddTransient<SftpBackendConnection>();

        // Add the proxy key service as singleton (shared across all connections)
        services.AddSingleton(sp =>
        {
            var logger = sp.GetRequiredService<ILogger<ProxyKeyService>>();
            return new ProxyKeyService(logger, keyDirectory);
        });

        return services;
    }
}
