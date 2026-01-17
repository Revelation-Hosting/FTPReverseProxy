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
    public static IServiceCollection AddSftpProxyServices(this IServiceCollection services)
    {
        services.AddTransient<SftpBackendConnection>();
        return services;
    }
}
