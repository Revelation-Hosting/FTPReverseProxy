using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Ftp.Handlers;
using Microsoft.Extensions.DependencyInjection;

namespace FtpReverseProxy.Ftp;

/// <summary>
/// Extension methods for registering FTP services
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds FTP proxy services to the service collection
    /// </summary>
    public static IServiceCollection AddFtpProxyServices(this IServiceCollection services)
    {
        services.AddSingleton<ISessionManager, SessionManager>();
        services.AddTransient<IBackendConnection, FtpBackendConnection>();

        return services;
    }
}
