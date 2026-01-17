using System.Security.Cryptography.X509Certificates;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Ftp.DataChannel;
using FtpReverseProxy.Ftp.Handlers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp;

/// <summary>
/// Configuration options for the FTP proxy data channel
/// </summary>
public class DataChannelOptions
{
    /// <summary>
    /// Minimum port for data channel connections
    /// </summary>
    public int MinPort { get; set; } = 50000;

    /// <summary>
    /// Maximum port for data channel connections
    /// </summary>
    public int MaxPort { get; set; } = 51000;

    /// <summary>
    /// External IP address to advertise to clients (for NAT scenarios)
    /// If null, will attempt to auto-detect
    /// </summary>
    public string? ExternalAddress { get; set; }

    /// <summary>
    /// Path to TLS certificate for data channel encryption
    /// </summary>
    public string? CertificatePath { get; set; }

    /// <summary>
    /// Password for the TLS certificate
    /// </summary>
    public string? CertificatePassword { get; set; }
}

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
        return services.AddFtpProxyServices(new DataChannelOptions());
    }

    /// <summary>
    /// Adds FTP proxy services to the service collection with custom options
    /// </summary>
    public static IServiceCollection AddFtpProxyServices(
        this IServiceCollection services,
        DataChannelOptions options)
    {
        services.AddSingleton<ISessionManager, SessionManager>();
        services.AddTransient<IBackendConnection, FtpBackendConnection>();

        // Register certificate provider as singleton
        services.AddSingleton<ICertificateProvider>(sp =>
        {
            var logger = sp.GetRequiredService<ILogger<CertificateProvider>>();
            return new CertificateProvider(logger, options.CertificatePath, options.CertificatePassword);
        });

        // Register data channel manager as singleton
        services.AddSingleton<IDataChannelManager>(sp =>
        {
            var logger = sp.GetRequiredService<ILogger<DataChannelManager>>();
            var certProvider = sp.GetRequiredService<ICertificateProvider>();

            return new DataChannelManager(
                logger,
                options.MinPort,
                options.MaxPort,
                options.ExternalAddress,
                certProvider.GetServerCertificate());
        });

        return services;
    }

    /// <summary>
    /// Adds FTP proxy services with configuration action
    /// </summary>
    public static IServiceCollection AddFtpProxyServices(
        this IServiceCollection services,
        Action<DataChannelOptions> configure)
    {
        var options = new DataChannelOptions();
        configure(options);
        return services.AddFtpProxyServices(options);
    }
}
