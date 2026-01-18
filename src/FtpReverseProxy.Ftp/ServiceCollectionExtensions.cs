using System.Security.Cryptography.X509Certificates;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Ftp.DataChannel;
using FtpReverseProxy.Ftp.Handlers;
using FtpReverseProxy.Ftp.Tls;
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

        // Register backend certificate validator as singleton
        services.AddSingleton<IBackendCertificateValidator, BackendCertificateValidator>();

        // Register certificate provider as singleton
        services.AddSingleton<ICertificateProvider>(sp =>
        {
            var logger = sp.GetRequiredService<ILogger<CertificateProvider>>();
            return new CertificateProvider(logger, options.CertificatePath, options.CertificatePassword);
        });

        // Register shared OpenSSL server context as singleton
        // This enables TLS session resumption between control and data channels
        services.AddSingleton<OpenSslServerContext>(sp =>
        {
            var certProvider = sp.GetRequiredService<ICertificateProvider>();
            var cert = certProvider.GetServerCertificate();

            if (cert is null)
            {
                throw new InvalidOperationException(
                    "TLS certificate is required for OpenSSL server context. " +
                    "Configure CertificatePath in DataChannelOptions.");
            }

            var logger = sp.GetRequiredService<ILogger<OpenSslServerContext>>();
            return OpenSslServerContext.Create(cert, logger);
        });

        // Register data channel manager as singleton
        services.AddSingleton<IDataChannelManager>(sp =>
        {
            var logger = sp.GetRequiredService<ILogger<DataChannelManager>>();
            var certProvider = sp.GetRequiredService<ICertificateProvider>();
            var certValidator = sp.GetRequiredService<IBackendCertificateValidator>();
            var sslContext = sp.GetService<OpenSslServerContext>();

            return new DataChannelManager(
                logger,
                certValidator,
                options.MinPort,
                options.MaxPort,
                options.ExternalAddress,
                certProvider.GetServerCertificate(),
                sslContext);
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
