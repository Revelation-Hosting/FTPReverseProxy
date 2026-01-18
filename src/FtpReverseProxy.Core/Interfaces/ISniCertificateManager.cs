using System.Security.Cryptography.X509Certificates;

namespace FtpReverseProxy.Core.Interfaces;

/// <summary>
/// Manages SNI-based certificate selection for multi-tenant FTPS support.
/// Allows different certificates to be presented based on the hostname the client is connecting to.
/// </summary>
public interface ISniCertificateManager
{
    /// <summary>
    /// Gets the appropriate certificate for the given SNI hostname.
    /// </summary>
    /// <param name="hostname">The hostname from the TLS SNI extension (e.g., "ftp.companya.com")</param>
    /// <returns>The certificate to present, or null if no specific certificate is configured</returns>
    X509Certificate2? GetCertificateForHost(string? hostname);

    /// <summary>
    /// Gets the default certificate to use when no SNI match is found.
    /// </summary>
    /// <returns>The default certificate, or null if none configured</returns>
    X509Certificate2? GetDefaultCertificate();

    /// <summary>
    /// Registers a certificate for one or more hostnames.
    /// </summary>
    /// <param name="hostnames">The hostnames this certificate should be used for</param>
    /// <param name="certificate">The certificate</param>
    void RegisterCertificate(IEnumerable<string> hostnames, X509Certificate2 certificate);

    /// <summary>
    /// Removes certificate registration for a hostname.
    /// </summary>
    /// <param name="hostname">The hostname to unregister</param>
    void UnregisterCertificate(string hostname);

    /// <summary>
    /// Reloads all certificates from configured backends.
    /// Call this when backend configurations change.
    /// </summary>
    Task ReloadCertificatesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets the list of all registered hostnames.
    /// </summary>
    IReadOnlyCollection<string> GetRegisteredHostnames();

    /// <summary>
    /// Checks if a certificate is available for the given hostname.
    /// </summary>
    bool HasCertificateForHost(string hostname);
}
