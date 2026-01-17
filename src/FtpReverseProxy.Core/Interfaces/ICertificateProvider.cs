using System.Security.Cryptography.X509Certificates;

namespace FtpReverseProxy.Core.Interfaces;

/// <summary>
/// Provides TLS certificates for the proxy
/// </summary>
public interface ICertificateProvider
{
    /// <summary>
    /// Gets the server certificate for TLS connections
    /// </summary>
    X509Certificate2? GetServerCertificate();

    /// <summary>
    /// Whether a valid certificate is available
    /// </summary>
    bool HasCertificate { get; }
}
