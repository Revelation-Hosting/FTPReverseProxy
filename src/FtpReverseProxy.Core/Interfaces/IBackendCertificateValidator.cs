using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace FtpReverseProxy.Core.Interfaces;

/// <summary>
/// Validates TLS certificates for backend server connections
/// </summary>
public interface IBackendCertificateValidator
{
    /// <summary>
    /// Validates a server certificate during TLS handshake
    /// </summary>
    /// <param name="sender">The sender object from the callback</param>
    /// <param name="certificate">The certificate to validate</param>
    /// <param name="chain">The certificate chain</param>
    /// <param name="sslPolicyErrors">Any SSL policy errors detected</param>
    /// <returns>True if the certificate is valid, false otherwise</returns>
    bool ValidateCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors);

    /// <summary>
    /// Gets the callback delegate for use with SslStream
    /// </summary>
    RemoteCertificateValidationCallback ValidationCallback { get; }
}
