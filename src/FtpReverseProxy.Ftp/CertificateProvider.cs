using System.Security.Cryptography.X509Certificates;
using FtpReverseProxy.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp;

/// <summary>
/// Provides TLS certificates for FTP/FTPS connections
/// </summary>
public class CertificateProvider : ICertificateProvider
{
    private readonly X509Certificate2? _certificate;
    private readonly ILogger<CertificateProvider> _logger;

    public CertificateProvider(ILogger<CertificateProvider> logger, string? certificatePath = null, string? certificatePassword = null)
    {
        _logger = logger;

        if (!string.IsNullOrEmpty(certificatePath))
        {
            try
            {
                _certificate = X509CertificateLoader.LoadPkcs12FromFile(certificatePath, certificatePassword);
                _logger.LogInformation("Loaded TLS certificate from {Path}, Subject: {Subject}",
                    certificatePath, _certificate.Subject);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load TLS certificate from {Path}", certificatePath);
            }
        }
        else
        {
            _logger.LogWarning("No TLS certificate path configured. FTPS will not be available.");
        }
    }

    public X509Certificate2? GetServerCertificate() => _certificate;

    public bool HasCertificate => _certificate is not null;
}
