using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FtpReverseProxy.Core.Configuration;
using FtpReverseProxy.Core.Interfaces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FtpReverseProxy.Ftp;

/// <summary>
/// Validates TLS certificates for backend server connections based on configuration
/// </summary>
public class BackendCertificateValidator : IBackendCertificateValidator
{
    private readonly BackendTlsConfiguration _config;
    private readonly ILogger<BackendCertificateValidator> _logger;
    private readonly HashSet<string> _trustedThumbprints;

    public BackendCertificateValidator(
        IOptions<ProxyConfiguration> options,
        ILogger<BackendCertificateValidator> logger)
    {
        _config = options.Value.BackendTls;
        _logger = logger;

        // Normalize thumbprints to uppercase without separators
        _trustedThumbprints = _config.TrustedThumbprints
            .Select(t => t.ToUpperInvariant().Replace(":", "").Replace(" ", ""))
            .ToHashSet();

        LogConfiguration();
    }

    public RemoteCertificateValidationCallback ValidationCallback => ValidateCertificate;

    public bool ValidateCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        // No certificate provided
        if (certificate is null)
        {
            _logger.LogWarning("Backend server did not provide a certificate");
            return false;
        }

        var cert2 = certificate as X509Certificate2 ?? new X509Certificate2(certificate);
        var thumbprint = GetThumbprint(cert2);

        // Log certificate details for debugging
        _logger.LogDebug(
            "Validating backend certificate: Subject={Subject}, Issuer={Issuer}, Thumbprint={Thumbprint}, Errors={Errors}",
            cert2.Subject, cert2.Issuer, thumbprint, sslPolicyErrors);

        return _config.ValidationMode switch
        {
            CertificateValidationMode.AcceptAll => AcceptAllValidation(sslPolicyErrors),
            CertificateValidationMode.TrustedThumbprintsOnly => ThumbprintValidation(thumbprint, sslPolicyErrors),
            CertificateValidationMode.Custom => CustomValidation(cert2, chain, sslPolicyErrors),
            _ => SystemDefaultValidation(sslPolicyErrors)
        };
    }

    private bool AcceptAllValidation(SslPolicyErrors errors)
    {
        if (errors != SslPolicyErrors.None)
        {
            _logger.LogWarning(
                "Backend certificate has errors but AcceptAll mode is enabled: {Errors}. " +
                "This is insecure and should only be used in development.",
                errors);
        }
        return true;
    }

    private bool SystemDefaultValidation(SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None)
        {
            return true;
        }

        _logger.LogWarning("Backend certificate validation failed: {Errors}", errors);
        return false;
    }

    private bool ThumbprintValidation(string thumbprint, SslPolicyErrors errors)
    {
        if (_trustedThumbprints.Count == 0)
        {
            _logger.LogError("TrustedThumbprintsOnly mode enabled but no thumbprints configured");
            return false;
        }

        if (_trustedThumbprints.Contains(thumbprint))
        {
            _logger.LogDebug("Backend certificate thumbprint is trusted: {Thumbprint}", thumbprint);
            return true;
        }

        _logger.LogWarning(
            "Backend certificate thumbprint {Thumbprint} not in trusted list",
            thumbprint);
        return false;
    }

    private bool CustomValidation(X509Certificate2 cert, X509Chain? chain, SslPolicyErrors errors)
    {
        // Start with system validation
        if (errors == SslPolicyErrors.None)
        {
            return true;
        }

        // Check for allowed exceptions
        var remainingErrors = errors;

        // Check expiration
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateChainErrors) && _config.AllowExpired)
        {
            if (chain?.ChainStatus.Any(s => s.Status == X509ChainStatusFlags.NotTimeValid) == true)
            {
                _logger.LogWarning("Backend certificate is expired but AllowExpired is enabled");
                // Remove chain errors if only issue was expiration
                if (chain.ChainStatus.All(s =>
                    s.Status == X509ChainStatusFlags.NoError ||
                    s.Status == X509ChainStatusFlags.NotTimeValid))
                {
                    remainingErrors &= ~SslPolicyErrors.RemoteCertificateChainErrors;
                }
            }
        }

        // Check name mismatch
        if (errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch) && _config.AllowNameMismatch)
        {
            _logger.LogWarning("Backend certificate name mismatch but AllowNameMismatch is enabled");
            remainingErrors &= ~SslPolicyErrors.RemoteCertificateNameMismatch;
        }

        // Check if certificate is in trusted thumbprints
        var thumbprint = GetThumbprint(cert);
        if (_trustedThumbprints.Contains(thumbprint))
        {
            _logger.LogDebug("Backend certificate thumbprint is trusted, ignoring other errors");
            return true;
        }

        if (remainingErrors == SslPolicyErrors.None)
        {
            return true;
        }

        _logger.LogWarning("Backend certificate validation failed after custom checks: {Errors}", remainingErrors);
        return false;
    }

    private static string GetThumbprint(X509Certificate2 cert)
    {
        // Use SHA256 thumbprint for better security
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(cert.RawData);
        return Convert.ToHexString(hash);
    }

    private void LogConfiguration()
    {
        _logger.LogInformation(
            "Backend TLS validation configured: Mode={Mode}, AllowExpired={AllowExpired}, " +
            "AllowNameMismatch={AllowNameMismatch}, TrustedThumbprints={ThumbprintCount}",
            _config.ValidationMode,
            _config.AllowExpired,
            _config.AllowNameMismatch,
            _trustedThumbprints.Count);

        if (_config.ValidationMode == CertificateValidationMode.AcceptAll)
        {
            _logger.LogWarning(
                "Backend TLS validation is set to AcceptAll - this is INSECURE and should only be used in development!");
        }
    }
}
