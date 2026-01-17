using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using FtpReverseProxy.Core.Configuration;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Data.Repositories;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace FtpReverseProxy.Data.Services;

/// <summary>
/// Manages SNI-based certificate selection for multi-tenant FTPS support.
/// Loads certificates from backend configurations and provides fast lookup by hostname.
/// </summary>
public class SniCertificateManager : ISniCertificateManager, IDisposable
{
    private readonly ILogger<SniCertificateManager> _logger;
    private readonly IBackendServerRepository _backendRepository;
    private readonly ProxyConfiguration _config;

    private readonly ConcurrentDictionary<string, X509Certificate2> _certificatesByHostname = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, X509Certificate2> _loadedCertificates = new(StringComparer.OrdinalIgnoreCase);
    private X509Certificate2? _defaultCertificate;
    private bool _disposed;

    public SniCertificateManager(
        ILogger<SniCertificateManager> logger,
        IBackendServerRepository backendRepository,
        IOptions<ProxyConfiguration> config)
    {
        _logger = logger;
        _backendRepository = backendRepository;
        _config = config.Value;

        // Load default certificate if configured
        LoadDefaultCertificate();
    }

    private void LoadDefaultCertificate()
    {
        if (_config.TlsCertificate is not null && !string.IsNullOrEmpty(_config.TlsCertificate.Path))
        {
            try
            {
                _defaultCertificate = X509CertificateLoader.LoadPkcs12FromFile(
                    _config.TlsCertificate.Path,
                    _config.TlsCertificate.Password);

                _logger.LogInformation(
                    "Loaded default TLS certificate: {Subject} (expires {Expiry})",
                    _defaultCertificate.Subject,
                    _defaultCertificate.NotAfter);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load default TLS certificate from {Path}", _config.TlsCertificate.Path);
            }
        }
    }

    public X509Certificate2? GetCertificateForHost(string? hostname)
    {
        if (string.IsNullOrEmpty(hostname))
        {
            _logger.LogDebug("No SNI hostname provided, using default certificate");
            return _defaultCertificate;
        }

        if (_certificatesByHostname.TryGetValue(hostname, out var cert))
        {
            _logger.LogDebug("Found certificate for SNI hostname {Hostname}: {Subject}", hostname, cert.Subject);
            return cert;
        }

        _logger.LogDebug("No certificate registered for hostname {Hostname}, using default", hostname);
        return _defaultCertificate;
    }

    public X509Certificate2? GetDefaultCertificate()
    {
        return _defaultCertificate;
    }

    public void RegisterCertificate(IEnumerable<string> hostnames, X509Certificate2 certificate)
    {
        foreach (var hostname in hostnames)
        {
            var normalizedHostname = hostname.Trim().ToLowerInvariant();
            _certificatesByHostname[normalizedHostname] = certificate;
            _logger.LogInformation(
                "Registered certificate for hostname {Hostname}: {Subject}",
                normalizedHostname,
                certificate.Subject);
        }
    }

    public void UnregisterCertificate(string hostname)
    {
        var normalizedHostname = hostname.Trim().ToLowerInvariant();
        if (_certificatesByHostname.TryRemove(normalizedHostname, out _))
        {
            _logger.LogInformation("Unregistered certificate for hostname {Hostname}", normalizedHostname);
        }
    }

    public async Task ReloadCertificatesAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Reloading SNI certificates from backend configurations...");

        // Clear existing registrations (but keep loaded certs for reuse)
        _certificatesByHostname.Clear();

        // Reload default certificate
        LoadDefaultCertificate();

        // Load certificates from all backends
        var backends = await _backendRepository.GetAllAsync(cancellationToken);
        var loadedCount = 0;

        foreach (var backend in backends)
        {
            if (string.IsNullOrEmpty(backend.ClientFacingHostnames) ||
                string.IsNullOrEmpty(backend.ClientCertificatePath))
            {
                continue;
            }

            try
            {
                // Check if we already have this certificate loaded
                if (!_loadedCertificates.TryGetValue(backend.ClientCertificatePath, out var cert))
                {
                    cert = X509CertificateLoader.LoadPkcs12FromFile(
                        backend.ClientCertificatePath,
                        backend.ClientCertificatePassword);

                    _loadedCertificates[backend.ClientCertificatePath] = cert;

                    _logger.LogInformation(
                        "Loaded certificate for backend {BackendName}: {Subject} (expires {Expiry})",
                        backend.Name,
                        cert.Subject,
                        cert.NotAfter);
                }

                // Register for all configured hostnames
                var hostnames = backend.ClientFacingHostnames
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

                RegisterCertificate(hostnames, cert);
                loadedCount++;
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Failed to load certificate for backend {BackendName} from {Path}",
                    backend.Name,
                    backend.ClientCertificatePath);
            }
        }

        _logger.LogInformation(
            "SNI certificate reload complete. {LoadedCount} backend certificates loaded, {TotalHostnames} hostnames registered",
            loadedCount,
            _certificatesByHostname.Count);
    }

    public IReadOnlyCollection<string> GetRegisteredHostnames()
    {
        return _certificatesByHostname.Keys.ToList().AsReadOnly();
    }

    public bool HasCertificateForHost(string hostname)
    {
        var normalizedHostname = hostname.Trim().ToLowerInvariant();
        return _certificatesByHostname.ContainsKey(normalizedHostname);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        _defaultCertificate?.Dispose();

        foreach (var cert in _loadedCertificates.Values)
        {
            cert.Dispose();
        }

        _loadedCertificates.Clear();
        _certificatesByHostname.Clear();
    }
}
