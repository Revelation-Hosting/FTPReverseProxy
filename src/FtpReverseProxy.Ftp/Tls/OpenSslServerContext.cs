using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp.Tls;

/// <summary>
/// Shared OpenSSL SSL_CTX for server-mode connections.
/// This enables TLS session resumption between control and data channels
/// when clients (like FileZilla) expect to resume their session.
/// Thread-safe for concurrent access.
/// </summary>
public class OpenSslServerContext : IDisposable
{
    private IntPtr _sslCtx;
    private readonly ILogger? _logger;
    private readonly object _lock = new();
    private bool _disposed;

    /// <summary>
    /// Gets the native SSL_CTX pointer.
    /// </summary>
    public IntPtr Handle => _sslCtx;

    /// <summary>
    /// Gets whether the context is valid.
    /// </summary>
    public bool IsValid => _sslCtx != IntPtr.Zero;

    private OpenSslServerContext(IntPtr sslCtx, ILogger? logger)
    {
        _sslCtx = sslCtx;
        _logger = logger;
    }

    /// <summary>
    /// Creates a new OpenSSL server context with the given certificate.
    /// The context enables session caching for resumption.
    /// </summary>
    public static OpenSslServerContext Create(X509Certificate2 certificate, ILogger? logger = null)
    {
        // Initialize OpenSSL (safe to call multiple times)
        OpenSslInterop.OPENSSL_init_ssl(0, IntPtr.Zero);

        // Create SSL context for server
        var method = OpenSslInterop.TLS_server_method();
        if (method == IntPtr.Zero)
        {
            throw new InvalidOperationException($"Failed to get TLS server method: {OpenSslInterop.GetLastErrorString()}");
        }

        var ctx = OpenSslInterop.SSL_CTX_new(method);
        if (ctx == IntPtr.Zero)
        {
            throw new InvalidOperationException($"Failed to create SSL context: {OpenSslInterop.GetLastErrorString()}");
        }

        try
        {
            // Set options - disable old protocols
            OpenSslInterop.SSL_CTX_set_options(ctx,
                OpenSslInterop.SSL_OP_NO_SSLv2 |
                OpenSslInterop.SSL_OP_NO_SSLv3 |
                OpenSslInterop.SSL_OP_NO_COMPRESSION);

            // Set minimum TLS version to 1.2
            OpenSslInterop.SSL_CTX_set_min_proto_version(ctx, OpenSslInterop.TLS1_2_VERSION);

            // Enable session caching for server (built-in session cache)
            // SSL_SESS_CACHE_SERVER enables server-side session caching
            OpenSslInterop.SSL_CTX_set_session_cache_mode(ctx, OpenSslInterop.SSL_SESS_CACHE_SERVER);
            logger?.LogDebug("OpenSSL session caching enabled for TLS session resumption");

            // Set session timeout to 5 minutes (should be enough for FTP)
            OpenSslInterop.SSL_CTX_set_timeout(ctx, 300);

            // Load certificate from X509Certificate2
            var pfxData = certificate.Export(X509ContentType.Pfx, "");
            if (!OpenSslInterop.LoadPkcs12(pfxData, "", out var cert, out var pkey))
            {
                throw new InvalidOperationException($"Failed to load certificate: {OpenSslInterop.GetLastErrorString()}");
            }

            try
            {
                if (OpenSslInterop.SSL_CTX_use_certificate(ctx, cert) != 1)
                {
                    throw new InvalidOperationException($"Failed to use certificate: {OpenSslInterop.GetLastErrorString()}");
                }

                if (OpenSslInterop.SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
                {
                    throw new InvalidOperationException($"Failed to use private key: {OpenSslInterop.GetLastErrorString()}");
                }

                if (OpenSslInterop.SSL_CTX_check_private_key(ctx) != 1)
                {
                    throw new InvalidOperationException($"Certificate and private key don't match: {OpenSslInterop.GetLastErrorString()}");
                }
            }
            finally
            {
                OpenSslInterop.X509_free(cert);
                OpenSslInterop.EVP_PKEY_free(pkey);
            }

            logger?.LogInformation("OpenSSL server context created with session caching enabled. Certificate: {Subject}",
                certificate.Subject);

            return new OpenSslServerContext(ctx, logger);
        }
        catch
        {
            OpenSslInterop.SSL_CTX_free(ctx);
            throw;
        }
    }

    /// <summary>
    /// Creates a new SSL connection on this context.
    /// Thread-safe for concurrent access.
    /// </summary>
    public IntPtr CreateSsl()
    {
        lock (_lock)
        {
            if (_disposed || _sslCtx == IntPtr.Zero)
            {
                throw new ObjectDisposedException(nameof(OpenSslServerContext));
            }

            var ssl = OpenSslInterop.SSL_new(_sslCtx);
            if (ssl == IntPtr.Zero)
            {
                // Capture error immediately while still holding lock
                var error = OpenSslInterop.GetLastErrorString();
                throw new InvalidOperationException($"Failed to create SSL object: {error}");
            }

            _logger?.LogDebug("Created new SSL object from shared context");
            return ssl;
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (!_disposed)
            {
                _disposed = true;
                if (_sslCtx != IntPtr.Zero)
                {
                    _logger?.LogInformation("Disposing shared OpenSSL server context");
                    OpenSslInterop.SSL_CTX_free(_sslCtx);
                    _sslCtx = IntPtr.Zero;
                }
            }
        }
    }
}
