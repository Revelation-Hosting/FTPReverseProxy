using FtpReverseProxy.Core.Configuration;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Ftp;
using FtpReverseProxy.Sftp;
using Microsoft.Extensions.Options;

namespace FtpReverseProxy.Service;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly IServiceProvider _serviceProvider;
    private readonly ProxyConfiguration _config;
    private readonly List<IProxyListener> _listeners = new();
    private ISessionManager? _sessionManager;

    public Worker(
        ILogger<Worker> logger,
        IServiceProvider serviceProvider,
        IOptions<ProxyConfiguration> config)
    {
        _logger = logger;
        _serviceProvider = serviceProvider;
        _config = config.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("FTP Reverse Proxy starting...");

        try
        {
            await StartListenersAsync(stoppingToken);

            // Wait until cancellation is requested
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Shutdown requested");
        }
        finally
        {
            await GracefulShutdownAsync();
        }
    }

    private async Task GracefulShutdownAsync()
    {
        // Signal that we're shutting down (reject new connections)
        if (_sessionManager is not null && _config.Shutdown.RejectNewConnections)
        {
            _sessionManager.IsShuttingDown = true;
            _logger.LogInformation("Rejecting new connections during shutdown");
        }

        // Stop accepting new connections
        await StopListenersAsync();

        // Wait for existing sessions to drain
        if (_sessionManager is not null && _sessionManager.ActiveSessionCount > 0)
        {
            var drainTimeout = TimeSpan.FromSeconds(_config.Shutdown.DrainTimeoutSeconds);
            _logger.LogInformation(
                "Waiting up to {Timeout}s for {Count} active session(s) to complete...",
                _config.Shutdown.DrainTimeoutSeconds,
                _sessionManager.ActiveSessionCount);

            var drained = await _sessionManager.WaitForDrainAsync(drainTimeout);

            if (drained)
            {
                _logger.LogInformation("All sessions completed gracefully");
            }
            else
            {
                _logger.LogWarning(
                    "Shutdown timeout reached with {Count} session(s) still active",
                    _sessionManager.ActiveSessionCount);
            }
        }
    }

    private async Task StartListenersAsync(CancellationToken stoppingToken)
    {
        _sessionManager = _serviceProvider.GetRequiredService<ISessionManager>();
        var sessionManager = _sessionManager;

        // Start FTP listener
        if (_config.Ftp.Enabled)
        {
            var ftpListener = new FtpListener(
                _config.Ftp.ListenAddress,
                _config.Ftp.Port,
                _serviceProvider,
                sessionManager,
                _serviceProvider.GetRequiredService<ILogger<FtpListener>>(),
                implicitTls: false);

            _listeners.Add(ftpListener);
            _ = ftpListener.StartAsync(stoppingToken);
        }

        // Start FTPS implicit listener
        if (_config.FtpsImplicit.Enabled)
        {
            if (_config.TlsCertificate is null || string.IsNullOrEmpty(_config.TlsCertificate.Path))
            {
                _logger.LogWarning("FTPS Implicit is enabled but no TLS certificate is configured. Skipping.");
            }
            else
            {
                var ftpsListener = new FtpListener(
                    _config.FtpsImplicit.ListenAddress,
                    _config.FtpsImplicit.Port,
                    _serviceProvider,
                    sessionManager,
                    _serviceProvider.GetRequiredService<ILogger<FtpListener>>(),
                    implicitTls: true);

                _listeners.Add(ftpsListener);
                _ = ftpsListener.StartAsync(stoppingToken);
            }
        }

        // Start SFTP listener
        if (_config.Sftp.Enabled)
        {
            var sftpListener = new SftpListener(
                _config.Sftp.ListenAddress,
                _config.Sftp.Port,
                _serviceProvider,
                _serviceProvider.GetRequiredService<ILogger<SftpListener>>(),
                _config.Sftp.HostKeyPath);

            _listeners.Add(sftpListener);
            _ = sftpListener.StartAsync(stoppingToken);

            _logger.LogInformation("SFTP listener started (note: full SFTP proxying requires additional implementation)");
        }

        _logger.LogInformation("Started {Count} listener(s)", _listeners.Count);

        foreach (var listener in _listeners)
        {
            _logger.LogInformation("  - {Protocol} on {Address}:{Port}",
                listener.Protocol, listener.ListenAddress, listener.Port);
        }
    }

    private async Task StopListenersAsync()
    {
        _logger.LogInformation("Stopping {Count} listener(s)...", _listeners.Count);

        foreach (var listener in _listeners)
        {
            try
            {
                await listener.StopAsync();
                await listener.DisposeAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error stopping {Protocol} listener", listener.Protocol);
            }
        }

        _listeners.Clear();
        _logger.LogInformation("All listeners stopped");
    }
}
