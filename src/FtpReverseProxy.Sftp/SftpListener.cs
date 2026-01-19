using System.Net;
using System.Security.Cryptography;
using FxSsh;
using FtpReverseProxy.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Sftp;

/// <summary>
/// SSH/SFTP listener using FxSsh
/// Note: This is a foundational implementation. Full SFTP proxying requires
/// additional work to parse and forward SFTP packets between client and backend.
/// </summary>
public class SftpListener : IProxyListener
{
    private readonly IPAddress _listenAddress;
    private readonly int _port;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<SftpListener> _logger;
    private readonly string? _hostKeyPath;

    private SshServer? _server;
    private CancellationTokenSource? _cts;

    public SftpListener(
        string listenAddress,
        int port,
        IServiceProvider serviceProvider,
        ILogger<SftpListener> logger,
        string? hostKeyPath = null)
    {
        _listenAddress = IPAddress.Parse(listenAddress);
        _port = port;
        _serviceProvider = serviceProvider;
        _logger = logger;
        _hostKeyPath = hostKeyPath;
    }

    public bool IsListening => _server != null;
    public string ListenAddress => _listenAddress.ToString();
    public int Port => _port;
    public string Protocol => "SFTP";

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        var startingInfo = new StartingInfo(
            _listenAddress,
            _port,
            "SSH-2.0-FTPReverseProxy");

        _server = new SshServer(startingInfo);

        // Add host keys
        ConfigureHostKeys();

        // Wire up event handlers
        _server.ConnectionAccepted += OnConnectionAccepted;

        _server.Start();
        _logger.LogInformation("SFTP listener started on {Address}:{Port}", _listenAddress, _port);

        return Task.CompletedTask;
    }

    public Task StopAsync()
    {
        _cts?.Cancel();
        _server?.Stop();
        _server = null;
        _logger.LogInformation("SFTP listener stopped on {Address}:{Port}", _listenAddress, _port);
        return Task.CompletedTask;
    }

    private void ConfigureHostKeys()
    {
        if (_server is null) return;

        // Generate RSA key for SSH server
        using var rsa = RSA.Create(2048);

        // FxSsh expects PEM-formatted private keys
        var rsaPem = rsa.ExportRSAPrivateKeyPem();

        // Register the key with both rsa-sha2-256 and rsa-sha2-512 algorithms
        _server.AddHostKey("rsa-sha2-256", rsaPem);
        _server.AddHostKey("rsa-sha2-512", rsaPem);

        _logger.LogInformation("RSA host key configured for SFTP server");
    }

    private void OnConnectionAccepted(object? sender, Session session)
    {
        _logger.LogInformation("SFTP connection accepted from {SessionId}", session.SessionId);

        // Create session handler for this connection
        var handler = new SftpSessionHandler(
            session,
            _serviceProvider,
            _logger);

        handler.Initialize();
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _cts?.Dispose();
        GC.SuppressFinalize(this);
    }
}
