using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Core.Models;
using Microsoft.Extensions.Logging;
using Renci.SshNet;

namespace FtpReverseProxy.Sftp;

/// <summary>
/// Manages connection to a backend SFTP server using SSH.NET
/// </summary>
public class SftpBackendConnection : IAsyncDisposable
{
    private readonly ILogger<SftpBackendConnection> _logger;

    private SftpClient? _sftpClient;
    private BackendServer? _server;

    public SftpBackendConnection(ILogger<SftpBackendConnection> logger)
    {
        _logger = logger;
    }

    public bool IsConnected => _sftpClient?.IsConnected ?? false;
    public SftpClient? Client => _sftpClient;

    /// <summary>
    /// Connects to the backend SFTP server
    /// </summary>
    public async Task ConnectAsync(BackendServer server, BackendCredentials credentials, CancellationToken cancellationToken = default)
    {
        _server = server;

        _logger.LogDebug("Connecting to SFTP backend {BackendName} at {Host}:{Port}",
            server.Name, server.Host, server.Port);

        // Create connection info based on credentials
        ConnectionInfo connectionInfo;

        if (!string.IsNullOrEmpty(credentials.PrivateKeyPath))
        {
            // Key-based authentication
            var keyFile = string.IsNullOrEmpty(credentials.PrivateKeyPassword)
                ? new PrivateKeyFile(credentials.PrivateKeyPath)
                : new PrivateKeyFile(credentials.PrivateKeyPath, credentials.PrivateKeyPassword);

            connectionInfo = new ConnectionInfo(
                server.Host,
                server.Port,
                credentials.Username,
                new PrivateKeyAuthenticationMethod(credentials.Username, keyFile));
        }
        else
        {
            // Password authentication
            connectionInfo = new ConnectionInfo(
                server.Host,
                server.Port,
                credentials.Username,
                new PasswordAuthenticationMethod(credentials.Username, credentials.Password));
        }

        connectionInfo.Timeout = TimeSpan.FromMilliseconds(server.ConnectionTimeoutMs);

        _sftpClient = new SftpClient(connectionInfo);

        // SSH.NET doesn't have native async connect, so we run it on thread pool
        await Task.Run(() => _sftpClient.Connect(), cancellationToken);

        _logger.LogDebug("Connected to SFTP backend {BackendName}", server.Name);
    }

    /// <summary>
    /// Disconnects from the backend server
    /// </summary>
    public Task DisconnectAsync()
    {
        if (_sftpClient?.IsConnected == true)
        {
            try
            {
                _sftpClient.Disconnect();
                _logger.LogDebug("Disconnected from SFTP backend {BackendName}", _server?.Name);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error disconnecting from SFTP backend");
            }
        }

        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync();
        _sftpClient?.Dispose();
        GC.SuppressFinalize(this);
    }
}
