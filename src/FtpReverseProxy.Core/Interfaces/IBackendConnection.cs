using FtpReverseProxy.Core.Models;

namespace FtpReverseProxy.Core.Interfaces;

/// <summary>
/// Interface for backend FTP/SFTP connections
/// </summary>
public interface IBackendConnection : IAsyncDisposable
{
    /// <summary>
    /// Connects to the backend server
    /// </summary>
    /// <param name="server">The backend server configuration</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task ConnectAsync(BackendServer server, CancellationToken cancellationToken = default);

    /// <summary>
    /// Authenticates with the backend server
    /// </summary>
    /// <param name="credentials">The credentials to use</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if authentication succeeded, false otherwise</returns>
    Task<bool> AuthenticateAsync(BackendCredentials credentials, CancellationToken cancellationToken = default);

    /// <summary>
    /// Sends a command to the backend server
    /// </summary>
    /// <param name="command">The command to send</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The response from the backend</returns>
    Task<FtpResponse> SendCommandAsync(FtpCommand command, CancellationToken cancellationToken = default);

    /// <summary>
    /// Upgrades the connection to TLS (for explicit FTPS)
    /// </summary>
    /// <param name="cancellationToken">Cancellation token</param>
    Task UpgradeToTlsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Whether the connection is currently established
    /// </summary>
    bool IsConnected { get; }

    /// <summary>
    /// Whether TLS is enabled on the connection
    /// </summary>
    bool IsTlsEnabled { get; }

    /// <summary>
    /// Disconnects from the backend server
    /// </summary>
    Task DisconnectAsync();
}
