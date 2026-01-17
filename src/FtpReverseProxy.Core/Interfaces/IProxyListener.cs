namespace FtpReverseProxy.Core.Interfaces;

/// <summary>
/// Interface for protocol-specific listeners (FTP, FTPS, SFTP)
/// </summary>
public interface IProxyListener : IAsyncDisposable
{
    /// <summary>
    /// Starts listening for incoming connections
    /// </summary>
    /// <param name="cancellationToken">Cancellation token to stop listening</param>
    Task StartAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Stops listening for new connections
    /// </summary>
    Task StopAsync();

    /// <summary>
    /// Whether the listener is currently active
    /// </summary>
    bool IsListening { get; }

    /// <summary>
    /// The port this listener is bound to
    /// </summary>
    int Port { get; }

    /// <summary>
    /// The protocol this listener handles
    /// </summary>
    string Protocol { get; }
}
