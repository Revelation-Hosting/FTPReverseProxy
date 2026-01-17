using System.Net;
using FtpReverseProxy.Core.Enums;

namespace FtpReverseProxy.Core.Interfaces;

/// <summary>
/// Manages FTP data channel connections for proxying
/// </summary>
public interface IDataChannelManager
{
    /// <summary>
    /// Sets up a passive mode data channel relay
    /// </summary>
    /// <param name="sessionId">The session ID this data channel belongs to</param>
    /// <param name="backendEndpoint">The backend's data channel endpoint from PASV response</param>
    /// <param name="useTls">Whether to use TLS for the data channel</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The local endpoint for the client to connect to</returns>
    Task<IPEndPoint> SetupPassiveRelayAsync(
        Guid sessionId,
        IPEndPoint backendEndpoint,
        bool useTls,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets up an active mode data channel relay
    /// </summary>
    /// <param name="sessionId">The session ID this data channel belongs to</param>
    /// <param name="clientEndpoint">The client's data channel endpoint from PORT command</param>
    /// <param name="useTls">Whether to use TLS for the data channel</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The local endpoint for the backend to connect to</returns>
    Task<IPEndPoint> SetupActiveRelayAsync(
        Guid sessionId,
        IPEndPoint clientEndpoint,
        bool useTls,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Starts data transfer relay for the session
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Bytes transferred (upload, download)</returns>
    Task<(long BytesUploaded, long BytesDownloaded)> RelayDataAsync(
        Guid sessionId,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Cancels any pending data channel for a session
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    void CancelDataChannel(Guid sessionId);

    /// <summary>
    /// Gets the current data channel mode for a session
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    /// <returns>The data channel mode, or null if no pending data channel</returns>
    DataChannelMode? GetDataChannelMode(Guid sessionId);
}
