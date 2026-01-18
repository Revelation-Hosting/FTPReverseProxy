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
    /// <param name="useClientTls">Whether to use TLS for the client data channel</param>
    /// <param name="useBackendTls">Whether to use TLS for the backend data channel</param>
    /// <param name="backendHostname">The backend hostname for TLS authentication (for session resumption)</param>
    /// <param name="skipBackendCertValidation">Whether to skip certificate validation for backend TLS</param>
    /// <param name="tlsSessionToResume">TLS session from control channel for session resumption (BouncyCastle TlsSession)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The local endpoint for the client to connect to</returns>
    Task<IPEndPoint> SetupPassiveRelayAsync(
        Guid sessionId,
        IPEndPoint backendEndpoint,
        bool useClientTls,
        bool useBackendTls,
        string? backendHostname = null,
        bool skipBackendCertValidation = false,
        object? tlsSessionToResume = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Sets up an active mode data channel relay
    /// </summary>
    /// <param name="sessionId">The session ID this data channel belongs to</param>
    /// <param name="clientEndpoint">The client's data channel endpoint from PORT command</param>
    /// <param name="useClientTls">Whether to use TLS for the client data channel</param>
    /// <param name="useBackendTls">Whether to use TLS for the backend data channel</param>
    /// <param name="backendHostname">The backend hostname for TLS authentication (for session resumption)</param>
    /// <param name="skipBackendCertValidation">Whether to skip certificate validation for backend TLS</param>
    /// <param name="tlsSessionToResume">TLS session from control channel for session resumption (BouncyCastle TlsSession)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The local endpoint for the backend to connect to</returns>
    Task<IPEndPoint> SetupActiveRelayAsync(
        Guid sessionId,
        IPEndPoint clientEndpoint,
        bool useClientTls,
        bool useBackendTls,
        string? backendHostname = null,
        bool skipBackendCertValidation = false,
        object? tlsSessionToResume = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Starts data transfer relay for the session
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    /// <param name="isUpload">True for upload commands (STOR/STOU/APPE), false for download (RETR/LIST/MLSD/NLST)</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Bytes transferred (upload, download)</returns>
    Task<(long BytesUploaded, long BytesDownloaded)> RelayDataAsync(
        Guid sessionId,
        bool isUpload,
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

    /// <summary>
    /// Cleans up all resources associated with a session when the control connection closes.
    /// This releases any held semaphores and cleans up per-session tracking data.
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    void CleanupSession(Guid sessionId);
}
