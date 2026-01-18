using System.Net;
using System.Net.Sockets;
using FtpReverseProxy.Core.Enums;
using FtpReverseProxy.Ftp.Tls;

namespace FtpReverseProxy.Ftp.DataChannel;

/// <summary>
/// Tracks the state of a pending or active data channel
/// </summary>
public class DataChannelState : IDisposable
{
    /// <summary>
    /// The session this data channel belongs to
    /// </summary>
    public Guid SessionId { get; init; }

    /// <summary>
    /// Data channel mode (passive or active)
    /// </summary>
    public DataChannelMode Mode { get; init; }

    /// <summary>
    /// Whether to use TLS for client data channel
    /// </summary>
    public bool UseClientTls { get; init; }

    /// <summary>
    /// Whether to use TLS for backend data channel
    /// </summary>
    public bool UseBackendTls { get; init; }

    /// <summary>
    /// Whether to skip certificate validation for backend TLS
    /// </summary>
    public bool SkipBackendCertValidation { get; init; }

    /// <summary>
    /// Backend hostname for TLS authentication (enables session resumption)
    /// </summary>
    public string? BackendHostname { get; init; }

    /// <summary>
    /// OpenSSL TLS session from control channel for session resumption
    /// </summary>
    public OpenSslSession? TlsSessionToResume { get; init; }

    /// <summary>
    /// For passive mode: listener for client connections
    /// </summary>
    public TcpListener? ClientListener { get; set; }

    /// <summary>
    /// For passive mode: the backend's data endpoint to connect to
    /// </summary>
    public IPEndPoint? BackendDataEndpoint { get; set; }

    /// <summary>
    /// For active mode: the client's data endpoint to connect to
    /// </summary>
    public IPEndPoint? ClientDataEndpoint { get; set; }

    /// <summary>
    /// For active mode: listener for backend connections
    /// </summary>
    public TcpListener? BackendListener { get; set; }

    /// <summary>
    /// The local endpoint we're exposing (for response rewriting)
    /// </summary>
    public IPEndPoint? LocalEndpoint { get; set; }

    /// <summary>
    /// Cancellation token source for this data channel
    /// </summary>
    public CancellationTokenSource Cts { get; } = new();

    /// <summary>
    /// Task completion source for signaling transfer completion
    /// </summary>
    public TaskCompletionSource<(long BytesUploaded, long BytesDownloaded)> TransferCompletion { get; } = new();

    /// <summary>
    /// Task completion source for signaling cleanup completion.
    /// This ensures callers wait for cleanup before continuing.
    /// </summary>
    public TaskCompletionSource CleanupCompletion { get; } = new();

    /// <summary>
    /// When this data channel was created
    /// </summary>
    public DateTime CreatedAt { get; } = DateTime.UtcNow;

    /// <summary>
    /// Whether this data channel has been used
    /// </summary>
    public bool IsUsed { get; set; }

    /// <summary>
    /// Whether this is an upload operation (STOR/STOU/APPE) vs download (RETR/LIST/MLSD/NLST).
    /// Used to determine which relay direction to wait for completion.
    /// </summary>
    public bool IsUpload { get; set; }

    /// <summary>
    /// Signals when the transfer direction (upload/download) has been determined.
    /// The relay must wait for this before starting to copy data.
    /// </summary>
    public TaskCompletionSource DirectionDetermined { get; } = new();

    public void Dispose()
    {
        Cts.Cancel();
        Cts.Dispose();

        // Stop and dispose listeners to fully release the ports
        // Just calling Stop() may not immediately release the port in all cases
        if (ClientListener is not null)
        {
            try
            {
                ClientListener.Stop();
                ClientListener.Server?.Dispose();
            }
            catch { /* Ignore disposal errors */ }
        }

        if (BackendListener is not null)
        {
            try
            {
                BackendListener.Stop();
                BackendListener.Server?.Dispose();
            }
            catch { /* Ignore disposal errors */ }
        }

        // Note: We don't release the TLS session here.
        // The FtpSessionHandler owns the OpenSslSession and manages its lifecycle.
        // FTP data channels for a single control connection are sequential,
        // so there's no concurrent access concern.
    }
}
