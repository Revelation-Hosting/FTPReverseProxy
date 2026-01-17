using System.Net;
using System.Net.Sockets;
using FtpReverseProxy.Core.Enums;

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
    /// Whether to use TLS for data channel
    /// </summary>
    public bool UseTls { get; init; }

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
    /// When this data channel was created
    /// </summary>
    public DateTime CreatedAt { get; } = DateTime.UtcNow;

    /// <summary>
    /// Whether this data channel has been used
    /// </summary>
    public bool IsUsed { get; set; }

    public void Dispose()
    {
        Cts.Cancel();
        Cts.Dispose();
        ClientListener?.Stop();
        BackendListener?.Stop();
    }
}
