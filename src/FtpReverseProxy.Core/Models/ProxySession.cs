using System.Net;
using FtpReverseProxy.Core.Enums;

namespace FtpReverseProxy.Core.Models;

/// <summary>
/// Represents an active proxy session between a client and backend server
/// </summary>
public class ProxySession
{
    /// <summary>
    /// Unique session identifier
    /// </summary>
    public Guid Id { get; } = Guid.NewGuid();

    /// <summary>
    /// Current state of the session
    /// </summary>
    public SessionState State { get; set; } = SessionState.Connected;

    /// <summary>
    /// Client's IP endpoint
    /// </summary>
    public required IPEndPoint ClientEndpoint { get; set; }

    /// <summary>
    /// Protocol used by the client
    /// </summary>
    public required Protocol ClientProtocol { get; set; }

    /// <summary>
    /// Username provided by the client (set after USER command)
    /// </summary>
    public string? ClientUsername { get; set; }

    /// <summary>
    /// The resolved backend server for this session
    /// </summary>
    public BackendServer? Backend { get; set; }

    /// <summary>
    /// Whether TLS is enabled on the client connection
    /// </summary>
    public bool ClientTlsEnabled { get; set; }

    /// <summary>
    /// Whether TLS is enabled on the backend connection
    /// </summary>
    public bool BackendTlsEnabled { get; set; }

    /// <summary>
    /// When the session was established
    /// </summary>
    public DateTime ConnectedAt { get; } = DateTime.UtcNow;

    /// <summary>
    /// When the session was last active
    /// </summary>
    public DateTime LastActivityAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Current working directory on the backend
    /// </summary>
    public string CurrentDirectory { get; set; } = "/";

    /// <summary>
    /// Data channel mode currently in use
    /// </summary>
    public DataChannelMode DataChannelMode { get; set; } = DataChannelMode.Passive;

    /// <summary>
    /// Whether data channel protection is enabled (PROT P)
    /// </summary>
    public bool DataChannelProtected { get; set; }

    /// <summary>
    /// Bytes transferred from client to backend
    /// </summary>
    public long BytesUploaded { get; set; }

    /// <summary>
    /// Bytes transferred from backend to client
    /// </summary>
    public long BytesDownloaded { get; set; }

    /// <summary>
    /// Number of commands processed in this session
    /// </summary>
    public int CommandCount { get; set; }
}
