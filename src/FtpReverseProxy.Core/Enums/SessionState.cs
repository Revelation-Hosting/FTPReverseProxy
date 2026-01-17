namespace FtpReverseProxy.Core.Enums;

/// <summary>
/// States of an FTP proxy session
/// </summary>
public enum SessionState
{
    /// <summary>
    /// Client has connected, awaiting USER command
    /// </summary>
    Connected,

    /// <summary>
    /// USER command received, awaiting PASS command
    /// </summary>
    AwaitingPassword,

    /// <summary>
    /// Credentials received, connecting to backend
    /// </summary>
    Authenticating,

    /// <summary>
    /// Successfully authenticated and connected to backend
    /// </summary>
    Active,

    /// <summary>
    /// TLS negotiation in progress (for explicit FTPS)
    /// </summary>
    TlsNegotiation,

    /// <summary>
    /// Session is closing
    /// </summary>
    Closing,

    /// <summary>
    /// Session has been closed
    /// </summary>
    Closed,

    /// <summary>
    /// Session encountered an error
    /// </summary>
    Error
}
