namespace FtpReverseProxy.Core.Enums;

/// <summary>
/// FTP data channel modes
/// </summary>
public enum DataChannelMode
{
    /// <summary>
    /// Passive mode - server opens port, client connects (PASV/EPSV)
    /// </summary>
    Passive,

    /// <summary>
    /// Active mode - client opens port, server connects (PORT/EPRT)
    /// </summary>
    Active
}
