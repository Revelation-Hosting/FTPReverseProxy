namespace FtpReverseProxy.Core.Enums;

/// <summary>
/// Supported protocols for FTP connections
/// </summary>
public enum Protocol
{
    /// <summary>
    /// Plain FTP (unencrypted)
    /// </summary>
    Ftp,

    /// <summary>
    /// Explicit FTPS - starts as plain FTP, upgrades via AUTH TLS
    /// </summary>
    FtpsExplicit,

    /// <summary>
    /// Implicit FTPS - TLS from connection start (typically port 990)
    /// </summary>
    FtpsImplicit,

    /// <summary>
    /// SFTP - SSH File Transfer Protocol (completely different from FTP)
    /// </summary>
    Sftp
}
