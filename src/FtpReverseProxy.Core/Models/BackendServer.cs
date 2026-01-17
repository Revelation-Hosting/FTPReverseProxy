using FtpReverseProxy.Core.Enums;

namespace FtpReverseProxy.Core.Models;

/// <summary>
/// Represents a backend FTP/SFTP server that connections can be routed to
/// </summary>
public class BackendServer
{
    /// <summary>
    /// Unique identifier for this backend server
    /// </summary>
    public required string Id { get; set; }

    /// <summary>
    /// Display name for this backend server
    /// </summary>
    public required string Name { get; set; }

    /// <summary>
    /// Hostname or IP address of the backend server
    /// </summary>
    public required string Host { get; set; }

    /// <summary>
    /// Port number for the backend server
    /// </summary>
    public int Port { get; set; } = 21;

    /// <summary>
    /// Protocol to use when connecting to the backend
    /// </summary>
    public Protocol Protocol { get; set; } = Protocol.Ftp;

    /// <summary>
    /// Credential mapping type for this backend
    /// </summary>
    public CredentialMappingType CredentialMapping { get; set; } = CredentialMappingType.Passthrough;

    /// <summary>
    /// Service account username (if using ServiceAccount credential mapping)
    /// </summary>
    public string? ServiceAccountUsername { get; set; }

    /// <summary>
    /// Service account password (if using ServiceAccount credential mapping)
    /// </summary>
    public string? ServiceAccountPassword { get; set; }

    /// <summary>
    /// Whether this backend server is enabled
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Optional description for this backend server
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Connection timeout in milliseconds
    /// </summary>
    public int ConnectionTimeoutMs { get; set; } = 30000;

    /// <summary>
    /// Maximum concurrent connections allowed to this backend (0 = unlimited)
    /// </summary>
    public int MaxConnections { get; set; } = 0;
}
