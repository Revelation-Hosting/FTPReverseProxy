using FtpReverseProxy.Core.Enums;

namespace FtpReverseProxy.Data.Entities;

/// <summary>
/// Database entity for backend FTP servers
/// </summary>
public class BackendServerEntity
{
    public required string Id { get; set; }
    public required string Name { get; set; }
    public required string Host { get; set; }
    public int Port { get; set; } = 21;
    public Protocol Protocol { get; set; } = Protocol.Ftp;
    public CredentialMappingType CredentialMapping { get; set; } = CredentialMappingType.Passthrough;
    public string? ServiceAccountUsername { get; set; }
    public string? ServiceAccountPassword { get; set; }
    public bool IsEnabled { get; set; } = true;
    public string? Description { get; set; }
    public int ConnectionTimeoutMs { get; set; } = 30000;
    public int MaxConnections { get; set; } = 0;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ModifiedAt { get; set; }

    /// <summary>
    /// Client-facing hostname(s) for SNI certificate selection (comma-separated)
    /// </summary>
    public string? ClientFacingHostnames { get; set; }

    /// <summary>
    /// Path to the client-facing TLS certificate (PFX format) for this backend
    /// </summary>
    public string? ClientCertificatePath { get; set; }

    /// <summary>
    /// Password for the client-facing certificate file
    /// </summary>
    public string? ClientCertificatePassword { get; set; }

    /// <summary>
    /// Skip TLS certificate validation when connecting to this backend
    /// </summary>
    public bool SkipCertificateValidation { get; set; } = false;

    // Navigation
    public ICollection<RouteMappingEntity> RouteMappings { get; set; } = new List<RouteMappingEntity>();
}
