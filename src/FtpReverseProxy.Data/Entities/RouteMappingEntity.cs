namespace FtpReverseProxy.Data.Entities;

/// <summary>
/// Database entity for username-to-backend route mappings
/// </summary>
public class RouteMappingEntity
{
    public required string Id { get; set; }
    public required string Username { get; set; }
    public required string BackendServerId { get; set; }
    public string? BackendUsername { get; set; }
    public string? BackendPassword { get; set; }

    /// <summary>
    /// SSH public key for key-based authentication (e.g., "ssh-ed25519 AAAAC3NzaC...")
    /// When set, the proxy validates the client's key before connecting to backend
    /// </summary>
    public string? PublicKey { get; set; }

    public bool IsEnabled { get; set; } = true;
    public int Priority { get; set; } = 100;
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ModifiedAt { get; set; }

    // Navigation
    public BackendServerEntity? BackendServer { get; set; }
}
