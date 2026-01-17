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
    public bool IsEnabled { get; set; } = true;
    public int Priority { get; set; } = 100;
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? ModifiedAt { get; set; }

    // Navigation
    public BackendServerEntity? BackendServer { get; set; }
}
