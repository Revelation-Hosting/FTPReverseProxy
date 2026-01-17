namespace FtpReverseProxy.Core.Models;

/// <summary>
/// Represents a mapping from a username pattern to a backend server
/// </summary>
public class RouteMapping
{
    /// <summary>
    /// Unique identifier for this route mapping
    /// </summary>
    public required string Id { get; set; }

    /// <summary>
    /// The username to match (exact match)
    /// </summary>
    public required string Username { get; set; }

    /// <summary>
    /// The ID of the backend server to route to
    /// </summary>
    public required string BackendServerId { get; set; }

    /// <summary>
    /// Optional: Override username when connecting to backend
    /// If null, uses the original username (possibly with prefix/suffix stripped)
    /// </summary>
    public string? BackendUsername { get; set; }

    /// <summary>
    /// Optional: Override password when connecting to backend
    /// If null, uses the original password
    /// </summary>
    public string? BackendPassword { get; set; }

    /// <summary>
    /// Whether this route mapping is enabled
    /// </summary>
    public bool IsEnabled { get; set; } = true;

    /// <summary>
    /// Priority for route matching (lower = higher priority)
    /// </summary>
    public int Priority { get; set; } = 100;

    /// <summary>
    /// Optional description for this route
    /// </summary>
    public string? Description { get; set; }

    /// <summary>
    /// Timestamp when this route was created
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Timestamp when this route was last modified
    /// </summary>
    public DateTime? ModifiedAt { get; set; }
}
