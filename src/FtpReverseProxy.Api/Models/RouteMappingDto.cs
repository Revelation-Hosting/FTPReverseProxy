namespace FtpReverseProxy.Api.Models;

/// <summary>
/// Response DTO for route mapping
/// </summary>
public record RouteMappingDto(
    string Id,
    string Username,
    string BackendServerId,
    string? BackendServerName,
    string? BackendUsername,
    bool IsEnabled,
    int Priority,
    string? Description,
    DateTime CreatedAt,
    DateTime? ModifiedAt);

/// <summary>
/// Request DTO for creating a route mapping
/// </summary>
public record CreateRouteMappingRequest(
    string Username,
    string BackendServerId,
    string? BackendUsername = null,
    string? BackendPassword = null,
    bool IsEnabled = true,
    int Priority = 100,
    string? Description = null);

/// <summary>
/// Request DTO for updating a route mapping
/// </summary>
public record UpdateRouteMappingRequest(
    string Username,
    string BackendServerId,
    string? BackendUsername,
    string? BackendPassword,
    bool IsEnabled,
    int Priority,
    string? Description);
