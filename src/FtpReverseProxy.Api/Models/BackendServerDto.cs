using FtpReverseProxy.Core.Enums;

namespace FtpReverseProxy.Api.Models;

/// <summary>
/// Response DTO for backend server
/// </summary>
public record BackendServerDto(
    string Id,
    string Name,
    string Host,
    int Port,
    Protocol Protocol,
    CredentialMappingType CredentialMapping,
    bool IsEnabled,
    string? Description,
    int ConnectionTimeoutMs,
    int MaxConnections,
    DateTime CreatedAt,
    DateTime? ModifiedAt,
    int RouteMappingsCount);

/// <summary>
/// Request DTO for creating a backend server
/// </summary>
public record CreateBackendServerRequest(
    string Name,
    string Host,
    int Port = 21,
    Protocol Protocol = Protocol.Ftp,
    CredentialMappingType CredentialMapping = CredentialMappingType.Passthrough,
    string? ServiceAccountUsername = null,
    string? ServiceAccountPassword = null,
    bool IsEnabled = true,
    string? Description = null,
    int ConnectionTimeoutMs = 30000,
    int MaxConnections = 0);

/// <summary>
/// Request DTO for updating a backend server
/// </summary>
public record UpdateBackendServerRequest(
    string Name,
    string Host,
    int Port,
    Protocol Protocol,
    CredentialMappingType CredentialMapping,
    string? ServiceAccountUsername,
    string? ServiceAccountPassword,
    bool IsEnabled,
    string? Description,
    int ConnectionTimeoutMs,
    int MaxConnections);
