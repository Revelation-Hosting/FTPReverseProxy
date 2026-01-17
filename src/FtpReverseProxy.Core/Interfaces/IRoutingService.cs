using FtpReverseProxy.Core.Models;

namespace FtpReverseProxy.Core.Interfaces;

/// <summary>
/// Service for resolving which backend server a connection should be routed to
/// </summary>
public interface IRoutingService
{
    /// <summary>
    /// Resolves the backend server for a given username
    /// </summary>
    /// <param name="username">The username from the FTP USER command</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The route mapping if found, null otherwise</returns>
    Task<RouteMapping?> ResolveRouteAsync(string username, CancellationToken cancellationToken = default);

    /// <summary>
    /// Gets a backend server by its ID
    /// </summary>
    /// <param name="backendId">The backend server ID</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The backend server if found, null otherwise</returns>
    Task<BackendServer?> GetBackendAsync(string backendId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Parses the username to extract routing information
    /// For example, "user@server" might extract "user" and route to "server"
    /// </summary>
    /// <param name="rawUsername">The raw username from the client</param>
    /// <returns>The parsed username (without routing suffix) and optional backend hint</returns>
    (string Username, string? BackendHint) ParseUsername(string rawUsername);
}
