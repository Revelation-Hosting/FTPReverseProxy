namespace FtpReverseProxy.Core.Interfaces;

/// <summary>
/// Tracks active connections to backend servers for enforcing connection limits
/// </summary>
public interface IConnectionTracker
{
    /// <summary>
    /// Attempts to acquire a connection slot for a backend server
    /// </summary>
    /// <param name="backendId">The backend server ID</param>
    /// <param name="maxConnections">Maximum connections allowed (0 = unlimited)</param>
    /// <returns>True if a slot was acquired, false if at limit</returns>
    bool TryAcquireConnection(string backendId, int maxConnections);

    /// <summary>
    /// Releases a connection slot for a backend server
    /// </summary>
    /// <param name="backendId">The backend server ID</param>
    void ReleaseConnection(string backendId);

    /// <summary>
    /// Gets the current connection count for a backend server
    /// </summary>
    /// <param name="backendId">The backend server ID</param>
    /// <returns>Current active connection count</returns>
    int GetConnectionCount(string backendId);

    /// <summary>
    /// Gets connection counts for all tracked backends
    /// </summary>
    /// <returns>Dictionary of backend ID to connection count</returns>
    IReadOnlyDictionary<string, int> GetAllConnectionCounts();
}
