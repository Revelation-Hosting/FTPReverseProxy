using FtpReverseProxy.Core.Models;

namespace FtpReverseProxy.Core.Interfaces;

/// <summary>
/// Manages active proxy sessions
/// </summary>
public interface ISessionManager
{
    /// <summary>
    /// Registers a new session
    /// </summary>
    /// <param name="session">The session to register</param>
    void RegisterSession(ProxySession session);

    /// <summary>
    /// Removes a session
    /// </summary>
    /// <param name="sessionId">The session ID to remove</param>
    void RemoveSession(Guid sessionId);

    /// <summary>
    /// Gets a session by ID
    /// </summary>
    /// <param name="sessionId">The session ID</param>
    /// <returns>The session if found, null otherwise</returns>
    ProxySession? GetSession(Guid sessionId);

    /// <summary>
    /// Gets all active sessions
    /// </summary>
    /// <returns>All active sessions</returns>
    IEnumerable<ProxySession> GetAllSessions();

    /// <summary>
    /// Gets the count of active sessions
    /// </summary>
    int ActiveSessionCount { get; }

    /// <summary>
    /// Gets the count of sessions connected to a specific backend
    /// </summary>
    /// <param name="backendId">The backend server ID</param>
    /// <returns>Number of active sessions to that backend</returns>
    int GetSessionCountForBackend(string backendId);

    /// <summary>
    /// Waits for all active sessions to complete or until timeout
    /// </summary>
    /// <param name="timeout">Maximum time to wait</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if all sessions completed, false if timeout occurred</returns>
    Task<bool> WaitForDrainAsync(TimeSpan timeout, CancellationToken cancellationToken = default);

    /// <summary>
    /// Signals that the system is shutting down (new connections may be rejected)
    /// </summary>
    bool IsShuttingDown { get; set; }
}
