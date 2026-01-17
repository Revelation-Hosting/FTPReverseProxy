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
}
