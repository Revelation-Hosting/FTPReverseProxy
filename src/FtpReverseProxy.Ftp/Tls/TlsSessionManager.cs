using System.Collections.Concurrent;
using Org.BouncyCastle.Tls;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp.Tls;

/// <summary>
/// Manages TLS sessions for session resumption between control and data channels.
/// This is critical for FTPS servers that require data channel TLS sessions
/// to be resumptions of the control channel session.
/// </summary>
public class TlsSessionManager
{
    private readonly ConcurrentDictionary<Guid, SessionInfo> _sessions = new();
    private readonly ILogger<TlsSessionManager>? _logger;

    public TlsSessionManager(ILogger<TlsSessionManager>? logger = null)
    {
        _logger = logger;
    }

    /// <summary>
    /// Stores a TLS session for a proxy session, allowing data channels to resume it.
    /// </summary>
    public void StoreSession(Guid proxySessionId, TlsSession tlsSession, NewSessionTicket? sessionTicket = null)
    {
        var sessionInfo = new SessionInfo
        {
            TlsSession = tlsSession,
            SessionTicket = sessionTicket,
            CreatedAt = DateTime.UtcNow
        };

        _sessions[proxySessionId] = sessionInfo;

        _logger?.LogDebug(
            "Stored TLS session for proxy session {SessionId}. Resumable: {Resumable}",
            proxySessionId, tlsSession?.IsResumable ?? false);
    }

    /// <summary>
    /// Gets a stored TLS session for resumption.
    /// </summary>
    public TlsSession? GetSession(Guid proxySessionId)
    {
        if (_sessions.TryGetValue(proxySessionId, out var sessionInfo))
        {
            // Check if session is still valid (sessions typically expire after a few hours)
            if (DateTime.UtcNow - sessionInfo.CreatedAt < TimeSpan.FromHours(1))
            {
                _logger?.LogDebug(
                    "Retrieved TLS session for proxy session {SessionId}. Resumable: {Resumable}",
                    proxySessionId, sessionInfo.TlsSession?.IsResumable ?? false);
                return sessionInfo.TlsSession;
            }
            else
            {
                _logger?.LogDebug("TLS session for proxy session {SessionId} has expired", proxySessionId);
                _sessions.TryRemove(proxySessionId, out _);
            }
        }

        return null;
    }

    /// <summary>
    /// Gets the session ticket for a proxy session (used for TLS 1.2 session ticket resumption).
    /// </summary>
    public NewSessionTicket? GetSessionTicket(Guid proxySessionId)
    {
        if (_sessions.TryGetValue(proxySessionId, out var sessionInfo))
        {
            return sessionInfo.SessionTicket;
        }
        return null;
    }

    /// <summary>
    /// Removes a stored session when the proxy session ends.
    /// </summary>
    public void RemoveSession(Guid proxySessionId)
    {
        if (_sessions.TryRemove(proxySessionId, out _))
        {
            _logger?.LogDebug("Removed TLS session for proxy session {SessionId}", proxySessionId);
        }
    }

    /// <summary>
    /// Cleans up expired sessions.
    /// </summary>
    public void CleanupExpiredSessions()
    {
        var expiredSessions = _sessions
            .Where(kvp => DateTime.UtcNow - kvp.Value.CreatedAt > TimeSpan.FromHours(1))
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var sessionId in expiredSessions)
        {
            _sessions.TryRemove(sessionId, out _);
        }

        if (expiredSessions.Count > 0)
        {
            _logger?.LogDebug("Cleaned up {Count} expired TLS sessions", expiredSessions.Count);
        }
    }

    private class SessionInfo
    {
        public TlsSession? TlsSession { get; init; }
        public NewSessionTicket? SessionTicket { get; init; }
        public DateTime CreatedAt { get; init; }
    }
}
