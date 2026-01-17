using System.Collections.Concurrent;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Core.Models;

namespace FtpReverseProxy.Ftp;

/// <summary>
/// In-memory session manager for tracking active proxy sessions
/// </summary>
public class SessionManager : ISessionManager
{
    private readonly ConcurrentDictionary<Guid, ProxySession> _sessions = new();

    public int ActiveSessionCount => _sessions.Count;

    public void RegisterSession(ProxySession session)
    {
        _sessions.TryAdd(session.Id, session);
    }

    public void RemoveSession(Guid sessionId)
    {
        _sessions.TryRemove(sessionId, out _);
    }

    public ProxySession? GetSession(Guid sessionId)
    {
        return _sessions.TryGetValue(sessionId, out var session) ? session : null;
    }

    public IEnumerable<ProxySession> GetAllSessions()
    {
        return _sessions.Values;
    }

    public int GetSessionCountForBackend(string backendId)
    {
        return _sessions.Values.Count(s => s.Backend?.Id == backendId);
    }
}
