using System.Collections.Concurrent;
using FtpReverseProxy.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Data.Services;

/// <summary>
/// Thread-safe connection tracker for enforcing backend connection limits
/// </summary>
public class ConnectionTracker : IConnectionTracker
{
    private readonly ConcurrentDictionary<string, int> _connectionCounts = new();
    private readonly object _lock = new();
    private readonly ILogger<ConnectionTracker> _logger;

    public ConnectionTracker(ILogger<ConnectionTracker> logger)
    {
        _logger = logger;
    }

    public bool TryAcquireConnection(string backendId, int maxConnections)
    {
        // Unlimited connections
        if (maxConnections <= 0)
        {
            _connectionCounts.AddOrUpdate(backendId, 1, (_, count) => count + 1);
            return true;
        }

        lock (_lock)
        {
            var currentCount = _connectionCounts.GetOrAdd(backendId, 0);

            if (currentCount >= maxConnections)
            {
                _logger.LogWarning(
                    "Connection limit reached for backend {BackendId}: {Current}/{Max}",
                    backendId, currentCount, maxConnections);
                return false;
            }

            _connectionCounts[backendId] = currentCount + 1;
            _logger.LogDebug(
                "Acquired connection for backend {BackendId}: {Current}/{Max}",
                backendId, currentCount + 1, maxConnections);
            return true;
        }
    }

    public void ReleaseConnection(string backendId)
    {
        _connectionCounts.AddOrUpdate(
            backendId,
            0,
            (_, count) => Math.Max(0, count - 1));

        var newCount = _connectionCounts.GetOrAdd(backendId, 0);
        _logger.LogDebug("Released connection for backend {BackendId}: {Current} remaining", backendId, newCount);
    }

    public int GetConnectionCount(string backendId)
    {
        return _connectionCounts.GetOrAdd(backendId, 0);
    }

    public IReadOnlyDictionary<string, int> GetAllConnectionCounts()
    {
        return new Dictionary<string, int>(_connectionCounts);
    }
}
