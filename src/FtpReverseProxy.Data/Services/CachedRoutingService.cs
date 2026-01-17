using System.Text.Json;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Core.Models;
using FtpReverseProxy.Data.Repositories;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Data.Services;

/// <summary>
/// Routing service with Redis caching for scalability
/// </summary>
public class CachedRoutingService : IRoutingService
{
    private readonly IRouteMappingRepository _routeMappingRepository;
    private readonly IBackendServerRepository _backendServerRepository;
    private readonly IDistributedCache _cache;
    private readonly ILogger<CachedRoutingService> _logger;

    // Cache configuration
    private static readonly TimeSpan CacheAbsoluteExpiration = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan CacheSlidingExpiration = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan NegativeCacheDuration = TimeSpan.FromSeconds(30);

    private const string RouteCachePrefix = "route:";
    private const string BackendCachePrefix = "backend:";
    private const string BackendByNameCachePrefix = "backend_name:";
    private const string NegativeCacheMarker = "__NULL__";

    public CachedRoutingService(
        IRouteMappingRepository routeMappingRepository,
        IBackendServerRepository backendServerRepository,
        IDistributedCache cache,
        ILogger<CachedRoutingService> logger)
    {
        _routeMappingRepository = routeMappingRepository;
        _backendServerRepository = backendServerRepository;
        _cache = cache;
        _logger = logger;
    }

    public async Task<RouteMapping?> ResolveRouteAsync(string username, CancellationToken cancellationToken = default)
    {
        var (parsedUsername, backendHint) = ParseUsername(username);
        var cacheKey = $"{RouteCachePrefix}{parsedUsername}";

        // Try cache first
        var cachedJson = await _cache.GetStringAsync(cacheKey, cancellationToken);
        if (!string.IsNullOrEmpty(cachedJson))
        {
            // Check for negative cache marker
            if (cachedJson == NegativeCacheMarker)
            {
                _logger.LogDebug("Negative cache hit for route: {Username}", parsedUsername);
                return null;
            }

            _logger.LogDebug("Cache hit for route: {Username}", parsedUsername);
            return JsonSerializer.Deserialize<RouteMapping>(cachedJson);
        }

        // Cache miss - query database
        _logger.LogDebug("Cache miss for route: {Username}", parsedUsername);
        var route = await _routeMappingRepository.GetByUsernameAsync(parsedUsername, cancellationToken);

        if (route is not null)
        {
            // Cache positive result with sliding expiration
            var json = JsonSerializer.Serialize(route);
            await _cache.SetStringAsync(cacheKey, json, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = CacheAbsoluteExpiration,
                SlidingExpiration = CacheSlidingExpiration
            }, cancellationToken);
        }
        else
        {
            // Cache negative result for shorter duration to prevent repeated DB queries
            await _cache.SetStringAsync(cacheKey, NegativeCacheMarker, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = NegativeCacheDuration
            }, cancellationToken);
        }

        return route;
    }

    public async Task<BackendServer?> GetBackendAsync(string backendId, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"{BackendCachePrefix}{backendId}";

        // Try cache first
        var cachedJson = await _cache.GetStringAsync(cacheKey, cancellationToken);
        if (!string.IsNullOrEmpty(cachedJson))
        {
            if (cachedJson == NegativeCacheMarker)
            {
                _logger.LogDebug("Negative cache hit for backend: {BackendId}", backendId);
                return null;
            }

            _logger.LogDebug("Cache hit for backend: {BackendId}", backendId);
            return JsonSerializer.Deserialize<BackendServer>(cachedJson);
        }

        // Cache miss - query database
        _logger.LogDebug("Cache miss for backend: {BackendId}", backendId);
        var backend = await _backendServerRepository.GetByIdAsync(backendId, cancellationToken);

        if (backend is not null)
        {
            // Cache positive result
            var json = JsonSerializer.Serialize(backend);
            await _cache.SetStringAsync(cacheKey, json, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = CacheAbsoluteExpiration,
                SlidingExpiration = CacheSlidingExpiration
            }, cancellationToken);

            // Also cache by name for fast lookup
            var nameKey = $"{BackendByNameCachePrefix}{backend.Name}";
            await _cache.SetStringAsync(nameKey, json, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = CacheAbsoluteExpiration,
                SlidingExpiration = CacheSlidingExpiration
            }, cancellationToken);
        }
        else
        {
            // Cache negative result
            await _cache.SetStringAsync(cacheKey, NegativeCacheMarker, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = NegativeCacheDuration
            }, cancellationToken);
        }

        return backend;
    }

    /// <summary>
    /// Gets a backend server by name (with caching)
    /// </summary>
    public async Task<BackendServer?> GetBackendByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"{BackendByNameCachePrefix}{name}";

        var cachedJson = await _cache.GetStringAsync(cacheKey, cancellationToken);
        if (!string.IsNullOrEmpty(cachedJson))
        {
            if (cachedJson == NegativeCacheMarker)
            {
                return null;
            }
            return JsonSerializer.Deserialize<BackendServer>(cachedJson);
        }

        var backend = await _backendServerRepository.GetByNameAsync(name, cancellationToken);

        if (backend is not null)
        {
            var json = JsonSerializer.Serialize(backend);
            await _cache.SetStringAsync(cacheKey, json, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = CacheAbsoluteExpiration,
                SlidingExpiration = CacheSlidingExpiration
            }, cancellationToken);

            // Also cache by ID
            var idKey = $"{BackendCachePrefix}{backend.Id}";
            await _cache.SetStringAsync(idKey, json, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = CacheAbsoluteExpiration,
                SlidingExpiration = CacheSlidingExpiration
            }, cancellationToken);
        }
        else
        {
            await _cache.SetStringAsync(cacheKey, NegativeCacheMarker, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = NegativeCacheDuration
            }, cancellationToken);
        }

        return backend;
    }

    public (string Username, string? BackendHint) ParseUsername(string rawUsername)
    {
        // Support formats like "user@backend" or "backend\user"
        if (rawUsername.Contains('@'))
        {
            var parts = rawUsername.Split('@', 2);
            return (parts[0], parts[1]);
        }

        if (rawUsername.Contains('\\'))
        {
            var parts = rawUsername.Split('\\', 2);
            return (parts[1], parts[0]);
        }

        return (rawUsername, null);
    }

    /// <summary>
    /// Invalidates the cache for a specific username route
    /// </summary>
    public async Task InvalidateRouteCacheAsync(string username, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"{RouteCachePrefix}{username}";
        await _cache.RemoveAsync(cacheKey, cancellationToken);
        _logger.LogDebug("Invalidated route cache for: {Username}", username);
    }

    /// <summary>
    /// Invalidates the cache for a specific backend server by ID
    /// </summary>
    public async Task InvalidateBackendCacheAsync(string backendId, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"{BackendCachePrefix}{backendId}";
        await _cache.RemoveAsync(cacheKey, cancellationToken);
        _logger.LogDebug("Invalidated backend cache for ID: {BackendId}", backendId);
    }

    /// <summary>
    /// Invalidates the cache for a backend server by both ID and name
    /// </summary>
    public async Task InvalidateBackendCacheAsync(string backendId, string backendName, CancellationToken cancellationToken = default)
    {
        var idKey = $"{BackendCachePrefix}{backendId}";
        var nameKey = $"{BackendByNameCachePrefix}{backendName}";

        await Task.WhenAll(
            _cache.RemoveAsync(idKey, cancellationToken),
            _cache.RemoveAsync(nameKey, cancellationToken));

        _logger.LogDebug("Invalidated backend cache for: {BackendId}/{BackendName}", backendId, backendName);
    }

    /// <summary>
    /// Invalidates all cache entries for a backend when its name might have changed
    /// </summary>
    public async Task InvalidateBackendCacheFullAsync(string backendId, string? oldName, string? newName, CancellationToken cancellationToken = default)
    {
        var tasks = new List<Task>
        {
            _cache.RemoveAsync($"{BackendCachePrefix}{backendId}", cancellationToken)
        };

        if (!string.IsNullOrEmpty(oldName))
        {
            tasks.Add(_cache.RemoveAsync($"{BackendByNameCachePrefix}{oldName}", cancellationToken));
        }

        if (!string.IsNullOrEmpty(newName) && newName != oldName)
        {
            tasks.Add(_cache.RemoveAsync($"{BackendByNameCachePrefix}{newName}", cancellationToken));
        }

        await Task.WhenAll(tasks);
        _logger.LogDebug("Invalidated full backend cache for: {BackendId}", backendId);
    }
}
