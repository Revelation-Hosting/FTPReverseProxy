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

    private static readonly TimeSpan CacheDuration = TimeSpan.FromMinutes(5);
    private const string RouteCachePrefix = "route:";
    private const string BackendCachePrefix = "backend:";

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
            _logger.LogDebug("Cache hit for route: {Username}", parsedUsername);
            return JsonSerializer.Deserialize<RouteMapping>(cachedJson);
        }

        // Cache miss - query database
        _logger.LogDebug("Cache miss for route: {Username}", parsedUsername);
        var route = await _routeMappingRepository.GetByUsernameAsync(parsedUsername, cancellationToken);

        if (route is not null)
        {
            // Cache the result
            var json = JsonSerializer.Serialize(route);
            await _cache.SetStringAsync(cacheKey, json, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = CacheDuration
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
            _logger.LogDebug("Cache hit for backend: {BackendId}", backendId);
            return JsonSerializer.Deserialize<BackendServer>(cachedJson);
        }

        // Cache miss - query database
        _logger.LogDebug("Cache miss for backend: {BackendId}", backendId);
        var backend = await _backendServerRepository.GetByIdAsync(backendId, cancellationToken);

        if (backend is not null)
        {
            // Cache the result
            var json = JsonSerializer.Serialize(backend);
            await _cache.SetStringAsync(cacheKey, json, new DistributedCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = CacheDuration
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
    /// Invalidates the cache for a specific backend server
    /// </summary>
    public async Task InvalidateBackendCacheAsync(string backendId, CancellationToken cancellationToken = default)
    {
        var cacheKey = $"{BackendCachePrefix}{backendId}";
        await _cache.RemoveAsync(cacheKey, cancellationToken);
        _logger.LogDebug("Invalidated backend cache for: {BackendId}", backendId);
    }
}
