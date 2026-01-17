using FtpReverseProxy.Core.Enums;
using FtpReverseProxy.Core.Models;
using FtpReverseProxy.Data.Repositories;
using FtpReverseProxy.Data.Services;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Moq;
using System.Text;
using System.Text.Json;

namespace FtpReverseProxy.Tests.Unit.Services;

public class CachedRoutingServiceTests
{
    private readonly Mock<IRouteMappingRepository> _routeRepoMock;
    private readonly Mock<IBackendServerRepository> _backendRepoMock;
    private readonly Mock<IDistributedCache> _cacheMock;
    private readonly CachedRoutingService _service;

    public CachedRoutingServiceTests()
    {
        _routeRepoMock = new Mock<IRouteMappingRepository>();
        _backendRepoMock = new Mock<IBackendServerRepository>();
        _cacheMock = new Mock<IDistributedCache>();
        var logger = new Mock<ILogger<CachedRoutingService>>();

        _service = new CachedRoutingService(
            _routeRepoMock.Object,
            _backendRepoMock.Object,
            _cacheMock.Object,
            logger.Object);
    }

    #region ParseUsername Tests

    [Fact]
    public void ParseUsername_SimpleUsername_ReturnsUsernameOnly()
    {
        var (username, backendHint) = _service.ParseUsername("testuser");

        Assert.Equal("testuser", username);
        Assert.Null(backendHint);
    }

    [Fact]
    public void ParseUsername_WithAtSymbol_SplitsCorrectly()
    {
        var (username, backendHint) = _service.ParseUsername("user@backend");

        Assert.Equal("user", username);
        Assert.Equal("backend", backendHint);
    }

    [Fact]
    public void ParseUsername_WithBackslash_SplitsCorrectly()
    {
        var (username, backendHint) = _service.ParseUsername("domain\\user");

        Assert.Equal("user", username);
        Assert.Equal("domain", backendHint);
    }

    [Fact]
    public void ParseUsername_WithMultipleAtSymbols_SplitsOnFirst()
    {
        var (username, backendHint) = _service.ParseUsername("user@domain@backend");

        Assert.Equal("user", username);
        Assert.Equal("domain@backend", backendHint);
    }

    [Fact]
    public void ParseUsername_EmptyString_ReturnsEmpty()
    {
        var (username, backendHint) = _service.ParseUsername("");

        Assert.Equal("", username);
        Assert.Null(backendHint);
    }

    [Fact]
    public void ParseUsername_JustAtSymbol_ReturnsEmptyUsername()
    {
        var (username, backendHint) = _service.ParseUsername("@backend");

        Assert.Equal("", username);
        Assert.Equal("backend", backendHint);
    }

    #endregion

    #region ResolveRouteAsync Tests

    [Fact]
    public async Task ResolveRouteAsync_CacheHit_ReturnsCachedRoute()
    {
        var route = CreateRoute("user1");
        var cachedJson = JsonSerializer.Serialize(route);

        _cacheMock.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Encoding.UTF8.GetBytes(cachedJson));

        var result = await _service.ResolveRouteAsync("user1");

        Assert.NotNull(result);
        Assert.Equal("user1", result.Username);
        _routeRepoMock.Verify(r => r.GetByUsernameAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ResolveRouteAsync_CacheMiss_QueriesRepository()
    {
        var route = CreateRoute("user1");

        _cacheMock.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((byte[]?)null);

        _routeRepoMock.Setup(r => r.GetByUsernameAsync("user1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(route);

        var result = await _service.ResolveRouteAsync("user1");

        Assert.NotNull(result);
        Assert.Equal("user1", result.Username);
        _routeRepoMock.Verify(r => r.GetByUsernameAsync("user1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ResolveRouteAsync_NotFound_ReturnsNull()
    {
        _cacheMock.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((byte[]?)null);

        _routeRepoMock.Setup(r => r.GetByUsernameAsync("unknown", It.IsAny<CancellationToken>()))
            .ReturnsAsync((RouteMapping?)null);

        var result = await _service.ResolveRouteAsync("unknown");

        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveRouteAsync_NegativeCache_ReturnsNull()
    {
        _cacheMock.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Encoding.UTF8.GetBytes("__NULL__"));

        var result = await _service.ResolveRouteAsync("unknown");

        Assert.Null(result);
        _routeRepoMock.Verify(r => r.GetByUsernameAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ResolveRouteAsync_CachesResult()
    {
        _cacheMock.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((byte[]?)null);

        _routeRepoMock.Setup(r => r.GetByUsernameAsync("user1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateRoute("user1"));

        await _service.ResolveRouteAsync("user1");

        _cacheMock.Verify(c => c.SetAsync(
            It.Is<string>(k => k.Contains("route:user1")),
            It.IsAny<byte[]>(),
            It.IsAny<DistributedCacheEntryOptions>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ResolveRouteAsync_CachesNegativeResult()
    {
        _cacheMock.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((byte[]?)null);

        _routeRepoMock.Setup(r => r.GetByUsernameAsync("unknown", It.IsAny<CancellationToken>()))
            .ReturnsAsync((RouteMapping?)null);

        await _service.ResolveRouteAsync("unknown");

        _cacheMock.Verify(c => c.SetAsync(
            It.Is<string>(k => k.Contains("route:unknown")),
            It.Is<byte[]>(b => Encoding.UTF8.GetString(b) == "__NULL__"),
            It.IsAny<DistributedCacheEntryOptions>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ResolveRouteAsync_WithAtSyntax_ParsesUsername()
    {
        _cacheMock.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((byte[]?)null);

        _routeRepoMock.Setup(r => r.GetByUsernameAsync("user", It.IsAny<CancellationToken>()))
            .ReturnsAsync(CreateRoute("user"));

        await _service.ResolveRouteAsync("user@backend");

        _routeRepoMock.Verify(r => r.GetByUsernameAsync("user", It.IsAny<CancellationToken>()), Times.Once);
    }

    #endregion

    #region GetBackendAsync Tests

    [Fact]
    public async Task GetBackendAsync_CacheHit_ReturnsCachedBackend()
    {
        var backend = CreateBackend("backend1");
        var cachedJson = JsonSerializer.Serialize(backend);

        _cacheMock.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Encoding.UTF8.GetBytes(cachedJson));

        var result = await _service.GetBackendAsync("backend1");

        Assert.NotNull(result);
        Assert.Equal("backend1", result.Id);
        _backendRepoMock.Verify(r => r.GetByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetBackendAsync_CacheMiss_QueriesRepository()
    {
        var backend = CreateBackend("backend1");

        _cacheMock.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((byte[]?)null);

        _backendRepoMock.Setup(r => r.GetByIdAsync("backend1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(backend);

        var result = await _service.GetBackendAsync("backend1");

        Assert.NotNull(result);
        Assert.Equal("backend1", result.Id);
    }

    [Fact]
    public async Task GetBackendAsync_NotFound_ReturnsNull()
    {
        _cacheMock.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((byte[]?)null);

        _backendRepoMock.Setup(r => r.GetByIdAsync("unknown", It.IsAny<CancellationToken>()))
            .ReturnsAsync((BackendServer?)null);

        var result = await _service.GetBackendAsync("unknown");

        Assert.Null(result);
    }

    [Fact]
    public async Task GetBackendAsync_NegativeCache_ReturnsNull()
    {
        _cacheMock.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Encoding.UTF8.GetBytes("__NULL__"));

        var result = await _service.GetBackendAsync("unknown");

        Assert.Null(result);
        _backendRepoMock.Verify(r => r.GetByIdAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task GetBackendAsync_CachesByIdAndName()
    {
        var backend = CreateBackend("backend1", "TestBackend");

        _cacheMock.Setup(c => c.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((byte[]?)null);

        _backendRepoMock.Setup(r => r.GetByIdAsync("backend1", It.IsAny<CancellationToken>()))
            .ReturnsAsync(backend);

        await _service.GetBackendAsync("backend1");

        // Should cache by both ID and name
        _cacheMock.Verify(c => c.SetAsync(
            It.Is<string>(k => k.Contains("backend:backend1")),
            It.IsAny<byte[]>(),
            It.IsAny<DistributedCacheEntryOptions>(),
            It.IsAny<CancellationToken>()), Times.Once);

        _cacheMock.Verify(c => c.SetAsync(
            It.Is<string>(k => k.Contains("backend_name:TestBackend")),
            It.IsAny<byte[]>(),
            It.IsAny<DistributedCacheEntryOptions>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    #endregion

    #region Cache Invalidation Tests

    [Fact]
    public async Task InvalidateRouteCacheAsync_RemovesFromCache()
    {
        await _service.InvalidateRouteCacheAsync("user1");

        _cacheMock.Verify(c => c.RemoveAsync("route:user1", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task InvalidateBackendCacheAsync_RemovesFromCache()
    {
        await _service.InvalidateBackendCacheAsync("backend1");

        _cacheMock.Verify(c => c.RemoveAsync("backend:backend1", It.IsAny<CancellationToken>()), Times.Once);
    }

    #endregion

    private static RouteMapping CreateRoute(string username)
    {
        return new RouteMapping
        {
            Id = $"route-{username}",
            Username = username,
            BackendServerId = "backend-1",
            IsEnabled = true,
            Priority = 1
        };
    }

    private static BackendServer CreateBackend(string id, string name = "TestBackend")
    {
        return new BackendServer
        {
            Id = id,
            Name = name,
            Host = "localhost",
            Port = 21,
            Protocol = Protocol.Ftp,
            CredentialMapping = CredentialMappingType.Passthrough,
            IsEnabled = true,
            MaxConnections = 0,
            ConnectionTimeoutMs = 30000
        };
    }
}
