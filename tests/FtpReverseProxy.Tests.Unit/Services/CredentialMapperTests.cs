using FtpReverseProxy.Core.Enums;
using FtpReverseProxy.Core.Models;
using FtpReverseProxy.Data.Services;
using Microsoft.Extensions.Logging;
using Moq;

namespace FtpReverseProxy.Tests.Unit.Services;

public class CredentialMapperTests
{
    private readonly CredentialMapper _mapper;

    public CredentialMapperTests()
    {
        var logger = new Mock<ILogger<CredentialMapper>>();
        _mapper = new CredentialMapper(logger.Object);
    }

    [Fact]
    public async Task MapCredentials_Passthrough_UsesClientCredentials()
    {
        var route = CreateRoute();
        var backend = CreateBackend(CredentialMappingType.Passthrough);

        var result = await _mapper.MapCredentialsAsync("clientuser", "clientpass", route, backend);

        Assert.Equal("clientuser", result.Username);
        Assert.Equal("clientpass", result.Password);
        Assert.Equal("clientuser", result.OriginalUsername);
    }

    [Fact]
    public async Task MapCredentials_Passthrough_WithRouteOverride_UsesRouteCredentials()
    {
        var route = CreateRoute(backendUsername: "routeuser", backendPassword: "routepass");
        var backend = CreateBackend(CredentialMappingType.Passthrough);

        var result = await _mapper.MapCredentialsAsync("clientuser", "clientpass", route, backend);

        Assert.Equal("routeuser", result.Username);
        Assert.Equal("routepass", result.Password);
        Assert.Equal("clientuser", result.OriginalUsername);
    }

    [Fact]
    public async Task MapCredentials_Passthrough_PartialOverride_UsesOverrideForUsername()
    {
        var route = CreateRoute(backendUsername: "routeuser");
        var backend = CreateBackend(CredentialMappingType.Passthrough);

        var result = await _mapper.MapCredentialsAsync("clientuser", "clientpass", route, backend);

        Assert.Equal("routeuser", result.Username);
        Assert.Equal("clientpass", result.Password);
    }

    [Fact]
    public async Task MapCredentials_ServiceAccount_UsesBackendServiceAccount()
    {
        var route = CreateRoute();
        var backend = CreateBackend(
            CredentialMappingType.ServiceAccount,
            serviceAccountUsername: "svcuser",
            serviceAccountPassword: "svcpass");

        var result = await _mapper.MapCredentialsAsync("clientuser", "clientpass", route, backend);

        Assert.Equal("svcuser", result.Username);
        Assert.Equal("svcpass", result.Password);
        Assert.Equal("clientuser", result.OriginalUsername);
    }

    [Fact]
    public async Task MapCredentials_ServiceAccount_WithoutCredentials_ThrowsException()
    {
        var route = CreateRoute();
        var backend = CreateBackend(CredentialMappingType.ServiceAccount);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _mapper.MapCredentialsAsync("clientuser", "clientpass", route, backend));
    }

    [Fact]
    public async Task MapCredentials_ServiceAccount_WithEmptyUsername_ThrowsException()
    {
        var route = CreateRoute();
        var backend = CreateBackend(
            CredentialMappingType.ServiceAccount,
            serviceAccountUsername: "",
            serviceAccountPassword: "pass");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _mapper.MapCredentialsAsync("clientuser", "clientpass", route, backend));
    }

    [Fact]
    public async Task MapCredentials_Mapped_UsesMappedCredentials()
    {
        var route = CreateRoute(backendUsername: "mappeduser", backendPassword: "mappedpass");
        var backend = CreateBackend(CredentialMappingType.Mapped);

        var result = await _mapper.MapCredentialsAsync("clientuser", "clientpass", route, backend);

        Assert.Equal("mappeduser", result.Username);
        Assert.Equal("mappedpass", result.Password);
        Assert.Equal("clientuser", result.OriginalUsername);
    }

    [Fact]
    public async Task MapCredentials_Mapped_WithoutCredentials_ThrowsException()
    {
        var route = CreateRoute();
        var backend = CreateBackend(CredentialMappingType.Mapped);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _mapper.MapCredentialsAsync("clientuser", "clientpass", route, backend));
    }

    [Fact]
    public async Task MapCredentials_SameUserInternalPassword_UsesClientUsernameWithRoutePassword()
    {
        var route = CreateRoute(backendPassword: "internalpass");
        var backend = CreateBackend(CredentialMappingType.SameUserInternalPassword);

        var result = await _mapper.MapCredentialsAsync("clientuser", "clientpass", route, backend);

        Assert.Equal("clientuser", result.Username);
        Assert.Equal("internalpass", result.Password);
        Assert.Equal("clientuser", result.OriginalUsername);
    }

    [Fact]
    public async Task MapCredentials_SameUserInternalPassword_WithoutPassword_ThrowsException()
    {
        var route = CreateRoute();
        var backend = CreateBackend(CredentialMappingType.SameUserInternalPassword);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _mapper.MapCredentialsAsync("clientuser", "clientpass", route, backend));
    }

    [Fact]
    public async Task MapCredentials_PreservesOriginalUsername()
    {
        var route = CreateRoute(backendUsername: "differentuser", backendPassword: "pass");
        var backend = CreateBackend(CredentialMappingType.Mapped);

        var result = await _mapper.MapCredentialsAsync("originaluser", "clientpass", route, backend);

        Assert.Equal("differentuser", result.Username);
        Assert.Equal("originaluser", result.OriginalUsername);
    }

    [Fact]
    public async Task MapCredentials_EmptyClientUsername_StillMaps()
    {
        var route = CreateRoute();
        var backend = CreateBackend(CredentialMappingType.Passthrough);

        var result = await _mapper.MapCredentialsAsync("", "clientpass", route, backend);

        Assert.Equal("", result.Username);
        Assert.Equal("clientpass", result.Password);
    }

    private static RouteMapping CreateRoute(
        string? backendUsername = null,
        string? backendPassword = null)
    {
        return new RouteMapping
        {
            Id = "route-1",
            Username = "testuser",
            BackendServerId = "backend-1",
            BackendUsername = backendUsername,
            BackendPassword = backendPassword,
            IsEnabled = true,
            Priority = 1
        };
    }

    private static BackendServer CreateBackend(
        CredentialMappingType mappingType,
        string? serviceAccountUsername = null,
        string? serviceAccountPassword = null)
    {
        return new BackendServer
        {
            Id = "backend-1",
            Name = "Test Backend",
            Host = "localhost",
            Port = 21,
            Protocol = Protocol.Ftp,
            CredentialMapping = mappingType,
            ServiceAccountUsername = serviceAccountUsername,
            ServiceAccountPassword = serviceAccountPassword,
            IsEnabled = true,
            MaxConnections = 0,
            ConnectionTimeoutMs = 30000
        };
    }
}
