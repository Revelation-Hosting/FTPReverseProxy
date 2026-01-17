using FtpReverseProxy.Core.Enums;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Core.Models;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Data.Services;

/// <summary>
/// Maps client credentials to backend credentials based on configuration
/// </summary>
public class CredentialMapper : ICredentialMapper
{
    private readonly ILogger<CredentialMapper> _logger;

    public CredentialMapper(ILogger<CredentialMapper> logger)
    {
        _logger = logger;
    }

    public Task<BackendCredentials> MapCredentialsAsync(
        string clientUsername,
        string clientPassword,
        RouteMapping route,
        BackendServer backend,
        CancellationToken cancellationToken = default)
    {
        BackendCredentials credentials;

        switch (backend.CredentialMapping)
        {
            case CredentialMappingType.Passthrough:
                // Use credentials from route override if specified, otherwise pass through
                credentials = new BackendCredentials
                {
                    Username = route.BackendUsername ?? clientUsername,
                    Password = route.BackendPassword ?? clientPassword,
                    OriginalUsername = clientUsername
                };
                break;

            case CredentialMappingType.ServiceAccount:
                // Use service account credentials from backend config
                if (string.IsNullOrEmpty(backend.ServiceAccountUsername) ||
                    string.IsNullOrEmpty(backend.ServiceAccountPassword))
                {
                    throw new InvalidOperationException(
                        $"Backend '{backend.Id}' is configured for ServiceAccount but credentials are not set");
                }

                credentials = new BackendCredentials
                {
                    Username = backend.ServiceAccountUsername,
                    Password = backend.ServiceAccountPassword,
                    OriginalUsername = clientUsername
                };
                break;

            case CredentialMappingType.Mapped:
                // Use mapped credentials from route
                if (string.IsNullOrEmpty(route.BackendUsername) ||
                    string.IsNullOrEmpty(route.BackendPassword))
                {
                    throw new InvalidOperationException(
                        $"Route '{route.Id}' is configured for Mapped credentials but they are not set");
                }

                credentials = new BackendCredentials
                {
                    Username = route.BackendUsername,
                    Password = route.BackendPassword,
                    OriginalUsername = clientUsername
                };
                break;

            case CredentialMappingType.SameUserInternalPassword:
                // Same username, but use route's backend password
                if (string.IsNullOrEmpty(route.BackendPassword))
                {
                    throw new InvalidOperationException(
                        $"Route '{route.Id}' is configured for SameUserInternalPassword but password is not set");
                }

                credentials = new BackendCredentials
                {
                    Username = clientUsername,
                    Password = route.BackendPassword,
                    OriginalUsername = clientUsername
                };
                break;

            default:
                throw new ArgumentOutOfRangeException(
                    nameof(backend.CredentialMapping),
                    $"Unknown credential mapping type: {backend.CredentialMapping}");
        }

        _logger.LogDebug(
            "Mapped credentials for {ClientUser} -> {BackendUser} using {MappingType}",
            clientUsername,
            credentials.Username,
            backend.CredentialMapping);

        return Task.FromResult(credentials);
    }
}
