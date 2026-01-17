using FtpReverseProxy.Core.Models;

namespace FtpReverseProxy.Core.Interfaces;

/// <summary>
/// Service for mapping client credentials to backend credentials
/// </summary>
public interface ICredentialMapper
{
    /// <summary>
    /// Maps client credentials to backend credentials based on the route and backend configuration
    /// </summary>
    /// <param name="clientUsername">Username provided by the client</param>
    /// <param name="clientPassword">Password provided by the client</param>
    /// <param name="route">The resolved route mapping</param>
    /// <param name="backend">The target backend server</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>The credentials to use when connecting to the backend</returns>
    Task<BackendCredentials> MapCredentialsAsync(
        string clientUsername,
        string clientPassword,
        RouteMapping route,
        BackendServer backend,
        CancellationToken cancellationToken = default);
}
