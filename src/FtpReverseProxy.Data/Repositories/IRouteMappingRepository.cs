using FtpReverseProxy.Core.Models;

namespace FtpReverseProxy.Data.Repositories;

/// <summary>
/// Repository for route mapping operations
/// </summary>
public interface IRouteMappingRepository
{
    Task<RouteMapping?> GetByIdAsync(string id, CancellationToken cancellationToken = default);
    Task<RouteMapping?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<RouteMapping>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<RouteMapping>> GetByBackendIdAsync(string backendId, CancellationToken cancellationToken = default);
    Task<RouteMapping> CreateAsync(RouteMapping mapping, CancellationToken cancellationToken = default);
    Task<RouteMapping> UpdateAsync(RouteMapping mapping, CancellationToken cancellationToken = default);
    Task DeleteAsync(string id, CancellationToken cancellationToken = default);
    Task<bool> ExistsAsync(string id, CancellationToken cancellationToken = default);
    Task<bool> UsernameExistsAsync(string username, CancellationToken cancellationToken = default);
}
