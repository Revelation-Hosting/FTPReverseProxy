using FtpReverseProxy.Core.Models;

namespace FtpReverseProxy.Data.Repositories;

/// <summary>
/// Repository for backend server operations
/// </summary>
public interface IBackendServerRepository
{
    Task<BackendServer?> GetByIdAsync(string id, CancellationToken cancellationToken = default);
    Task<BackendServer?> GetByNameAsync(string name, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<BackendServer>> GetAllAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<BackendServer>> GetEnabledAsync(CancellationToken cancellationToken = default);
    Task<BackendServer> CreateAsync(BackendServer server, CancellationToken cancellationToken = default);
    Task<BackendServer> UpdateAsync(BackendServer server, CancellationToken cancellationToken = default);
    Task DeleteAsync(string id, CancellationToken cancellationToken = default);
    Task<bool> ExistsAsync(string id, CancellationToken cancellationToken = default);
}
