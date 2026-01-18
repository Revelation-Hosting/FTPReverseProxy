using FtpReverseProxy.Core.Models;
using FtpReverseProxy.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace FtpReverseProxy.Data.Repositories;

/// <summary>
/// EF Core implementation of backend server repository
/// </summary>
public class BackendServerRepository : IBackendServerRepository
{
    private readonly FtpProxyDbContext _context;

    public BackendServerRepository(FtpProxyDbContext context)
    {
        _context = context;
    }

    public async Task<BackendServer?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        var entity = await _context.BackendServers
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

        return entity is null ? null : MapToModel(entity);
    }

    public async Task<BackendServer?> GetByNameAsync(string name, CancellationToken cancellationToken = default)
    {
        var entity = await _context.BackendServers
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Name == name, cancellationToken);

        return entity is null ? null : MapToModel(entity);
    }

    public async Task<IReadOnlyList<BackendServer>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        var entities = await _context.BackendServers
            .AsNoTracking()
            .OrderBy(x => x.Name)
            .ToListAsync(cancellationToken);

        return entities.Select(MapToModel).ToList();
    }

    public async Task<IReadOnlyList<BackendServer>> GetEnabledAsync(CancellationToken cancellationToken = default)
    {
        var entities = await _context.BackendServers
            .AsNoTracking()
            .Where(x => x.IsEnabled)
            .OrderBy(x => x.Name)
            .ToListAsync(cancellationToken);

        return entities.Select(MapToModel).ToList();
    }

    public async Task<BackendServer> CreateAsync(BackendServer server, CancellationToken cancellationToken = default)
    {
        var entity = MapToEntity(server);
        entity.CreatedAt = DateTime.UtcNow;

        _context.BackendServers.Add(entity);
        await _context.SaveChangesAsync(cancellationToken);

        return MapToModel(entity);
    }

    public async Task<BackendServer> UpdateAsync(BackendServer server, CancellationToken cancellationToken = default)
    {
        var entity = await _context.BackendServers
            .FirstOrDefaultAsync(x => x.Id == server.Id, cancellationToken)
            ?? throw new InvalidOperationException($"Backend server '{server.Id}' not found");

        entity.Name = server.Name;
        entity.Host = server.Host;
        entity.Port = server.Port;
        entity.Protocol = server.Protocol;
        entity.CredentialMapping = server.CredentialMapping;
        entity.ServiceAccountUsername = server.ServiceAccountUsername;
        entity.ServiceAccountPassword = server.ServiceAccountPassword;
        entity.IsEnabled = server.IsEnabled;
        entity.Description = server.Description;
        entity.ConnectionTimeoutMs = server.ConnectionTimeoutMs;
        entity.MaxConnections = server.MaxConnections;
        entity.ClientFacingHostnames = server.ClientFacingHostnames;
        entity.ClientCertificatePath = server.ClientCertificatePath;
        entity.ClientCertificatePassword = server.ClientCertificatePassword;
        entity.SkipCertificateValidation = server.SkipCertificateValidation;
        entity.ModifiedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync(cancellationToken);

        return MapToModel(entity);
    }

    public async Task DeleteAsync(string id, CancellationToken cancellationToken = default)
    {
        var entity = await _context.BackendServers
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

        if (entity is not null)
        {
            _context.BackendServers.Remove(entity);
            await _context.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task<bool> ExistsAsync(string id, CancellationToken cancellationToken = default)
    {
        return await _context.BackendServers.AnyAsync(x => x.Id == id, cancellationToken);
    }

    private static BackendServer MapToModel(BackendServerEntity entity) => new()
    {
        Id = entity.Id,
        Name = entity.Name,
        Host = entity.Host,
        Port = entity.Port,
        Protocol = entity.Protocol,
        CredentialMapping = entity.CredentialMapping,
        ServiceAccountUsername = entity.ServiceAccountUsername,
        ServiceAccountPassword = entity.ServiceAccountPassword,
        IsEnabled = entity.IsEnabled,
        Description = entity.Description,
        ConnectionTimeoutMs = entity.ConnectionTimeoutMs,
        MaxConnections = entity.MaxConnections,
        ClientFacingHostnames = entity.ClientFacingHostnames,
        ClientCertificatePath = entity.ClientCertificatePath,
        ClientCertificatePassword = entity.ClientCertificatePassword,
        SkipCertificateValidation = entity.SkipCertificateValidation
    };

    private static BackendServerEntity MapToEntity(BackendServer model) => new()
    {
        Id = model.Id,
        Name = model.Name,
        Host = model.Host,
        Port = model.Port,
        Protocol = model.Protocol,
        CredentialMapping = model.CredentialMapping,
        ServiceAccountUsername = model.ServiceAccountUsername,
        ServiceAccountPassword = model.ServiceAccountPassword,
        IsEnabled = model.IsEnabled,
        Description = model.Description,
        ConnectionTimeoutMs = model.ConnectionTimeoutMs,
        MaxConnections = model.MaxConnections,
        ClientFacingHostnames = model.ClientFacingHostnames,
        ClientCertificatePath = model.ClientCertificatePath,
        ClientCertificatePassword = model.ClientCertificatePassword,
        SkipCertificateValidation = model.SkipCertificateValidation
    };
}
