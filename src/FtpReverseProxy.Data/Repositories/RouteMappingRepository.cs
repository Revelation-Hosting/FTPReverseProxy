using FtpReverseProxy.Core.Models;
using FtpReverseProxy.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace FtpReverseProxy.Data.Repositories;

/// <summary>
/// EF Core implementation of route mapping repository
/// </summary>
public class RouteMappingRepository : IRouteMappingRepository
{
    private readonly FtpProxyDbContext _context;

    public RouteMappingRepository(FtpProxyDbContext context)
    {
        _context = context;
    }

    public async Task<RouteMapping?> GetByIdAsync(string id, CancellationToken cancellationToken = default)
    {
        var entity = await _context.RouteMappings
            .AsNoTracking()
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

        return entity is null ? null : MapToModel(entity);
    }

    public async Task<RouteMapping?> GetByUsernameAsync(string username, CancellationToken cancellationToken = default)
    {
        var entity = await _context.RouteMappings
            .AsNoTracking()
            .Where(x => x.Username == username && x.IsEnabled)
            .OrderBy(x => x.Priority)
            .FirstOrDefaultAsync(cancellationToken);

        return entity is null ? null : MapToModel(entity);
    }

    public async Task<IReadOnlyList<RouteMapping>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        var entities = await _context.RouteMappings
            .AsNoTracking()
            .OrderBy(x => x.Username)
            .ToListAsync(cancellationToken);

        return entities.Select(MapToModel).ToList();
    }

    public async Task<IReadOnlyList<RouteMapping>> GetByBackendIdAsync(string backendId, CancellationToken cancellationToken = default)
    {
        var entities = await _context.RouteMappings
            .AsNoTracking()
            .Where(x => x.BackendServerId == backendId)
            .OrderBy(x => x.Username)
            .ToListAsync(cancellationToken);

        return entities.Select(MapToModel).ToList();
    }

    public async Task<RouteMapping> CreateAsync(RouteMapping mapping, CancellationToken cancellationToken = default)
    {
        var entity = MapToEntity(mapping);
        entity.CreatedAt = DateTime.UtcNow;

        _context.RouteMappings.Add(entity);
        await _context.SaveChangesAsync(cancellationToken);

        return MapToModel(entity);
    }

    public async Task<RouteMapping> UpdateAsync(RouteMapping mapping, CancellationToken cancellationToken = default)
    {
        var entity = await _context.RouteMappings
            .FirstOrDefaultAsync(x => x.Id == mapping.Id, cancellationToken)
            ?? throw new InvalidOperationException($"Route mapping '{mapping.Id}' not found");

        entity.Username = mapping.Username;
        entity.BackendServerId = mapping.BackendServerId;
        entity.BackendUsername = mapping.BackendUsername;
        entity.BackendPassword = mapping.BackendPassword;
        entity.PublicKey = mapping.PublicKey;
        entity.IsEnabled = mapping.IsEnabled;
        entity.Priority = mapping.Priority;
        entity.Description = mapping.Description;
        entity.ModifiedAt = DateTime.UtcNow;

        await _context.SaveChangesAsync(cancellationToken);

        return MapToModel(entity);
    }

    public async Task DeleteAsync(string id, CancellationToken cancellationToken = default)
    {
        var entity = await _context.RouteMappings
            .FirstOrDefaultAsync(x => x.Id == id, cancellationToken);

        if (entity is not null)
        {
            _context.RouteMappings.Remove(entity);
            await _context.SaveChangesAsync(cancellationToken);
        }
    }

    public async Task<bool> ExistsAsync(string id, CancellationToken cancellationToken = default)
    {
        return await _context.RouteMappings.AnyAsync(x => x.Id == id, cancellationToken);
    }

    public async Task<bool> UsernameExistsAsync(string username, CancellationToken cancellationToken = default)
    {
        return await _context.RouteMappings.AnyAsync(x => x.Username == username, cancellationToken);
    }

    private static RouteMapping MapToModel(RouteMappingEntity entity) => new()
    {
        Id = entity.Id,
        Username = entity.Username,
        BackendServerId = entity.BackendServerId,
        BackendUsername = entity.BackendUsername,
        BackendPassword = entity.BackendPassword,
        PublicKey = entity.PublicKey,
        IsEnabled = entity.IsEnabled,
        Priority = entity.Priority,
        Description = entity.Description,
        CreatedAt = entity.CreatedAt,
        ModifiedAt = entity.ModifiedAt
    };

    private static RouteMappingEntity MapToEntity(RouteMapping model) => new()
    {
        Id = model.Id,
        Username = model.Username,
        BackendServerId = model.BackendServerId,
        BackendUsername = model.BackendUsername,
        BackendPassword = model.BackendPassword,
        PublicKey = model.PublicKey,
        IsEnabled = model.IsEnabled,
        Priority = model.Priority,
        Description = model.Description,
        CreatedAt = model.CreatedAt,
        ModifiedAt = model.ModifiedAt
    };
}
