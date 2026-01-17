using System.Text.Json.Serialization;
using FtpReverseProxy.Api.Models;
using FtpReverseProxy.Data;
using FtpReverseProxy.Data.Entities;
using FtpReverseProxy.Data.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;

var builder = WebApplication.CreateBuilder(args);

// Configure JSON to accept string enum values
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

// Configure database
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? Environment.GetEnvironmentVariable("FTP_PROXY_CONNECTION_STRING")
    ?? "Host=localhost;Database=ftpproxy;Username=postgres;Password=postgres";

var dbProvider = builder.Configuration.GetValue<string>("DatabaseProvider") ?? "PostgreSQL";

builder.Services.AddDbContext<FtpProxyDbContext>(options =>
{
    if (dbProvider.Equals("SqlServer", StringComparison.OrdinalIgnoreCase))
    {
        options.UseSqlServer(connectionString);
    }
    else
    {
        options.UseNpgsql(connectionString);
    }
});

// Configure Redis cache for cache invalidation (if available)
var redisConnection = builder.Configuration.GetValue<string>("Redis:ConnectionString")
    ?? Environment.GetEnvironmentVariable("REDIS_CONNECTION_STRING");

if (!string.IsNullOrEmpty(redisConnection))
{
    builder.Services.AddStackExchangeRedisCache(options =>
    {
        options.Configuration = redisConnection;
        options.InstanceName = "FtpProxy:";
    });
}
else
{
    // Use in-memory cache if Redis not configured
    builder.Services.AddDistributedMemoryCache();
}

builder.Services.AddOpenApi();

var app = builder.Build();

// Apply migrations on startup (for development/Docker)
if (app.Configuration.GetValue<bool>("AutoMigrate"))
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<FtpProxyDbContext>();
    db.Database.Migrate();
}

app.MapOpenApi();

// Health check endpoint
app.MapGet("/health", async (FtpProxyDbContext db) =>
{
    try
    {
        await db.Database.CanConnectAsync();
        return Results.Ok(new { status = "healthy", database = "connected" });
    }
    catch (Exception ex)
    {
        return Results.Json(new { status = "unhealthy", database = "disconnected", error = ex.Message },
            statusCode: 503);
    }
})
.WithName("HealthCheck")
.WithTags("Health")
;

// ==================== Backend Servers API ====================

app.MapGet("/api/backends", async (FtpProxyDbContext db, bool? enabled) =>
{
    var query = db.BackendServers.AsQueryable();

    if (enabled.HasValue)
    {
        query = query.Where(b => b.IsEnabled == enabled.Value);
    }

    var backends = await query
        .OrderBy(b => b.Name)
        .Select(b => new BackendServerDto(
            b.Id,
            b.Name,
            b.Host,
            b.Port,
            b.Protocol,
            b.CredentialMapping,
            b.IsEnabled,
            b.Description,
            b.ConnectionTimeoutMs,
            b.MaxConnections,
            b.ClientFacingHostnames,
            b.ClientCertificatePath,
            b.CreatedAt,
            b.ModifiedAt,
            b.RouteMappings.Count))
        .ToListAsync();

    return Results.Ok(backends);
})
.WithName("GetBackendServers")
.WithTags("Backend Servers")
;

app.MapGet("/api/backends/{id}", async (string id, FtpProxyDbContext db) =>
{
    var backend = await db.BackendServers
        .Where(b => b.Id == id)
        .Select(b => new BackendServerDto(
            b.Id,
            b.Name,
            b.Host,
            b.Port,
            b.Protocol,
            b.CredentialMapping,
            b.IsEnabled,
            b.Description,
            b.ConnectionTimeoutMs,
            b.MaxConnections,
            b.ClientFacingHostnames,
            b.ClientCertificatePath,
            b.CreatedAt,
            b.ModifiedAt,
            b.RouteMappings.Count))
        .FirstOrDefaultAsync();

    return backend is null ? Results.NotFound() : Results.Ok(backend);
})
.WithName("GetBackendServer")
.WithTags("Backend Servers")
;

app.MapPost("/api/backends", async (CreateBackendServerRequest request, FtpProxyDbContext db) =>
{
    // Check for duplicate name
    if (await db.BackendServers.AnyAsync(b => b.Name == request.Name))
    {
        return Results.Conflict(new { error = $"Backend server with name '{request.Name}' already exists" });
    }

    var backend = new BackendServerEntity
    {
        Id = Guid.NewGuid().ToString("N"),
        Name = request.Name,
        Host = request.Host,
        Port = request.Port,
        Protocol = request.Protocol,
        CredentialMapping = request.CredentialMapping,
        ServiceAccountUsername = request.ServiceAccountUsername,
        ServiceAccountPassword = request.ServiceAccountPassword,
        IsEnabled = request.IsEnabled,
        Description = request.Description,
        ConnectionTimeoutMs = request.ConnectionTimeoutMs,
        MaxConnections = request.MaxConnections,
        ClientFacingHostnames = request.ClientFacingHostnames,
        ClientCertificatePath = request.ClientCertificatePath,
        ClientCertificatePassword = request.ClientCertificatePassword,
        CreatedAt = DateTime.UtcNow
    };

    db.BackendServers.Add(backend);
    await db.SaveChangesAsync();

    var dto = new BackendServerDto(
        backend.Id,
        backend.Name,
        backend.Host,
        backend.Port,
        backend.Protocol,
        backend.CredentialMapping,
        backend.IsEnabled,
        backend.Description,
        backend.ConnectionTimeoutMs,
        backend.MaxConnections,
        backend.ClientFacingHostnames,
        backend.ClientCertificatePath,
        backend.CreatedAt,
        backend.ModifiedAt,
        0);

    return Results.Created($"/api/backends/{backend.Id}", dto);
})
.WithName("CreateBackendServer")
.WithTags("Backend Servers")
;

app.MapPut("/api/backends/{id}", async (string id, UpdateBackendServerRequest request, FtpProxyDbContext db, IDistributedCache cache) =>
{
    var backend = await db.BackendServers.FindAsync(id);
    if (backend is null)
    {
        return Results.NotFound();
    }

    var oldName = backend.Name;

    // Check for duplicate name (excluding current)
    if (await db.BackendServers.AnyAsync(b => b.Name == request.Name && b.Id != id))
    {
        return Results.Conflict(new { error = $"Backend server with name '{request.Name}' already exists" });
    }

    backend.Name = request.Name;
    backend.Host = request.Host;
    backend.Port = request.Port;
    backend.Protocol = request.Protocol;
    backend.CredentialMapping = request.CredentialMapping;
    backend.ServiceAccountUsername = request.ServiceAccountUsername;
    backend.ServiceAccountPassword = request.ServiceAccountPassword;
    backend.IsEnabled = request.IsEnabled;
    backend.Description = request.Description;
    backend.ConnectionTimeoutMs = request.ConnectionTimeoutMs;
    backend.MaxConnections = request.MaxConnections;
    backend.ClientFacingHostnames = request.ClientFacingHostnames;
    backend.ClientCertificatePath = request.ClientCertificatePath;
    backend.ClientCertificatePassword = request.ClientCertificatePassword;
    backend.ModifiedAt = DateTime.UtcNow;

    await db.SaveChangesAsync();

    // Invalidate cache
    await cache.RemoveAsync($"backend:{id}");
    await cache.RemoveAsync($"backend_name:{oldName}");
    if (oldName != request.Name)
    {
        await cache.RemoveAsync($"backend_name:{request.Name}");
    }

    return Results.NoContent();
})
.WithName("UpdateBackendServer")
.WithTags("Backend Servers")
;

app.MapDelete("/api/backends/{id}", async (string id, FtpProxyDbContext db, IDistributedCache cache) =>
{
    var backend = await db.BackendServers.FindAsync(id);
    if (backend is null)
    {
        return Results.NotFound();
    }

    var backendName = backend.Name;
    db.BackendServers.Remove(backend);
    await db.SaveChangesAsync();

    // Invalidate cache
    await cache.RemoveAsync($"backend:{id}");
    await cache.RemoveAsync($"backend_name:{backendName}");

    return Results.NoContent();
})
.WithName("DeleteBackendServer")
.WithTags("Backend Servers")
;

// ==================== Route Mappings API ====================

app.MapGet("/api/routes", async (FtpProxyDbContext db, string? username, string? backendId, bool? enabled) =>
{
    var query = db.RouteMappings
        .Include(r => r.BackendServer)
        .AsQueryable();

    if (!string.IsNullOrEmpty(username))
    {
        query = query.Where(r => r.Username.Contains(username));
    }

    if (!string.IsNullOrEmpty(backendId))
    {
        query = query.Where(r => r.BackendServerId == backendId);
    }

    if (enabled.HasValue)
    {
        query = query.Where(r => r.IsEnabled == enabled.Value);
    }

    var routes = await query
        .OrderBy(r => r.Username)
        .ThenBy(r => r.Priority)
        .Select(r => new RouteMappingDto(
            r.Id,
            r.Username,
            r.BackendServerId,
            r.BackendServer != null ? r.BackendServer.Name : null,
            r.BackendUsername,
            r.IsEnabled,
            r.Priority,
            r.Description,
            r.CreatedAt,
            r.ModifiedAt))
        .ToListAsync();

    return Results.Ok(routes);
})
.WithName("GetRouteMappings")
.WithTags("Route Mappings")
;

app.MapGet("/api/routes/{id}", async (string id, FtpProxyDbContext db) =>
{
    var route = await db.RouteMappings
        .Include(r => r.BackendServer)
        .Where(r => r.Id == id)
        .Select(r => new RouteMappingDto(
            r.Id,
            r.Username,
            r.BackendServerId,
            r.BackendServer != null ? r.BackendServer.Name : null,
            r.BackendUsername,
            r.IsEnabled,
            r.Priority,
            r.Description,
            r.CreatedAt,
            r.ModifiedAt))
        .FirstOrDefaultAsync();

    return route is null ? Results.NotFound() : Results.Ok(route);
})
.WithName("GetRouteMapping")
.WithTags("Route Mappings")
;

app.MapPost("/api/routes", async (CreateRouteMappingRequest request, FtpProxyDbContext db) =>
{
    // Verify backend exists
    if (!await db.BackendServers.AnyAsync(b => b.Id == request.BackendServerId))
    {
        return Results.BadRequest(new { error = $"Backend server '{request.BackendServerId}' not found" });
    }

    var route = new RouteMappingEntity
    {
        Id = Guid.NewGuid().ToString("N"),
        Username = request.Username,
        BackendServerId = request.BackendServerId,
        BackendUsername = request.BackendUsername,
        BackendPassword = request.BackendPassword,
        IsEnabled = request.IsEnabled,
        Priority = request.Priority,
        Description = request.Description,
        CreatedAt = DateTime.UtcNow
    };

    db.RouteMappings.Add(route);
    await db.SaveChangesAsync();

    var backendName = await db.BackendServers
        .Where(b => b.Id == request.BackendServerId)
        .Select(b => b.Name)
        .FirstOrDefaultAsync();

    var dto = new RouteMappingDto(
        route.Id,
        route.Username,
        route.BackendServerId,
        backendName,
        route.BackendUsername,
        route.IsEnabled,
        route.Priority,
        route.Description,
        route.CreatedAt,
        route.ModifiedAt);

    return Results.Created($"/api/routes/{route.Id}", dto);
})
.WithName("CreateRouteMapping")
.WithTags("Route Mappings")
;

app.MapPut("/api/routes/{id}", async (string id, UpdateRouteMappingRequest request, FtpProxyDbContext db, IDistributedCache cache) =>
{
    var route = await db.RouteMappings.FindAsync(id);
    if (route is null)
    {
        return Results.NotFound();
    }

    var oldUsername = route.Username;

    // Verify backend exists
    if (!await db.BackendServers.AnyAsync(b => b.Id == request.BackendServerId))
    {
        return Results.BadRequest(new { error = $"Backend server '{request.BackendServerId}' not found" });
    }

    route.Username = request.Username;
    route.BackendServerId = request.BackendServerId;
    route.BackendUsername = request.BackendUsername;
    route.BackendPassword = request.BackendPassword;
    route.IsEnabled = request.IsEnabled;
    route.Priority = request.Priority;
    route.Description = request.Description;
    route.ModifiedAt = DateTime.UtcNow;

    await db.SaveChangesAsync();

    // Invalidate cache for old and new usernames
    await cache.RemoveAsync($"route:{oldUsername}");
    if (oldUsername != request.Username)
    {
        await cache.RemoveAsync($"route:{request.Username}");
    }

    return Results.NoContent();
})
.WithName("UpdateRouteMapping")
.WithTags("Route Mappings")
;

app.MapDelete("/api/routes/{id}", async (string id, FtpProxyDbContext db, IDistributedCache cache) =>
{
    var route = await db.RouteMappings.FindAsync(id);
    if (route is null)
    {
        return Results.NotFound();
    }

    var username = route.Username;
    db.RouteMappings.Remove(route);
    await db.SaveChangesAsync();

    // Invalidate cache
    await cache.RemoveAsync($"route:{username}");

    return Results.NoContent();
})
.WithName("DeleteRouteMapping")
.WithTags("Route Mappings")
;

// ==================== Lookup endpoint for routing ====================

app.MapGet("/api/routes/lookup/{username}", async (string username, FtpProxyDbContext db) =>
{
    var route = await db.RouteMappings
        .Include(r => r.BackendServer)
        .Where(r => r.Username == username && r.IsEnabled && r.BackendServer!.IsEnabled)
        .OrderBy(r => r.Priority)
        .Select(r => new
        {
            r.Id,
            r.Username,
            r.BackendServerId,
            BackendServerName = r.BackendServer!.Name,
            BackendHost = r.BackendServer.Host,
            BackendPort = r.BackendServer.Port,
            Protocol = r.BackendServer.Protocol,
            r.BackendUsername,
            r.BackendServer.CredentialMapping,
            r.BackendServer.ServiceAccountUsername,
            r.BackendServer.ConnectionTimeoutMs
        })
        .FirstOrDefaultAsync();

    return route is null ? Results.NotFound() : Results.Ok(route);
})
.WithName("LookupRoute")
.WithTags("Route Mappings")
;

app.Run();
