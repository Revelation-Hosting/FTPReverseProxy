using FtpReverseProxy.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace FtpReverseProxy.Data;

/// <summary>
/// Database context for FTP Reverse Proxy configuration
/// </summary>
public class FtpProxyDbContext : DbContext
{
    public FtpProxyDbContext(DbContextOptions<FtpProxyDbContext> options) : base(options)
    {
    }

    public DbSet<BackendServerEntity> BackendServers => Set<BackendServerEntity>();
    public DbSet<RouteMappingEntity> RouteMappings => Set<RouteMappingEntity>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // BackendServer configuration
        modelBuilder.Entity<BackendServerEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasMaxLength(50);
            entity.Property(e => e.Name).HasMaxLength(200).IsRequired();
            entity.Property(e => e.Host).HasMaxLength(255).IsRequired();
            entity.Property(e => e.ServiceAccountUsername).HasMaxLength(255);
            entity.Property(e => e.ServiceAccountPassword).HasMaxLength(500);
            entity.Property(e => e.Description).HasMaxLength(1000);

            entity.HasIndex(e => e.Name).IsUnique();
            entity.HasIndex(e => e.IsEnabled);
        });

        // RouteMapping configuration
        modelBuilder.Entity<RouteMappingEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Id).HasMaxLength(50);
            entity.Property(e => e.Username).HasMaxLength(255).IsRequired();
            entity.Property(e => e.BackendServerId).HasMaxLength(50).IsRequired();
            entity.Property(e => e.BackendUsername).HasMaxLength(255);
            entity.Property(e => e.BackendPassword).HasMaxLength(500);
            entity.Property(e => e.PublicKey).HasMaxLength(1000);
            entity.Property(e => e.Description).HasMaxLength(1000);

            entity.HasIndex(e => e.Username);
            entity.HasIndex(e => e.IsEnabled);
            entity.HasIndex(e => new { e.Username, e.IsEnabled });

            entity.HasOne(e => e.BackendServer)
                .WithMany(b => b.RouteMappings)
                .HasForeignKey(e => e.BackendServerId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
