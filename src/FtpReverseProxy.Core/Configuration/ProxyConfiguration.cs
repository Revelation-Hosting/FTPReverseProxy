namespace FtpReverseProxy.Core.Configuration;

/// <summary>
/// Root configuration for the FTP reverse proxy
/// </summary>
public class ProxyConfiguration
{
    /// <summary>
    /// FTP listener configuration (plain FTP, port 21)
    /// </summary>
    public ListenerConfiguration Ftp { get; set; } = new() { Port = 21 };

    /// <summary>
    /// FTPS implicit listener configuration (port 990)
    /// </summary>
    public FtpsListenerConfiguration FtpsImplicit { get; set; } = new() { Port = 990 };

    /// <summary>
    /// SFTP listener configuration (port 22)
    /// </summary>
    public SftpListenerConfiguration Sftp { get; set; } = new() { Port = 22 };

    /// <summary>
    /// Data channel configuration for FTP passive/active modes
    /// </summary>
    public DataChannelConfiguration DataChannel { get; set; } = new();

    /// <summary>
    /// TLS certificate configuration for FTPS
    /// </summary>
    public TlsCertificateConfiguration? TlsCertificate { get; set; }

    /// <summary>
    /// Database connection configuration
    /// </summary>
    public DatabaseConfiguration Database { get; set; } = new();

    /// <summary>
    /// Redis cache configuration
    /// </summary>
    public RedisConfiguration? Redis { get; set; }
}

/// <summary>
/// Base listener configuration
/// </summary>
public class ListenerConfiguration
{
    /// <summary>
    /// Whether this listener is enabled
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// IP address to bind to. Use "0.0.0.0" for all interfaces, or a specific IP
    /// </summary>
    public string ListenAddress { get; set; } = "0.0.0.0";

    /// <summary>
    /// Port to listen on
    /// </summary>
    public int Port { get; set; }
}

/// <summary>
/// FTPS listener configuration with TLS settings
/// </summary>
public class FtpsListenerConfiguration : ListenerConfiguration
{
    public FtpsListenerConfiguration()
    {
        Enabled = false; // Disabled by default until certificate is configured
    }
}

/// <summary>
/// SFTP listener configuration with SSH host key settings
/// </summary>
public class SftpListenerConfiguration : ListenerConfiguration
{
    public SftpListenerConfiguration()
    {
        Enabled = false; // Disabled by default until host key is configured
    }

    /// <summary>
    /// Path to SSH host key file (RSA, ECDSA, or Ed25519)
    /// </summary>
    public string? HostKeyPath { get; set; }

    /// <summary>
    /// Password for encrypted host key (if applicable)
    /// </summary>
    public string? HostKeyPassword { get; set; }
}

/// <summary>
/// Data channel configuration for FTP PASV/PORT modes
/// </summary>
public class DataChannelConfiguration
{
    /// <summary>
    /// Minimum port for passive mode data connections
    /// </summary>
    public int MinPort { get; set; } = 50000;

    /// <summary>
    /// Maximum port for passive mode data connections
    /// </summary>
    public int MaxPort { get; set; } = 51000;

    /// <summary>
    /// External IP address to advertise in PASV responses.
    /// Required for NAT scenarios. If null, will use the listener's bound address.
    /// </summary>
    public string? ExternalAddress { get; set; }
}

/// <summary>
/// TLS certificate configuration for FTPS
/// </summary>
public class TlsCertificateConfiguration
{
    /// <summary>
    /// Path to the certificate file (PFX/PKCS12 format)
    /// </summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>
    /// Password for the certificate file
    /// </summary>
    public string? Password { get; set; }
}

/// <summary>
/// Database connection configuration
/// </summary>
public class DatabaseConfiguration
{
    /// <summary>
    /// Database provider: "PostgreSQL" or "SqlServer"
    /// </summary>
    public string Provider { get; set; } = "PostgreSQL";

    /// <summary>
    /// Database connection string
    /// </summary>
    public string ConnectionString { get; set; } = string.Empty;
}

/// <summary>
/// Redis cache configuration
/// </summary>
public class RedisConfiguration
{
    /// <summary>
    /// Whether Redis caching is enabled
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Redis connection string
    /// </summary>
    public string ConnectionString { get; set; } = "localhost:6379";

    /// <summary>
    /// Cache TTL in seconds for route lookups
    /// </summary>
    public int CacheTtlSeconds { get; set; } = 300;
}
