namespace FtpReverseProxy.Core.Models;

/// <summary>
/// Credentials to use when connecting to a backend server
/// </summary>
public class BackendCredentials
{
    /// <summary>
    /// Username for backend authentication
    /// </summary>
    public required string Username { get; set; }

    /// <summary>
    /// Password for backend authentication
    /// </summary>
    public required string Password { get; set; }

    /// <summary>
    /// Path to private key file for SSH key-based authentication (SFTP)
    /// </summary>
    public string? PrivateKeyPath { get; set; }

    /// <summary>
    /// Password for encrypted private key (if applicable)
    /// </summary>
    public string? PrivateKeyPassword { get; set; }

    /// <summary>
    /// Original username provided by the client (for audit purposes)
    /// </summary>
    public string? OriginalUsername { get; set; }
}
