using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Core.Services;

/// <summary>
/// Manages the proxy's SSH keypair for authenticating to backend servers.
/// The proxy uses this key to authenticate to backends on behalf of clients.
/// </summary>
public class ProxyKeyService
{
    private readonly ILogger<ProxyKeyService> _logger;
    private readonly string _keyDirectory;
    private readonly string _privateKeyPath;
    private readonly string _publicKeyPath;

    private byte[]? _privateKeyBytes;
    private string? _publicKeyString;
    private readonly object _lock = new();

    public ProxyKeyService(ILogger<ProxyKeyService> logger, string? keyDirectory = null)
    {
        _logger = logger;
        _keyDirectory = keyDirectory ?? Path.Combine(AppContext.BaseDirectory, "keys");
        _privateKeyPath = Path.Combine(_keyDirectory, "proxy_key");
        _publicKeyPath = Path.Combine(_keyDirectory, "proxy_key.pub");
    }

    /// <summary>
    /// Gets the proxy's public key in OpenSSH format (e.g., "ssh-ed25519 AAAAC3NzaC...")
    /// </summary>
    public string PublicKey
    {
        get
        {
            EnsureKeyLoaded();
            return _publicKeyString!;
        }
    }

    /// <summary>
    /// Gets the proxy's private key bytes for use with SSH.NET
    /// </summary>
    public byte[] PrivateKeyBytes
    {
        get
        {
            EnsureKeyLoaded();
            return _privateKeyBytes!;
        }
    }

    /// <summary>
    /// Gets the proxy's private key in PEM format
    /// </summary>
    public string PrivateKeyPem
    {
        get
        {
            EnsureKeyLoaded();
            return Encoding.UTF8.GetString(_privateKeyBytes!);
        }
    }

    /// <summary>
    /// Ensures the key is loaded, generating a new one if necessary
    /// </summary>
    private void EnsureKeyLoaded()
    {
        if (_privateKeyBytes is not null && _publicKeyString is not null)
            return;

        lock (_lock)
        {
            if (_privateKeyBytes is not null && _publicKeyString is not null)
                return;

            if (File.Exists(_privateKeyPath) && File.Exists(_publicKeyPath))
            {
                LoadExistingKey();
            }
            else
            {
                GenerateNewKey();
            }
        }
    }

    private void LoadExistingKey()
    {
        _logger.LogInformation("Loading existing proxy service key from {Path}", _privateKeyPath);

        _privateKeyBytes = File.ReadAllBytes(_privateKeyPath);
        _publicKeyString = File.ReadAllText(_publicKeyPath).Trim();

        _logger.LogInformation("Proxy service key loaded successfully");
        _logger.LogInformation("Proxy public key: {PublicKey}", _publicKeyString);
    }

    private void GenerateNewKey()
    {
        _logger.LogInformation("Generating new proxy service keypair...");

        // Ensure directory exists
        Directory.CreateDirectory(_keyDirectory);

        // Generate Ed25519 keypair (preferred for modern SSH)
        // Note: .NET doesn't have native Ed25519 support, so we'll use RSA for broader compatibility
        using var rsa = RSA.Create(4096);

        // Export private key in PEM format (OpenSSH compatible)
        var privateKeyPem = rsa.ExportRSAPrivateKeyPem();
        _privateKeyBytes = Encoding.UTF8.GetBytes(privateKeyPem);

        // Export public key in OpenSSH format
        _publicKeyString = ExportRsaPublicKeyOpenSsh(rsa);

        // Save keys to disk
        File.WriteAllBytes(_privateKeyPath, _privateKeyBytes);
        File.WriteAllText(_publicKeyPath, _publicKeyString);

        // Set restrictive permissions on private key (Unix-like systems)
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(_privateKeyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not set restrictive permissions on private key file");
        }

        _logger.LogInformation("New proxy service keypair generated and saved");
        _logger.LogInformation("Proxy public key: {PublicKey}", _publicKeyString);
        _logger.LogWarning("IMPORTANT: Add the proxy's public key to your backend servers' authorized_keys files!");
    }

    /// <summary>
    /// Exports an RSA public key in OpenSSH format (ssh-rsa ...)
    /// </summary>
    private static string ExportRsaPublicKeyOpenSsh(RSA rsa)
    {
        var parameters = rsa.ExportParameters(false);

        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        // Write key type
        WriteOpenSshString(writer, "ssh-rsa");

        // Write exponent (e)
        WriteOpenSshMpint(writer, parameters.Exponent!);

        // Write modulus (n)
        WriteOpenSshMpint(writer, parameters.Modulus!);

        var keyBlob = ms.ToArray();
        var base64Key = Convert.ToBase64String(keyBlob);

        return $"ssh-rsa {base64Key} ftp-proxy-service-key";
    }

    private static void WriteOpenSshString(BinaryWriter writer, string value)
    {
        var bytes = Encoding.ASCII.GetBytes(value);
        WriteOpenSshBytes(writer, bytes);
    }

    private static void WriteOpenSshBytes(BinaryWriter writer, byte[] bytes)
    {
        // OpenSSH uses big-endian length prefix
        var length = bytes.Length;
        writer.Write((byte)((length >> 24) & 0xFF));
        writer.Write((byte)((length >> 16) & 0xFF));
        writer.Write((byte)((length >> 8) & 0xFF));
        writer.Write((byte)(length & 0xFF));
        writer.Write(bytes);
    }

    private static void WriteOpenSshMpint(BinaryWriter writer, byte[] value)
    {
        // MPInt format: if the high bit is set, prepend a zero byte
        if (value.Length > 0 && (value[0] & 0x80) != 0)
        {
            var padded = new byte[value.Length + 1];
            padded[0] = 0;
            Array.Copy(value, 0, padded, 1, value.Length);
            WriteOpenSshBytes(writer, padded);
        }
        else
        {
            WriteOpenSshBytes(writer, value);
        }
    }
}
