using System.Buffers.Binary;
using System.Text;
using FxSsh.Services;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Core.Models;
using FtpReverseProxy.Core.Services;
using FtpReverseProxy.Sftp.Protocol;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Renci.SshNet;
using SshSession = FxSsh.Session;

namespace FtpReverseProxy.Sftp;

/// <summary>
/// Handles an individual SFTP session and proxies to a backend server.
/// Parses SFTP binary packets and translates operations to the backend.
/// </summary>
public class SftpSessionHandler : IDisposable
{
    private readonly SshSession _session;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger _logger;

    private string? _username;
    private string? _password;
    private bool _usedPublicKeyAuth;
    private BackendServer? _backendServer;
    private RouteMapping? _routeMapping;
    private SftpClient? _backendClient;
    private SftpProxy? _sftpProxy;
    private SessionChannel? _clientChannel;

    // Packet buffering for handling fragmented data
    private readonly MemoryStream _packetBuffer = new();
    private int _expectedPacketLength = -1;
    private bool _connectionAcquired;
    private readonly IProxyMetrics? _metrics;

    public SftpSessionHandler(
        SshSession session,
        IServiceProvider serviceProvider,
        ILogger logger)
    {
        _session = session;
        _serviceProvider = serviceProvider;
        _logger = logger;
        _metrics = serviceProvider.GetService<IProxyMetrics>();
    }

    public void Initialize()
    {
        _logger.LogInformation("SftpSessionHandler initialized, waiting for service registration");
        _session.ServiceRegistered += OnServiceRegistered;
    }

    private void OnServiceRegistered(object? sender, SshService service)
    {
        _logger.LogInformation("SSH service registered: {ServiceType}", service.GetType().Name);

        // Handle different SSH service types
        if (service is UserAuthService authService)
        {
            _logger.LogInformation("Attaching to UserAuthService events");
            authService.UserAuth += OnUserAuth;
        }
        else if (service is ConnectionService connectionService)
        {
            _logger.LogInformation("Attaching to ConnectionService events");
            connectionService.CommandOpened += OnCommandOpened;
        }
    }

    private void OnUserAuth(object? sender, UserAuthArgs args)
    {
        // Extract username and password for routing and backend auth
        _username = args.Username;

        // FxSsh.PwAuth provides Password property for password authentication
        // Check if password is available (will be null for public key auth)
        _password = args.Password;

        // Check if this is public key auth (FxSsh provides KeyAlgorithm and Fingerprint for pubkey auth)
        var isPublicKeyAuth = !string.IsNullOrEmpty(args.KeyAlgorithm);
        var authMethod = isPublicKeyAuth ? $"publickey ({args.KeyAlgorithm})" :
                        (!string.IsNullOrEmpty(_password) ? "password" : "none");

        _logger.LogInformation("SFTP auth attempt for user: {Username}, method: {Method}",
            _username, authMethod);

        if (isPublicKeyAuth)
        {
            _logger.LogDebug("Public key fingerprint: {Fingerprint}", args.Fingerprint);
        }

        // Resolve backend based on username
        var result = ResolveBackend(_username);

        if (result.Success)
        {
            _backendServer = result.Server;
            _routeMapping = result.Route;

            // For public key auth, validate the key against stored public key
            if (isPublicKeyAuth)
            {
                // Check if route has a stored public key
                if (string.IsNullOrEmpty(_routeMapping?.PublicKey))
                {
                    _logger.LogWarning("Public key auth rejected for {Username}: no public key configured in route. " +
                        "Add the user's public key to the route mapping via the API.", _username);
                    args.Result = false;
                    _metrics?.RecordAuthentication(false, "SFTP", _backendServer?.Id);
                    return;
                }

                // Validate the client's public key against stored key
                var clientKeyString = FormatPublicKeyFromBlob(args.KeyAlgorithm!, args.Key);
                if (!ValidatePublicKey(clientKeyString, _routeMapping.PublicKey))
                {
                    _logger.LogWarning("Public key auth rejected for {Username}: key mismatch. " +
                        "Client key fingerprint: {Fingerprint}", _username, args.Fingerprint);
                    args.Result = false;
                    _metrics?.RecordAuthentication(false, "SFTP", _backendServer?.Id);
                    return;
                }

                _usedPublicKeyAuth = true;
                _logger.LogInformation("Public key auth accepted for {Username}, will use proxy service key for backend",
                    _username);
            }

            args.Result = true;
            _metrics?.RecordAuthentication(true, "SFTP", _backendServer?.Id);
            _metrics?.RecordConnectionOpened("SFTP", _backendServer?.Id);
            _logger.LogInformation("SFTP authentication accepted for {Username}, routing to {Backend}",
                _username, _backendServer?.Name);
        }
        else
        {
            args.Result = false;
            _metrics?.RecordAuthentication(false, "SFTP", null);
            _logger.LogWarning("SFTP authentication failed for {Username}: no route found", _username);
        }
    }

    /// <summary>
    /// Formats the public key blob from FxSsh into OpenSSH format for comparison
    /// </summary>
    private static string FormatPublicKeyFromBlob(string algorithm, byte[] keyBlob)
    {
        var base64Key = Convert.ToBase64String(keyBlob);
        return $"{algorithm} {base64Key}";
    }

    /// <summary>
    /// Validates that the client's public key matches the stored public key
    /// </summary>
    private bool ValidatePublicKey(string clientKey, string storedKey)
    {
        // Normalize both keys for comparison
        // Format: "algorithm base64data [comment]"
        var clientParts = clientKey.Split(' ', 3);
        var storedParts = storedKey.Split(' ', 3);

        if (clientParts.Length < 2 || storedParts.Length < 2)
        {
            _logger.LogWarning("Invalid key format for comparison");
            return false;
        }

        // Compare algorithm and key data (ignore comment)
        var clientAlgo = clientParts[0];
        var clientData = clientParts[1];
        var storedAlgo = storedParts[0];
        var storedData = storedParts[1];

        // Handle algorithm name variations (e.g., ssh-rsa vs rsa-sha2-256)
        var algorithmsMatch = clientAlgo.Equals(storedAlgo, StringComparison.OrdinalIgnoreCase) ||
            (IsRsaAlgorithm(clientAlgo) && IsRsaAlgorithm(storedAlgo));

        var keysMatch = clientData.Equals(storedData, StringComparison.Ordinal);

        if (algorithmsMatch && keysMatch)
        {
            _logger.LogDebug("Public key validation successful");
            return true;
        }

        _logger.LogDebug("Public key validation failed - Algorithm match: {AlgoMatch}, Key match: {KeyMatch}",
            algorithmsMatch, keysMatch);
        return false;
    }

    private static bool IsRsaAlgorithm(string algorithm)
    {
        return algorithm.Equals("ssh-rsa", StringComparison.OrdinalIgnoreCase) ||
               algorithm.Equals("rsa-sha2-256", StringComparison.OrdinalIgnoreCase) ||
               algorithm.Equals("rsa-sha2-512", StringComparison.OrdinalIgnoreCase);
    }

    private (bool Success, BackendServer? Server, RouteMapping? Route) ResolveBackend(string username)
    {
        // Try to get routing service
        var routingService = _serviceProvider.GetService<IRoutingService>();

        if (routingService is not null)
        {
            // Use routing service to resolve backend
            try
            {
                var route = routingService.ResolveRouteAsync(username, CancellationToken.None)
                    .GetAwaiter().GetResult();

                if (route is not null)
                {
                    // Get the backend server using the ID from the route
                    var backend = routingService.GetBackendAsync(route.BackendServerId, CancellationToken.None)
                        .GetAwaiter().GetResult();

                    if (backend is not null && backend.IsEnabled)
                    {
                        return (true, backend, route);
                    }

                    if (backend is not null && !backend.IsEnabled)
                    {
                        _logger.LogWarning("Backend server {Backend} is disabled", backend.Name);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error resolving route for {Username}", username);
            }
        }

        // Fallback: Try to parse username as user@backend format (e.g., "claplante@10.1.9.7")
        // This allows direct testing without requiring database configuration
        var atIndex = username.LastIndexOf('@');
        if (atIndex > 0)
        {
            var user = username[..atIndex];
            var backendHost = username[(atIndex + 1)..];

            _logger.LogInformation("Using direct backend connection: user='{User}' host='{Host}'", user, backendHost);

            // Create a temporary backend server for this connection
            var tempId = Guid.NewGuid().ToString();
            var testBackend = new BackendServer
            {
                Id = tempId,
                Name = $"Direct-{backendHost}",
                Host = backendHost,
                Port = 22, // Default SFTP port
                Protocol = Core.Enums.Protocol.Sftp,
                IsEnabled = true,
                MaxConnections = 10,
                ConnectionTimeoutMs = 30000
            };

            // Create a passthrough route (credentials passed directly)
            var testRoute = new RouteMapping
            {
                Id = Guid.NewGuid().ToString(),
                Username = user,
                BackendServerId = tempId,
                BackendUsername = null, // Will use the parsed username
                BackendPassword = null, // Will use the client-provided password
                IsEnabled = true
            };

            return (true, testBackend, testRoute);
        }

        return (false, null, null);
    }

    private void OnCommandOpened(object? sender, CommandRequestedArgs args)
    {
        _logger.LogDebug("SSH command requested: {ShellType}", args.ShellType);

        // Check if this is an SFTP subsystem request
        if (args.ShellType == "subsystem" && args.CommandText == "sftp")
        {
            _logger.LogInformation("SFTP subsystem requested by {Username}", _username);

            _clientChannel = args.Channel;

            // Set up event handlers
            args.Channel.DataReceived += OnClientDataReceived;
            args.Channel.CloseReceived += OnClientChannelClosed;

            // Connect to backend and create proxy
            if (!ConnectToBackend())
            {
                _logger.LogError("Failed to connect to backend SFTP server");
                args.Channel.SendClose();
                return;
            }

            // Create the SFTP proxy
            _sftpProxy = new SftpProxy(
                _backendClient!,
                SendDataToClient,
                _logger);

            // Signal that the subsystem request is accepted
            args.Agreed = true;

            _logger.LogInformation("SFTP proxy session established for {Username} -> {Backend}",
                _username, _backendServer?.Name);
        }
    }

    private bool ConnectToBackend()
    {
        if (_backendServer is null || _username is null || _routeMapping is null)
        {
            return false;
        }

        try
        {
            // Try to acquire a connection slot
            var connectionTracker = _serviceProvider.GetService<IConnectionTracker>();
            if (connectionTracker is not null &&
                !connectionTracker.TryAcquireConnection(_backendServer.Id, _backendServer.MaxConnections))
            {
                _logger.LogWarning("Connection limit reached for backend {Backend}", _backendServer.Name);
                return false;
            }
            _connectionAcquired = connectionTracker is not null;

            // Parse actual username if format is user@backend
            var parsedUsername = _username;
            var atIndex = _username.LastIndexOf('@');
            if (atIndex > 0)
            {
                parsedUsername = _username[..atIndex];
            }

            // Determine backend username
            var backendUsername = _routeMapping.BackendUsername ?? parsedUsername;

            // Create authentication method based on how client authenticated
            AuthenticationMethod authMethod;

            if (_usedPublicKeyAuth)
            {
                // Client used public key auth - use proxy's service key to authenticate to backend
                var proxyKeyService = _serviceProvider.GetService<ProxyKeyService>();
                if (proxyKeyService is null)
                {
                    _logger.LogError("ProxyKeyService not available - cannot authenticate to backend with service key");
                    return false;
                }

                _logger.LogInformation("Using proxy service key to authenticate to backend as {User}", backendUsername);

                // Create private key from PEM
                using var keyStream = new MemoryStream(Encoding.UTF8.GetBytes(proxyKeyService.PrivateKeyPem));
                var privateKey = new PrivateKeyFile(keyStream);
                authMethod = new PrivateKeyAuthenticationMethod(backendUsername, privateKey);
            }
            else
            {
                // Client used password auth - use credential mapper or passthrough
                var credentialMapper = _serviceProvider.GetService<ICredentialMapper>();
                string backendPassword;

                if (credentialMapper is not null)
                {
                    var credentials = credentialMapper.MapCredentialsAsync(
                        parsedUsername,
                        _password ?? string.Empty,
                        _routeMapping,
                        _backendServer,
                        CancellationToken.None).GetAwaiter().GetResult();

                    backendUsername = credentials.Username;
                    backendPassword = credentials.Password;
                }
                else
                {
                    // Fallback to direct passthrough
                    backendPassword = _routeMapping.BackendPassword ?? _password ?? string.Empty;
                }

                if (string.IsNullOrEmpty(backendPassword))
                {
                    _logger.LogWarning("No password available for backend authentication.");
                }

                authMethod = new PasswordAuthenticationMethod(backendUsername, backendPassword);
            }

            // Create SFTP connection to backend
            var connectionInfo = new ConnectionInfo(
                _backendServer.Host,
                _backendServer.Port,
                backendUsername,
                authMethod)
            {
                Timeout = TimeSpan.FromMilliseconds(_backendServer.ConnectionTimeoutMs)
            };

            _backendClient = new SftpClient(connectionInfo);
            _backendClient.Connect();

            _logger.LogInformation("Connected to backend SFTP server {Backend} as {User} (auth: {AuthMethod})",
                _backendServer.Name, backendUsername, _usedPublicKeyAuth ? "proxy-key" : "password");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to connect to backend SFTP server");

            // Release connection slot on failure
            if (_connectionAcquired)
            {
                var connectionTracker = _serviceProvider.GetService<IConnectionTracker>();
                connectionTracker?.ReleaseConnection(_backendServer.Id);
                _connectionAcquired = false;
            }
            return false;
        }
    }

    private void OnClientDataReceived(object? sender, byte[] data)
    {
        _logger.LogTrace("Received {Length} bytes from client", data.Length);

        try
        {
            // Buffer the incoming data
            _packetBuffer.Write(data);

            // Process complete packets
            ProcessBufferedPackets();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing client data");
        }
    }

    private void ProcessBufferedPackets()
    {
        while (true)
        {
            var buffer = _packetBuffer.ToArray();

            // Need at least 4 bytes for length prefix
            if (buffer.Length < 4)
                break;

            // Read packet length
            if (_expectedPacketLength < 0)
            {
                _expectedPacketLength = (int)BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(0, 4));
            }

            // Total packet size = 4-byte length + packet data
            var totalPacketSize = 4 + _expectedPacketLength;

            // Check if we have the complete packet
            if (buffer.Length < totalPacketSize)
                break;

            // Extract the complete packet
            var packet = buffer[..totalPacketSize];

            // Remove processed data from buffer
            var remaining = buffer[totalPacketSize..];
            _packetBuffer.SetLength(0);
            if (remaining.Length > 0)
            {
                _packetBuffer.Write(remaining);
            }

            // Reset expected length for next packet
            _expectedPacketLength = -1;

            // Process the packet
            if (_sftpProxy is not null)
            {
                _sftpProxy.ProcessPacket(packet);
            }
            else
            {
                _logger.LogWarning("Received SFTP data but proxy not initialized");
            }
        }
    }

    private void SendDataToClient(byte[] data)
    {
        try
        {
            _clientChannel?.SendData(data);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error sending data to client");
        }
    }

    private void OnClientChannelClosed(object? sender, EventArgs args)
    {
        _logger.LogDebug("SFTP client channel closed for {Username}", _username);
        Cleanup();
    }

    private void Cleanup()
    {
        _sftpProxy?.Dispose();
        _sftpProxy = null;

        if (_backendClient?.IsConnected == true)
        {
            try
            {
                _backendClient.Disconnect();
            }
            catch
            {
                // Ignore cleanup errors
            }
        }

        _backendClient?.Dispose();
        _backendClient = null;

        // Release connection slot
        if (_connectionAcquired && _backendServer is not null)
        {
            var connectionTracker = _serviceProvider.GetService<IConnectionTracker>();
            connectionTracker?.ReleaseConnection(_backendServer.Id);
            _connectionAcquired = false;
        }

        // Record connection closed
        _metrics?.RecordConnectionClosed("SFTP", _backendServer?.Id);

        _packetBuffer.Dispose();
    }

    public void Dispose()
    {
        Cleanup();
    }
}
