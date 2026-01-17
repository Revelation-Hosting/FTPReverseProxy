using System.Buffers.Binary;
using FxSsh.Services;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Core.Models;
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
        _session.ServiceRegistered += OnServiceRegistered;
    }

    private void OnServiceRegistered(object? sender, SshService service)
    {
        // Handle different SSH service types
        if (service is UserauthService authService)
        {
            authService.Userauth += OnUserAuth;
        }
        else if (service is ConnectionService connectionService)
        {
            connectionService.CommandOpened += OnCommandOpened;
        }
    }

    private void OnUserAuth(object? sender, UserauthArgs args)
    {
        // Extract username and password for routing and backend auth
        _username = args.Username;

        // FxSsh.PwAuth provides Password property for password authentication
        // Check if password is available (will be null for public key auth)
        _password = args.Password;

        var authMethod = string.IsNullOrEmpty(_password) ? "publickey" : "password";
        _logger.LogDebug("SFTP auth attempt for user: {Username}, method: {Method}",
            _username, authMethod);

        // Resolve backend based on username
        var result = ResolveBackend(_username);

        if (result.Success)
        {
            _backendServer = result.Server;
            _routeMapping = result.Route;
            args.Result = true;
            _metrics?.RecordAuthentication(true, "SFTP", _backendServer?.Id);
            _metrics?.RecordConnectionOpened("SFTP", _backendServer?.Id);
            _logger.LogDebug("SFTP authentication accepted for {Username}, routing to {Backend}",
                _username, _backendServer?.Name);
        }
        else
        {
            args.Result = false;
            _metrics?.RecordAuthentication(false, "SFTP", null);
            _logger.LogWarning("SFTP authentication failed for {Username}: no route found", _username);
        }
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

        // Fallback: Try to parse username as user@backend format
        var atIndex = username.LastIndexOf('@');
        if (atIndex > 0)
        {
            var user = username[..atIndex];
            var backendName = username[(atIndex + 1)..];

            _logger.LogDebug("Parsed username '{User}' targeting backend '{Backend}'", user, backendName);

            // In a real implementation, we'd look up the backend by name
            // For development/testing, could create a test backend here
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

            // Use credential mapper to get proper credentials
            var credentialMapper = _serviceProvider.GetService<ICredentialMapper>();
            string backendUsername;
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
                backendUsername = _routeMapping.BackendUsername ?? parsedUsername;
                backendPassword = _routeMapping.BackendPassword ?? _password ?? string.Empty;
            }

            if (string.IsNullOrEmpty(backendPassword))
            {
                _logger.LogWarning("No password available for backend authentication. " +
                    "Client may have used public key auth which cannot be proxied to password-based backend.");
            }

            // Create SFTP connection to backend
            var connectionInfo = new ConnectionInfo(
                _backendServer.Host,
                _backendServer.Port,
                backendUsername,
                new PasswordAuthenticationMethod(backendUsername, backendPassword))
            {
                Timeout = TimeSpan.FromMilliseconds(_backendServer.ConnectionTimeoutMs)
            };

            _backendClient = new SftpClient(connectionInfo);
            _backendClient.Connect();

            _logger.LogInformation("Connected to backend SFTP server {Backend} as {User}",
                _backendServer.Name, backendUsername);
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
