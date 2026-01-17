using FxSsh.Services;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Core.Models;
using FtpReverseProxy.Sftp.Protocol;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Renci.SshNet;
using System.Buffers.Binary;
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
#pragma warning disable CS0649 // Field is never assigned - password auth requires FxSsh.PwAuth
    private string? _password;
#pragma warning restore CS0649
    private BackendServer? _backendServer;
    private SftpClient? _backendClient;
    private SftpProxy? _sftpProxy;
    private SessionChannel? _clientChannel;

    // Packet buffering for handling fragmented data
    private readonly MemoryStream _packetBuffer = new();
    private int _expectedPacketLength = -1;

    public SftpSessionHandler(
        SshSession session,
        IServiceProvider serviceProvider,
        ILogger logger)
    {
        _session = session;
        _serviceProvider = serviceProvider;
        _logger = logger;
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
        // Extract username for routing
        _username = args.Username;

        _logger.LogDebug("SFTP auth attempt for user: {Username}, algorithm: {Algorithm}",
            _username, args.KeyAlgorithm);

        // Resolve backend based on username
        var result = ResolveBackend(_username);

        if (result.Success)
        {
            _backendServer = result.Server;
            args.Result = true;
            _logger.LogDebug("SFTP authentication accepted for {Username}, routing to {Backend}",
                _username, _backendServer?.Name);
        }
        else
        {
            args.Result = false;
            _logger.LogWarning("SFTP authentication failed for {Username}: no route found", _username);
        }
    }

    private (bool Success, BackendServer? Server) ResolveBackend(string username)
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

                    if (backend is not null)
                    {
                        return (true, backend);
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

        return (false, null);
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
        if (_backendServer is null || _username is null)
        {
            return false;
        }

        try
        {
            // For password auth, we need the password from the auth event
            // FxSsh's standard auth doesn't provide password - need FxSsh.PwAuth
            // For now, use a placeholder that can be extended
            var password = _password ?? string.Empty;

            // Parse actual username if format is user@backend
            var actualUsername = _username;
            var atIndex = _username.LastIndexOf('@');
            if (atIndex > 0)
            {
                actualUsername = _username[..atIndex];
            }

            // Create SFTP connection to backend
            var connectionInfo = new ConnectionInfo(
                _backendServer.Host,
                _backendServer.Port,
                actualUsername,
                new PasswordAuthenticationMethod(actualUsername, password))
            {
                Timeout = TimeSpan.FromMilliseconds(_backendServer.ConnectionTimeoutMs)
            };

            _backendClient = new SftpClient(connectionInfo);
            _backendClient.Connect();

            _logger.LogDebug("Connected to backend SFTP server {Backend}", _backendServer.Name);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to connect to backend SFTP server");
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

        _packetBuffer.Dispose();
    }

    public void Dispose()
    {
        Cleanup();
    }
}
