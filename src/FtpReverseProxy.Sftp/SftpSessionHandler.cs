using FxSsh.Services;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Core.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Renci.SshNet;
using SshSession = FxSsh.Session;

namespace FtpReverseProxy.Sftp;

/// <summary>
/// Handles an individual SFTP session and proxies to a backend server.
///
/// Note: This is a foundational implementation. Full SFTP proxying requires:
/// 1. Parsing SFTP binary packets from the client
/// 2. Executing corresponding operations on the backend using SSH.NET
/// 3. Serializing responses back to the client
///
/// Currently, this handles authentication and connection setup.
/// The actual SFTP packet proxying is marked as TODO.
/// </summary>
public class SftpSessionHandler
{
    private readonly SshSession _session;
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger _logger;

    private string? _username;
    private string? _password;
    private BackendServer? _backendServer;
    private SftpClient? _backendClient;

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
        _logger.LogDebug("SFTP command requested: {ShellType}", args.ShellType);

        // Check if this is an SFTP subsystem request
        // ShellType can be "shell", "exec", or "subsystem"
        // For SFTP, ShellType should be "subsystem" with CommandText being "sftp"
        if (args.ShellType == "subsystem" && args.CommandText == "sftp")
        {
            // SFTP subsystem requested
            _logger.LogInformation("SFTP subsystem requested by {Username}", _username);

            // Set up the SFTP proxy
            args.Channel.DataReceived += OnClientDataReceived;
            args.Channel.CloseReceived += OnClientChannelClosed;

            // Connect to backend
            if (!ConnectToBackend())
            {
                _logger.LogError("Failed to connect to backend SFTP server");
                return;
            }

            _logger.LogInformation("SFTP proxy session established for {Username}", _username);
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

            // Create SFTP connection to backend
            var connectionInfo = new ConnectionInfo(
                _backendServer.Host,
                _backendServer.Port,
                _username,
                new PasswordAuthenticationMethod(_username, password))
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
        // This is where SFTP packet proxying happens
        //
        // The SFTP protocol is binary. Each packet has:
        // - 4-byte length
        // - 1-byte type (SSH_FXP_INIT, SSH_FXP_OPEN, SSH_FXP_READ, etc.)
        // - 4-byte request-id
        // - Payload (type-specific)
        //
        // To proxy properly, we need to:
        // 1. Parse the packet type and contents
        // 2. Call corresponding SSH.NET SftpClient methods
        // 3. Serialize the response and send back to client
        //
        // This is non-trivial and marked for future implementation.

        _logger.LogTrace("SFTP data received from client: {Length} bytes", data.Length);

        // TODO: Implement SFTP packet parsing and proxying
        // For now, log that we received data
    }

    private void OnClientChannelClosed(object? sender, EventArgs args)
    {
        _logger.LogDebug("SFTP client channel closed for {Username}", _username);
        Cleanup();
    }

    private void Cleanup()
    {
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
    }
}
