using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FtpReverseProxy.Core.Enums;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Core.Models;
using FtpReverseProxy.Ftp.DataChannel;
using FtpReverseProxy.Ftp.Parsing;
using FtpReverseProxy.Ftp.Tls;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp.Handlers;

/// <summary>
/// Handles a single FTP client session
/// </summary>
public class FtpSessionHandler : IDisposable
{
    private readonly TcpClient _client;
    private readonly IServiceProvider _serviceProvider;
    private readonly ISessionManager _sessionManager;
    private readonly Protocol _protocol;
    private readonly ILogger _logger;

    private Stream _clientStream = null!;
    private StreamReader _reader = null!;
    private StreamWriter _writer = null!;
    private ProxySession _session = null!;

    private string? _pendingUsername;
    private IBackendConnection? _backendConnection;
    private IDataChannelManager? _dataChannelManager;
    private bool _connectionAcquired;
    private IProxyMetrics? _metrics;
    private OpenSslServerStream? _openSslStream;

    // Keepalive mechanism to prevent backend timeout
    private CancellationTokenSource? _keepaliveCts;
    private Task? _keepaliveTask;
    private readonly SemaphoreSlim _backendCommandLock = new(1, 1);
    private DateTime _lastBackendActivity = DateTime.UtcNow;
    private const int KeepAliveIntervalSeconds = 15; // Send NOOP every 15 seconds of inactivity

    // Commands that trigger data transfer
    private static readonly HashSet<string> DataTransferCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        FtpCommandParser.Commands.List,
        FtpCommandParser.Commands.Nlst,
        FtpCommandParser.Commands.Mlsd,
        FtpCommandParser.Commands.Retr,
        FtpCommandParser.Commands.Stor,
        FtpCommandParser.Commands.Stou,
        FtpCommandParser.Commands.Appe
    };

    // Commands that are uploads (client sends data to server)
    private static readonly HashSet<string> UploadCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        FtpCommandParser.Commands.Stor,
        FtpCommandParser.Commands.Stou,
        FtpCommandParser.Commands.Appe
    };

    public FtpSessionHandler(
        TcpClient client,
        IServiceProvider serviceProvider,
        ISessionManager sessionManager,
        Protocol protocol,
        ILogger logger)
    {
        _client = client;
        _serviceProvider = serviceProvider;
        _sessionManager = sessionManager;
        _protocol = protocol;
        _logger = logger;
    }

    public async Task HandleSessionAsync(CancellationToken cancellationToken)
    {
        // Initialize session
        var endpoint = _client.Client.RemoteEndPoint as IPEndPoint ?? new IPEndPoint(IPAddress.None, 0);
        _session = new ProxySession
        {
            ClientEndpoint = endpoint,
            ClientProtocol = _protocol
        };
        _sessionManager.RegisterSession(_session);

        _logger.LogDebug("Session {SessionId}: Initializing session handler for {Endpoint}", _session.Id, endpoint);

        // Get metrics service
        _metrics = _serviceProvider.GetService<IProxyMetrics>();
        _metrics?.RecordConnectionOpened(_protocol.ToString(), null);

        // Get data channel manager
        _dataChannelManager = _serviceProvider.GetRequiredService<IDataChannelManager>();

        try
        {
            // Get network stream
            _clientStream = _client.GetStream();
            _logger.LogDebug("Session {SessionId}: Got network stream", _session.Id);

            // Handle implicit TLS
            if (_protocol == Protocol.FtpsImplicit)
            {
                _logger.LogDebug("Session {SessionId}: Starting implicit TLS upgrade", _session.Id);
                await UpgradeToTlsAsync(cancellationToken);
                _logger.LogDebug("Session {SessionId}: Implicit TLS upgrade completed", _session.Id);
            }

            // Use UTF8 without BOM - FTP clients can't handle BOM in responses
            var utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
            _reader = new StreamReader(_clientStream, utf8NoBom);
            _writer = new StreamWriter(_clientStream, utf8NoBom) { AutoFlush = true };

            // Send welcome banner
            _logger.LogDebug("Session {SessionId}: Sending welcome banner", _session.Id);
            await SendResponseAsync(FtpResponseParser.Codes.ServiceReady, "FTP Proxy Server Ready");

            // Main command loop
            await ProcessCommandsAsync(cancellationToken);
        }
        finally
        {
            _dataChannelManager.CancelDataChannel(_session.Id);
            _sessionManager.RemoveSession(_session.Id);
            _session.State = SessionState.Closed;

            // Release connection slot if acquired
            if (_connectionAcquired && _session.Backend is not null)
            {
                var connectionTracker = _serviceProvider.GetService<IConnectionTracker>();
                connectionTracker?.ReleaseConnection(_session.Backend.Id);
                _connectionAcquired = false;
            }

            // Record connection closed
            _metrics?.RecordConnectionClosed(_protocol.ToString(), _session.Backend?.Id);

            // Record bytes transferred
            if (_session.BytesUploaded > 0 || _session.BytesDownloaded > 0)
            {
                _metrics?.RecordBytesTransferred("upload", _session.BytesUploaded, _session.Backend?.Id);
                _metrics?.RecordBytesTransferred("download", _session.BytesDownloaded, _session.Backend?.Id);
            }
        }
    }

    private async Task ProcessCommandsAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested && _session.State != SessionState.Closed)
        {
            try
            {
                // Log socket state before reading with millisecond UTC timestamp for Wireshark correlation
                var socketConnected = _client.Client?.Connected ?? false;
                var socketAvailable = 0;
                try { socketAvailable = _client.Client?.Available ?? 0; } catch { }
                var utcNow = DateTime.UtcNow;

                _logger.LogDebug("[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] Session {SessionId}: Waiting for next command from client... SocketConnected={SocketConnected}, BytesAvailable={BytesAvailable}",
                    utcNow, _session.Id, socketConnected, socketAvailable);

                var line = await _reader.ReadLineAsync(cancellationToken);
                if (line is null)
                {
                    // Log detailed socket state when we get null
                    var socketConnected2 = _client.Client?.Connected ?? false;
                    var socketAvailable2 = 0;
                    try { socketAvailable2 = _client.Client?.Available ?? 0; } catch { }
                    var utcNow2 = DateTime.UtcNow;

                    _logger.LogWarning("[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] Session {SessionId}: Client disconnected (ReadLineAsync returned null). SocketConnected={SocketConnected}, BytesAvailable={BytesAvailable}",
                        utcNow2, _session.Id, socketConnected2, socketAvailable2);

                    // Perform explicit TLS shutdown before exiting - this sends close_notify to the client
                    // This must be done while the socket is still in a good state
                    if (_openSslStream != null)
                    {
                        _logger.LogInformation("Session {SessionId}: Performing TLS shutdown on control channel disconnect", _session.Id);
                        _openSslStream.TlsShutdown();
                    }

                    break;
                }

                _session.LastActivityAt = DateTime.UtcNow;
                _session.CommandCount++;

                var command = FtpCommandParser.Parse(line);
                _logger.LogInformation("Received command from client: {Verb} {Argument}", command.Verb,
                    command.Verb == FtpCommandParser.Commands.Pass ? "****" : command.Argument);

                await HandleCommandAsync(command, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Session {SessionId}: Command loop cancelled", _session.Id);
                break;
            }
            catch (IOException ioEx)
            {
                _logger.LogWarning(ioEx, "Session {SessionId}: Connection lost (IOException). Inner: {Inner}",
                    _session.Id, ioEx.InnerException?.Message ?? "none");
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing command");
                await SendResponseAsync(FtpResponseParser.Codes.ActionAborted, "Internal error");
            }
        }

        _logger.LogInformation("Session {SessionId}: Command loop exited. Cancelled={Cancelled}, State={State}",
            _session.Id, cancellationToken.IsCancellationRequested, _session.State);
    }

    private async Task HandleCommandAsync(FtpCommand command, CancellationToken cancellationToken)
    {
        switch (command.Verb)
        {
            case FtpCommandParser.Commands.User:
                await HandleUserAsync(command, cancellationToken);
                break;

            case FtpCommandParser.Commands.Pass:
                await HandlePassAsync(command, cancellationToken);
                break;

            case FtpCommandParser.Commands.Quit:
                await HandleQuitAsync(cancellationToken);
                break;

            case FtpCommandParser.Commands.Auth:
                await HandleAuthAsync(command, cancellationToken);
                break;

            case FtpCommandParser.Commands.Pbsz:
                await HandlePbszAsync(command, cancellationToken);
                break;

            case FtpCommandParser.Commands.Prot:
                await HandleProtAsync(command, cancellationToken);
                break;

            case FtpCommandParser.Commands.Feat:
                await HandleFeatAsync(cancellationToken);
                break;

            case FtpCommandParser.Commands.Syst:
                await SendResponseAsync(FtpResponseParser.Codes.SystemType, "UNIX Type: L8");
                break;

            case FtpCommandParser.Commands.Noop:
                await SendResponseAsync(FtpResponseParser.Codes.CommandOk, "OK");
                break;

            case FtpCommandParser.Commands.Pasv:
            case FtpCommandParser.Commands.Epsv:
                await HandlePassiveModeAsync(command, cancellationToken);
                break;

            case FtpCommandParser.Commands.Port:
            case FtpCommandParser.Commands.Eprt:
                await HandleActiveModeAsync(command, cancellationToken);
                break;

            default:
                await HandleProxiedCommandAsync(command, cancellationToken);
                break;
        }
    }

    private async Task HandleUserAsync(FtpCommand command, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(command.Argument))
        {
            await SendResponseAsync(FtpResponseParser.Codes.SyntaxErrorInArguments, "Username required");
            return;
        }

        _pendingUsername = command.Argument;
        _session.ClientUsername = command.Argument;
        _session.State = SessionState.AwaitingPassword;

        await SendResponseAsync(FtpResponseParser.Codes.UserNameOkNeedPassword, "Password required");
    }

    private async Task HandlePassAsync(FtpCommand command, CancellationToken cancellationToken)
    {
        if (_session.State != SessionState.AwaitingPassword || string.IsNullOrEmpty(_pendingUsername))
        {
            await SendResponseAsync(FtpResponseParser.Codes.BadSequence, "Login with USER first");
            return;
        }

        _session.State = SessionState.Authenticating;

        try
        {
            // Resolve route
            var routingService = _serviceProvider.GetRequiredService<IRoutingService>();
            var route = await routingService.ResolveRouteAsync(_pendingUsername, cancellationToken);

            if (route is null)
            {
                _logger.LogWarning("No route found for username: {Username}", _pendingUsername);
                await SendResponseAsync(FtpResponseParser.Codes.NotLoggedIn, "Login failed - no route configured");
                _session.State = SessionState.Connected;
                return;
            }

            // Get backend server
            var backend = await routingService.GetBackendAsync(route.BackendServerId, cancellationToken);
            if (backend is null || !backend.IsEnabled)
            {
                _logger.LogWarning("Backend server not found or disabled: {BackendId}", route.BackendServerId);
                await SendResponseAsync(FtpResponseParser.Codes.ServiceNotAvailable, "Backend server unavailable");
                _session.State = SessionState.Connected;
                return;
            }

            _session.Backend = backend;

            // Try to acquire a connection slot
            var connectionTracker = _serviceProvider.GetRequiredService<IConnectionTracker>();
            if (!connectionTracker.TryAcquireConnection(backend.Id, backend.MaxConnections))
            {
                _logger.LogWarning("Connection limit reached for backend {Backend}", backend.Name);
                await SendResponseAsync(FtpResponseParser.Codes.ServiceNotAvailable,
                    "Backend server at capacity");
                _session.State = SessionState.Connected;
                return;
            }
            _connectionAcquired = true;

            // Map credentials
            var credentialMapper = _serviceProvider.GetRequiredService<ICredentialMapper>();
            var credentials = await credentialMapper.MapCredentialsAsync(
                _pendingUsername,
                command.Argument ?? string.Empty,
                route,
                backend,
                cancellationToken);

            // Connect to backend with retry logic for transient failures
            const int maxRetries = 3;
            var authSuccess = false;
            Exception? lastException = null;

            for (int attempt = 1; attempt <= maxRetries; attempt++)
            {
                try
                {
                    // Clean up any previous failed connection
                    if (_backendConnection is not null)
                    {
                        await _backendConnection.DisposeAsync();
                        _backendConnection = null;
                    }

                    _backendConnection = _serviceProvider.GetRequiredService<IBackendConnection>();
                    await _backendConnection.ConnectAsync(backend, cancellationToken);

                    // Upgrade backend to TLS if needed
                    if (_session.ClientTlsEnabled && backend.Protocol != Protocol.Ftp)
                    {
                        await _backendConnection.UpgradeToTlsAsync(cancellationToken);
                        _session.BackendTlsEnabled = true;
                    }

                    // Authenticate with backend
                    authSuccess = await _backendConnection.AuthenticateAsync(credentials, cancellationToken);
                    lastException = null;
                    break; // Success, exit retry loop
                }
                catch (IOException ex) when (attempt < maxRetries)
                {
                    lastException = ex;
                    _logger.LogWarning("Backend connection attempt {Attempt}/{MaxRetries} failed for {Backend}: {Error}. Retrying...",
                        attempt, maxRetries, backend.Name, ex.Message);

                    // Brief delay before retry to let things settle
                    await Task.Delay(100 * attempt, cancellationToken);
                }
            }

            // If all retries failed, throw the last exception
            if (lastException is not null)
            {
                throw lastException;
            }

            // Record authentication result
            _metrics?.RecordAuthentication(authSuccess, _protocol.ToString(), backend.Id);

            if (authSuccess)
            {
                _session.State = SessionState.Active;
                _logger.LogInformation("User {Username} authenticated, connected to backend {Backend}",
                    _pendingUsername, backend.Name);
                await SendResponseAsync(FtpResponseParser.Codes.UserLoggedIn, "Login successful");

                // Start keepalive task to prevent backend timeout
                StartKeepaliveTask();
            }
            else
            {
                _logger.LogWarning("Authentication failed for user {Username} on backend {Backend}",
                    _pendingUsername, backend.Name);
                await SendResponseAsync(FtpResponseParser.Codes.NotLoggedIn, "Login failed");
                _session.State = SessionState.Connected;
                await _backendConnection.DisconnectAsync();
                _backendConnection = null;

                // Release connection slot on auth failure
                if (_connectionAcquired)
                {
                    connectionTracker.ReleaseConnection(backend.Id);
                    _connectionAcquired = false;
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during authentication for user {Username}", _pendingUsername);
            await SendResponseAsync(FtpResponseParser.Codes.ServiceNotAvailable, "Authentication error");
            _session.State = SessionState.Connected;

            // Release connection slot on error
            if (_connectionAcquired && _session.Backend is not null)
            {
                var connectionTracker = _serviceProvider.GetService<IConnectionTracker>();
                connectionTracker?.ReleaseConnection(_session.Backend.Id);
                _connectionAcquired = false;
            }
        }
    }

    private async Task HandleQuitAsync(CancellationToken cancellationToken)
    {
        await SendResponseAsync(FtpResponseParser.Codes.ServiceClosing, "Goodbye");
        _session.State = SessionState.Closed;

        if (_backendConnection is not null)
        {
            await _backendConnection.DisconnectAsync();
        }
    }

    private async Task HandleAuthAsync(FtpCommand command, CancellationToken cancellationToken)
    {
        if (_session.ClientTlsEnabled)
        {
            await SendResponseAsync(FtpResponseParser.Codes.BadSequence, "TLS already active");
            return;
        }

        if (string.Equals(command.Argument, "TLS", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(command.Argument, "SSL", StringComparison.OrdinalIgnoreCase))
        {
            // Check if TLS certificate is available
            var certProvider = _serviceProvider.GetService<ICertificateProvider>();
            if (certProvider is null || !certProvider.HasCertificate)
            {
                await SendResponseAsync(FtpResponseParser.Codes.CommandNotImplemented,
                    "TLS not available - no certificate configured");
                return;
            }

            await SendResponseAsync(FtpResponseParser.Codes.SecurityDataExchange, "AUTH TLS successful");
            await UpgradeToTlsAsync(cancellationToken);
        }
        else
        {
            await SendResponseAsync(FtpResponseParser.Codes.CommandNotImplementedForParameter,
                "AUTH mechanism not supported");
        }
    }

    private async Task HandlePbszAsync(FtpCommand command, CancellationToken cancellationToken)
    {
        // Protection buffer size - we always use 0 for streaming
        await SendResponseAsync(FtpResponseParser.Codes.CommandOk, "PBSZ=0");
    }

    private async Task HandleProtAsync(FtpCommand command, CancellationToken cancellationToken)
    {
        if (string.Equals(command.Argument, "P", StringComparison.OrdinalIgnoreCase))
        {
            _session.DataChannelProtected = true;
            await SendResponseAsync(FtpResponseParser.Codes.CommandOk, "Protection level set to Private");
        }
        else if (string.Equals(command.Argument, "C", StringComparison.OrdinalIgnoreCase))
        {
            _session.DataChannelProtected = false;
            await SendResponseAsync(FtpResponseParser.Codes.CommandOk, "Protection level set to Clear");
        }
        else
        {
            await SendResponseAsync(FtpResponseParser.Codes.CommandNotImplementedForParameter,
                "Unsupported protection level");
        }
    }

    private async Task HandleFeatAsync(CancellationToken cancellationToken)
    {
        var features = new StringBuilder();
        features.AppendLine("211-Features:");
        features.AppendLine(" AUTH TLS");
        features.AppendLine(" AUTH SSL");
        features.AppendLine(" PBSZ");
        features.AppendLine(" PROT");
        features.AppendLine(" UTF8");
        features.AppendLine(" PASV");
        features.AppendLine(" EPSV");
        // PORT and EPRT (active mode) are not advertised because they are not supported.
        // Active mode requires the backend to connect back to the proxy, which doesn't
        // work reliably through firewalls, NAT, or container networking.
        features.AppendLine(" SIZE");
        features.AppendLine(" MDTM");
        features.AppendLine(" REST STREAM");
        features.Append("211 End");

        await _writer.WriteLineAsync(features.ToString());
    }

    private async Task HandlePassiveModeAsync(FtpCommand command, CancellationToken cancellationToken)
    {
        if (_session.State != SessionState.Active || _backendConnection is null)
        {
            await SendResponseAsync(FtpResponseParser.Codes.NotLoggedIn, "Please login first");
            return;
        }

        // Forward PASV/EPSV to backend
        var response = await _backendConnection.SendCommandAsync(command, cancellationToken);

        if (response.Code != FtpResponseParser.Codes.EnteringPassiveMode &&
            response.Code != FtpResponseParser.Codes.EnteringExtendedPassiveMode)
        {
            // Backend rejected the command, forward the error
            await _writer.WriteLineAsync(response.RawResponse);
            return;
        }

        // Parse backend's data endpoint
        IPEndPoint? backendEndpoint;
        if (command.Verb == FtpCommandParser.Commands.Pasv)
        {
            backendEndpoint = DataChannelHelpers.ParsePasvResponse(response.RawResponse);
        }
        else
        {
            // For EPSV, we use the backend's control connection IP
            var port = DataChannelHelpers.ParseEpsvResponse(response.RawResponse);
            if (port == 0 || _session.Backend is null)
            {
                await SendResponseAsync(FtpResponseParser.Codes.CantOpenDataConnection,
                    "Failed to parse backend response");
                return;
            }
            var backendIp = IPAddress.Parse(_session.Backend.Host);
            backendEndpoint = new IPEndPoint(backendIp, port);
        }

        if (backendEndpoint is null)
        {
            await SendResponseAsync(FtpResponseParser.Codes.CantOpenDataConnection,
                "Failed to parse backend response");
            return;
        }

        _logger.LogDebug("Backend passive mode endpoint: {Endpoint}", backendEndpoint);

        // Set up data channel relay
        // Client TLS: only if client is using FTPS and PROT P
        var useClientTls = _session.DataChannelProtected && _session.ClientTlsEnabled;
        // Backend TLS: if backend is FTPS (we sent PROT P during control channel setup)
        var useBackendTls = _session.Backend?.Protocol == Core.Enums.Protocol.FtpsExplicit ||
                           _session.Backend?.Protocol == Core.Enums.Protocol.FtpsImplicit;
        // Skip certificate validation if configured for this backend
        var skipBackendCertValidation = _session.Backend?.SkipCertificateValidation ?? false;
        // Use backend hostname for TLS (enables session resumption)
        var backendHostname = _session.Backend?.Host;
        // Get TLS session from control channel for session resumption
        var tlsSessionToResume = _backendConnection?.TlsSessionForResumption;

        // Log the session we're passing to the data channel for correlation
        if (tlsSessionToResume is Tls.OpenSslSession session)
        {
            _logger.LogDebug("Session {SessionId}: Passing TLS session {TlsSessionId} (valid={Valid}) to data channel",
                _session.Id, session.SessionId, session.IsValid);
        }

        var proxyEndpoint = await _dataChannelManager!.SetupPassiveRelayAsync(
            _session.Id,
            backendEndpoint,
            useClientTls,
            useBackendTls,
            backendHostname,
            skipBackendCertValidation,
            tlsSessionToResume,
            cancellationToken);

        _session.DataChannelMode = DataChannelMode.Passive;

        _logger.LogDebug("Proxy passive mode endpoint: {Endpoint}", proxyEndpoint);

        // Send rewritten response to client with proxy's endpoint
        string clientResponse;
        if (command.Verb == FtpCommandParser.Commands.Pasv)
        {
            clientResponse = DataChannelHelpers.FormatPasvResponse(proxyEndpoint);
        }
        else
        {
            clientResponse = DataChannelHelpers.FormatEpsvResponse(proxyEndpoint.Port);
        }

        await _writer.WriteLineAsync(clientResponse);
    }

    private async Task HandleActiveModeAsync(FtpCommand command, CancellationToken cancellationToken)
    {
        // Active mode (PORT/EPRT) is not supported by this proxy.
        // Active mode requires the backend server to connect back to the proxy,
        // which is problematic through firewalls, NAT, and container networking.
        // Clients should use passive mode (PASV/EPSV) instead.
        _logger.LogWarning("Session {SessionId}: Rejected {Command} - active mode not supported. Client should use PASV/EPSV.",
            _session.Id, command.Verb);

        // 502 = Command not implemented for this parameter
        // This tells the client the command is recognized but won't work in this context
        await SendResponseAsync(502, "Active mode not supported. Please use PASV or EPSV for passive mode.");
    }

    // Original HandleActiveModeAsync kept for reference but disabled
    // In active mode, the client tells us their address and the backend connects to it.
    // This requires the proxy to have an IP reachable by the backend, which is often
    // not possible in NAT/Docker environments.
    private async Task HandleActiveModeAsync_Disabled(FtpCommand command, CancellationToken cancellationToken)
    {
        if (_session.State != SessionState.Active || _backendConnection is null)
        {
            await SendResponseAsync(FtpResponseParser.Codes.NotLoggedIn, "Please login first");
            return;
        }

        // Parse client's data endpoint from command
        IPEndPoint? clientEndpoint;
        if (command.Verb == FtpCommandParser.Commands.Port)
        {
            clientEndpoint = DataChannelHelpers.ParsePortCommand(command.Argument ?? string.Empty);
        }
        else
        {
            clientEndpoint = DataChannelHelpers.ParseEprtCommand(command.Argument ?? string.Empty);
        }

        if (clientEndpoint is null)
        {
            await SendResponseAsync(FtpResponseParser.Codes.SyntaxErrorInArguments,
                "Invalid address format");
            return;
        }

        _logger.LogDebug("Client active mode endpoint: {Endpoint}", clientEndpoint);

        // Set up data channel relay
        // Client TLS: only if client is using FTPS and PROT P
        var useClientTls = _session.DataChannelProtected && _session.ClientTlsEnabled;
        // Backend TLS: if backend is FTPS (we sent PROT P during control channel setup)
        var useBackendTls = _session.Backend?.Protocol == Core.Enums.Protocol.FtpsExplicit ||
                           _session.Backend?.Protocol == Core.Enums.Protocol.FtpsImplicit;
        // Skip certificate validation if configured for this backend
        var skipBackendCertValidation = _session.Backend?.SkipCertificateValidation ?? false;
        // Use backend hostname for TLS (enables session resumption)
        var backendHostname = _session.Backend?.Host;
        // Get TLS session from control channel for session resumption
        var tlsSessionToResume = _backendConnection?.TlsSessionForResumption;

        var proxyEndpoint = await _dataChannelManager!.SetupActiveRelayAsync(
            _session.Id,
            clientEndpoint,
            useClientTls,
            useBackendTls,
            backendHostname,
            skipBackendCertValidation,
            tlsSessionToResume,
            cancellationToken);

        _session.DataChannelMode = DataChannelMode.Active;

        _logger.LogDebug("Proxy active mode endpoint for backend: {Endpoint}", proxyEndpoint);

        // Send rewritten PORT/EPRT to backend with proxy's endpoint
        string backendCommand;
        if (command.Verb == FtpCommandParser.Commands.Port)
        {
            backendCommand = DataChannelHelpers.FormatPortCommand(proxyEndpoint);
        }
        else
        {
            backendCommand = DataChannelHelpers.FormatEprtCommand(proxyEndpoint);
        }

        var backendResponse = await _backendConnection.SendCommandAsync(
            new FtpCommand { Verb = command.Verb, Argument = backendCommand.Split(' ', 2)[1], RawCommand = backendCommand },
            cancellationToken);

        // Forward response to client
        await _writer.WriteLineAsync(backendResponse.RawResponse);
    }

    private async Task HandleProxiedCommandAsync(FtpCommand command, CancellationToken cancellationToken)
    {
        if (_session.State != SessionState.Active || _backendConnection is null)
        {
            await SendResponseAsync(FtpResponseParser.Codes.NotLoggedIn, "Please login first");
            return;
        }

        // Check if this is a data transfer command
        if (DataTransferCommands.Contains(command.Verb))
        {
            await HandleDataTransferCommandAsync(command, cancellationToken);
            return;
        }

        // Forward command to backend and relay response
        var response = await _backendConnection.SendCommandAsync(command, cancellationToken);
        TouchBackendActivity();
        await _writer.WriteLineAsync(response.RawResponse);
    }

    private async Task HandleDataTransferCommandAsync(FtpCommand command, CancellationToken cancellationToken)
    {
        // Verify we have a data channel set up
        var dataChannelMode = _dataChannelManager!.GetDataChannelMode(_session.Id);
        if (dataChannelMode is null)
        {
            await SendResponseAsync(FtpResponseParser.Codes.CantOpenDataConnection,
                "Use PASV or PORT first");
            return;
        }

        _logger.LogInformation("Starting data transfer for {Command} in {Mode} mode. Forwarding to backend...",
            command.Verb, dataChannelMode);

        // Send command to backend
        var response = await _backendConnection!.SendCommandAsync(command, cancellationToken);

        _logger.LogInformation("Backend responded with {Code}: {Message}",
            response.Code, response.Message);

        // Send preliminary response to client (150 or error)
        await _writer.WriteLineAsync(response.RawResponse);

        if (!response.IsPreliminary)
        {
            // Command rejected, no data transfer
            _dataChannelManager.CancelDataChannel(_session.Id);
            return;
        }

        try
        {
            // Wait for data transfer to complete
            var isUpload = UploadCommands.Contains(command.Verb);
            var (uploaded, downloaded) = await _dataChannelManager.RelayDataAsync(_session.Id, isUpload, cancellationToken);

            _session.BytesUploaded += uploaded;
            _session.BytesDownloaded += downloaded;

            _logger.LogInformation("Session {SessionId}: Data transfer completed: {Uploaded} bytes up, {Downloaded} bytes down. Now reading 226 response...",
                _session.Id, uploaded, downloaded);

            // Read the completion response from backend (226)
            // NOTE: RelayDataAsync now waits for cleanup to complete before returning,
            // so we're guaranteed the data channel is fully closed before we read from
            // the backend control channel.
            var completionResponse = await ReadBackendResponseAsync(cancellationToken);

            // Log socket state before writing 226 with millisecond UTC timestamp
            var preWriteSocketConnected = _client.Client?.Connected ?? false;
            var preWriteUtc = DateTime.UtcNow;
            _logger.LogInformation("[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] Session {SessionId}: Received 226 response from backend: {Code}. Forwarding to client... SocketConnected={SocketConnected}",
                preWriteUtc, _session.Id, completionResponse.Code, preWriteSocketConnected);

            await _writer.WriteLineAsync(completionResponse.RawResponse);

            // Log socket state after writing 226 with millisecond UTC timestamp
            var postWriteSocketConnected = _client.Client?.Connected ?? false;
            var postWriteUtc = DateTime.UtcNow;
            _logger.LogInformation("[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] Session {SessionId}: 226 response sent to client. SocketConnected={SocketConnected}. Returning to command loop.",
                postWriteUtc, _session.Id, postWriteSocketConnected);
        }
        catch (OperationCanceledException)
        {
            _logger.LogWarning("Session {SessionId}: Data transfer was cancelled", _session.Id);
            // CRITICAL: Drain the backend's pending response to prevent response desync.
            // The backend may have sent a 226/426 that we must consume before the next command.
            await DrainBackendResponseAsync("cancelled");
            await SendResponseAsync(FtpResponseParser.Codes.ConnectionClosed, "Transfer aborted");
        }
        catch (IOException ioEx)
        {
            _logger.LogError(ioEx, "Session {SessionId}: IOException during data transfer. Backend may have closed the connection. InnerException: {Inner}",
                _session.Id, ioEx.InnerException?.Message ?? "none");
            // CRITICAL: Drain the backend's pending response to prevent response desync.
            // The backend may have sent a 226/426 that we must consume before the next command.
            await DrainBackendResponseAsync("IOException");

            // CRITICAL: For failed uploads, delete the 0 byte file that was created when the backend
            // received the STOR command. Otherwise empty/corrupted files will litter the server.
            var isUpload = UploadCommands.Contains(command.Verb);
            if (isUpload && !string.IsNullOrEmpty(command.Argument))
            {
                await DeleteFailedUploadFileAsync(command.Argument);
            }

            await SendResponseAsync(FtpResponseParser.Codes.ActionAborted, "Transfer failed");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Session {SessionId}: Error during data transfer: {ExType}",
                _session.Id, ex.GetType().Name);
            // CRITICAL: Drain the backend's pending response to prevent response desync.
            // The backend may have sent a 226/426 that we must consume before the next command.
            await DrainBackendResponseAsync(ex.GetType().Name);

            // CRITICAL: For failed uploads, delete the 0 byte file that was created when the backend
            // received the STOR command. Otherwise empty/corrupted files will litter the server.
            var isUpload = UploadCommands.Contains(command.Verb);
            if (isUpload && !string.IsNullOrEmpty(command.Argument))
            {
                await DeleteFailedUploadFileAsync(command.Argument);
            }

            await SendResponseAsync(FtpResponseParser.Codes.ActionAborted, "Transfer failed");
        }
    }

    /// <summary>
    /// Drains any pending response from the backend after a data transfer error.
    /// This prevents response desynchronization where a stale 226/426 response
    /// would be read by the next command instead of its proper response.
    /// </summary>
    private async Task DrainBackendResponseAsync(string errorContext)
    {
        if (_backendConnection is null)
        {
            return;
        }

        try
        {
            // Use a short timeout - we just want to drain any pending response
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            var response = await _backendConnection.ReadResponseAsync(cts.Token);
            _logger.LogWarning("Session {SessionId}: Drained stale backend response after {ErrorContext}: {Code} {Message}",
                _session.Id, errorContext, response.Code, response.Message);
        }
        catch (OperationCanceledException)
        {
            // Timeout - no pending response, which is fine
            _logger.LogDebug("Session {SessionId}: No pending backend response to drain after {ErrorContext}",
                _session.Id, errorContext);
        }
        catch (IOException)
        {
            // Backend connection closed - that's okay, no response to drain
            _logger.LogDebug("Session {SessionId}: Backend connection closed, no response to drain after {ErrorContext}",
                _session.Id, errorContext);
        }
        catch (Exception ex)
        {
            // Log but don't fail - we tried our best to drain the response
            _logger.LogDebug(ex, "Session {SessionId}: Error draining backend response after {ErrorContext}",
                _session.Id, errorContext);
        }
    }

    /// <summary>
    /// Deletes a file on the backend that was created for a failed upload.
    /// When an FTP server receives a STOR command, it creates the file before the data transfer.
    /// If the data transfer fails (especially with 0 bytes), we need to clean up this empty file.
    /// </summary>
    private async Task DeleteFailedUploadFileAsync(string filename)
    {
        if (_backendConnection is null || !_backendConnection.IsConnected)
        {
            _logger.LogDebug("Session {SessionId}: Cannot delete failed upload file - backend not connected", _session.Id);
            return;
        }

        try
        {
            _logger.LogInformation("Session {SessionId}: Deleting failed upload file: {Filename}", _session.Id, filename);

            // Send DELE command to remove the 0 byte file
            var deleCommand = new FtpCommand { Verb = "DELE", Argument = filename, RawCommand = $"DELE {filename}" };
            var response = await _backendConnection.SendCommandAsync(deleCommand, CancellationToken.None);

            if (response.Code == 250)
            {
                _logger.LogInformation("Session {SessionId}: Successfully deleted failed upload file: {Filename}", _session.Id, filename);
            }
            else
            {
                // File might not exist, or permission denied - log but don't fail
                _logger.LogWarning("Session {SessionId}: Could not delete failed upload file {Filename}: {Code} {Message}",
                    _session.Id, filename, response.Code, response.Message);
            }
        }
        catch (Exception ex)
        {
            // Log but don't fail - we tried our best to clean up
            _logger.LogWarning(ex, "Session {SessionId}: Error deleting failed upload file {Filename}",
                _session.Id, filename);
        }
    }

    private async Task<FtpResponse> ReadBackendResponseAsync(CancellationToken cancellationToken)
    {
        // Read the pending response from the backend without sending any command
        // This is used to read the 226 completion response after a data transfer
        return await _backendConnection!.ReadResponseAsync(cancellationToken);
    }

    private async Task UpgradeToTlsAsync(CancellationToken cancellationToken)
    {
        _session.State = SessionState.TlsNegotiation;

        // Get the shared OpenSSL context for session resumption support
        var sharedSslContext = _serviceProvider.GetService<OpenSslServerContext>();

        if (sharedSslContext is not null)
        {
            // Use OpenSSL with shared context - enables TLS session resumption
            // between control channel and data channels
            _logger.LogDebug("Upgrading control channel to TLS using shared OpenSSL context (session resumption enabled)");

            // OpenSSL operations are synchronous, wrap in Task.Run
            var tcpClient = new TcpClient { Client = _client.Client };
            _openSslStream = await Task.Run(() => OpenSslServerStream.Accept(
                tcpClient,
                sharedSslContext,
                _logger), cancellationToken);

            _clientStream = _openSslStream;
        }
        else
        {
            // Fall back to SslStream if no OpenSSL context available
            _logger.LogDebug("Upgrading control channel to TLS using .NET SslStream (no session resumption)");

            // Try SNI certificate manager first, fall back to legacy certificate provider
            var sniCertManager = _serviceProvider.GetService<ISniCertificateManager>();
            var certProvider = _serviceProvider.GetService<ICertificateProvider>();

            // Check if we have any certificates available
            var defaultCert = sniCertManager?.GetDefaultCertificate() ?? certProvider?.GetServerCertificate();
            if (defaultCert is null && sniCertManager?.GetRegisteredHostnames().Count == 0)
            {
                _logger.LogError("TLS upgrade requested but no certificate configured");
                throw new InvalidOperationException("No TLS certificate configured");
            }

            var sslStream = new SslStream(_clientStream, false);

            // Use SNI-based certificate selection
            var sslOptions = new SslServerAuthenticationOptions
            {
                ClientCertificateRequired = false,
                CertificateRevocationCheckMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck,
                ServerCertificateSelectionCallback = (sender, hostName) =>
                {
                    _logger.LogDebug("SNI certificate selection for hostname: {Hostname}", hostName ?? "(none)");

                    // Try SNI manager first
                    var cert = sniCertManager?.GetCertificateForHost(hostName);
                    if (cert is not null)
                    {
                        _logger.LogDebug("Using SNI certificate: {Subject}", cert.Subject);
                        return cert;
                    }

                    // Fall back to legacy certificate provider
                    cert = certProvider?.GetServerCertificate();
                    if (cert is not null)
                    {
                        _logger.LogDebug("Using default certificate: {Subject}", cert.Subject);
                        return cert;
                    }

                    _logger.LogWarning("No certificate found for hostname {Hostname}", hostName);
                    return null!;
                }
            };

            await sslStream.AuthenticateAsServerAsync(sslOptions, cancellationToken);
            _clientStream = sslStream;
        }

        var utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        _reader = new StreamReader(_clientStream, utf8NoBom);
        _writer = new StreamWriter(_clientStream, utf8NoBom) { AutoFlush = true };

        _session.ClientTlsEnabled = true;
        _session.State = SessionState.Connected;

        _logger.LogDebug("TLS upgrade completed for session {SessionId}", _session.Id);
    }

    private async Task SendResponseAsync(int code, string message)
    {
        await _writer.WriteLineAsync($"{code} {message}");
    }

    #region Backend Health Check

    private void StartKeepaliveTask()
    {
        _keepaliveCts = new CancellationTokenSource();
        _lastBackendActivity = DateTime.UtcNow;
        _keepaliveTask = Task.Run(() => BackendHealthCheckLoopAsync(_keepaliveCts.Token));
        _logger.LogDebug("Session {SessionId}: Started backend health check task (interval: {Interval}s)",
            _session.Id, KeepAliveIntervalSeconds);
    }

    private void StopKeepaliveTask()
    {
        if (_keepaliveCts != null)
        {
            _keepaliveCts.Cancel();
            try
            {
                _keepaliveTask?.Wait(TimeSpan.FromSeconds(2));
            }
            catch { }
            _keepaliveCts.Dispose();
            _keepaliveCts = null;
            _keepaliveTask = null;
            _logger.LogDebug("Session {SessionId}: Stopped backend health check task", _session.Id);
        }
    }

    private async Task BackendHealthCheckLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested &&
                   _session.State == SessionState.Active)
            {
                // Wait for the check interval
                await Task.Delay(TimeSpan.FromSeconds(KeepAliveIntervalSeconds), cancellationToken);

                // Check if the backend connection is still alive
                if (_backendConnection is FtpBackendConnection ftpBackend)
                {
                    if (!ftpBackend.IsConnected)
                    {
                        _logger.LogWarning("Session {SessionId}: Backend health check detected disconnection, closing client connection",
                            _session.Id);

                        // Close the client socket to trigger the command loop to exit
                        try
                        {
                            _client.Client?.Shutdown(System.Net.Sockets.SocketShutdown.Both);
                            _client.Close();
                        }
                        catch { }

                        break;
                    }

                    // Check if the socket is actually connected by polling
                    // Poll with SelectRead: if readable with no data available = disconnected
                    try
                    {
                        var socket = ftpBackend.GetSocket();
                        if (socket != null)
                        {
                            bool readable = socket.Poll(0, System.Net.Sockets.SelectMode.SelectRead);
                            bool hasData = socket.Available > 0;

                            if (readable && !hasData)
                            {
                                // Socket is readable but no data = connection closed by peer
                                _logger.LogWarning("Session {SessionId}: Backend health check detected peer closure (poll), closing client connection",
                                    _session.Id);

                                try
                                {
                                    _client.Client?.Shutdown(System.Net.Sockets.SocketShutdown.Both);
                                    _client.Close();
                                }
                                catch { }

                                break;
                            }
                        }
                    }
                    catch
                    {
                        // Socket error during poll = connection is dead
                        _logger.LogWarning("Session {SessionId}: Backend health check socket poll failed, closing client connection",
                            _session.Id);

                        try
                        {
                            _client.Client?.Shutdown(System.Net.Sockets.SocketShutdown.Both);
                            _client.Close();
                        }
                        catch { }

                        break;
                    }
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal cancellation
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Session {SessionId}: Backend health check loop ended with error", _session.Id);
        }
    }

    /// <summary>
    /// Updates the last backend activity timestamp. Call this after any backend command.
    /// </summary>
    private void TouchBackendActivity()
    {
        _lastBackendActivity = DateTime.UtcNow;
    }

    #endregion

    public void Dispose()
    {
        StopKeepaliveTask();
        _backendCommandLock.Dispose();
        _dataChannelManager?.CancelDataChannel(_session.Id);
        _dataChannelManager?.CleanupSession(_session.Id);
        _backendConnection?.DisposeAsync().AsTask().Wait();
        _reader?.Dispose();
        _writer?.Dispose();
        _openSslStream?.Dispose();
    }
}
