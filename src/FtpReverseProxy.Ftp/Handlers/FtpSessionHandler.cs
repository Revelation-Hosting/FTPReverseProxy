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

        // Get metrics service
        _metrics = _serviceProvider.GetService<IProxyMetrics>();
        _metrics?.RecordConnectionOpened(_protocol.ToString(), null);

        // Get data channel manager
        _dataChannelManager = _serviceProvider.GetRequiredService<IDataChannelManager>();

        try
        {
            // Get network stream
            _clientStream = _client.GetStream();

            // Handle implicit TLS
            if (_protocol == Protocol.FtpsImplicit)
            {
                await UpgradeToTlsAsync(cancellationToken);
            }

            _reader = new StreamReader(_clientStream, Encoding.UTF8);
            _writer = new StreamWriter(_clientStream, Encoding.UTF8) { AutoFlush = true };

            // Send welcome banner
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
                var line = await _reader.ReadLineAsync(cancellationToken);
                if (line is null)
                {
                    _logger.LogDebug("Client disconnected");
                    break;
                }

                _session.LastActivityAt = DateTime.UtcNow;
                _session.CommandCount++;

                var command = FtpCommandParser.Parse(line);
                _logger.LogDebug("Received command: {Verb} {Argument}", command.Verb,
                    command.Verb == FtpCommandParser.Commands.Pass ? "****" : command.Argument);

                await HandleCommandAsync(command, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (IOException)
            {
                _logger.LogDebug("Connection lost");
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing command");
                await SendResponseAsync(FtpResponseParser.Codes.ActionAborted, "Internal error");
            }
        }
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

            // Connect to backend
            _backendConnection = _serviceProvider.GetRequiredService<IBackendConnection>();
            await _backendConnection.ConnectAsync(backend, cancellationToken);

            // Upgrade backend to TLS if needed
            if (_session.ClientTlsEnabled && backend.Protocol != Protocol.Ftp)
            {
                await _backendConnection.UpgradeToTlsAsync(cancellationToken);
                _session.BackendTlsEnabled = true;
            }

            // Authenticate with backend
            var authSuccess = await _backendConnection.AuthenticateAsync(credentials, cancellationToken);

            // Record authentication result
            _metrics?.RecordAuthentication(authSuccess, _protocol.ToString(), backend.Id);

            if (authSuccess)
            {
                _session.State = SessionState.Active;
                _logger.LogInformation("User {Username} authenticated, connected to backend {Backend}",
                    _pendingUsername, backend.Name);
                await SendResponseAsync(FtpResponseParser.Codes.UserLoggedIn, "Login successful");
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
        features.AppendLine(" PORT");
        features.AppendLine(" EPRT");
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
        var useTls = _session.DataChannelProtected && _session.ClientTlsEnabled;
        var proxyEndpoint = await _dataChannelManager!.SetupPassiveRelayAsync(
            _session.Id,
            backendEndpoint,
            useTls,
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
        var useTls = _session.DataChannelProtected && _session.ClientTlsEnabled;
        var proxyEndpoint = await _dataChannelManager!.SetupActiveRelayAsync(
            _session.Id,
            clientEndpoint,
            useTls,
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

        _logger.LogDebug("Starting data transfer for {Command} in {Mode} mode",
            command.Verb, dataChannelMode);

        // Send command to backend
        var response = await _backendConnection!.SendCommandAsync(command, cancellationToken);

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
            var (uploaded, downloaded) = await _dataChannelManager.RelayDataAsync(_session.Id, cancellationToken);

            _session.BytesUploaded += uploaded;
            _session.BytesDownloaded += downloaded;

            _logger.LogDebug("Data transfer completed: {Uploaded} bytes up, {Downloaded} bytes down",
                uploaded, downloaded);

            // Read the completion response from backend (226)
            var completionResponse = await ReadBackendResponseAsync(cancellationToken);
            await _writer.WriteLineAsync(completionResponse.RawResponse);
        }
        catch (OperationCanceledException)
        {
            await SendResponseAsync(FtpResponseParser.Codes.ConnectionClosed, "Transfer aborted");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during data transfer");
            await SendResponseAsync(FtpResponseParser.Codes.ActionAborted, "Transfer failed");
        }
    }

    private async Task<FtpResponse> ReadBackendResponseAsync(CancellationToken cancellationToken)
    {
        // This is a simplified version - ideally IBackendConnection should expose this
        // For now, we'll send a NOOP to get a response
        return await _backendConnection!.SendCommandAsync(
            new FtpCommand { Verb = "", Argument = null, RawCommand = "" },
            cancellationToken);
    }

    private async Task UpgradeToTlsAsync(CancellationToken cancellationToken)
    {
        _session.State = SessionState.TlsNegotiation;

        var certProvider = _serviceProvider.GetRequiredService<ICertificateProvider>();
        var certificate = certProvider.GetServerCertificate();

        if (certificate is null)
        {
            _logger.LogError("TLS upgrade requested but no certificate configured");
            throw new InvalidOperationException("No TLS certificate configured");
        }

        var sslStream = new SslStream(_clientStream, false);
        await sslStream.AuthenticateAsServerAsync(
            certificate,
            clientCertificateRequired: false,
            checkCertificateRevocation: false);

        _clientStream = sslStream;
        _reader = new StreamReader(_clientStream, Encoding.UTF8);
        _writer = new StreamWriter(_clientStream, Encoding.UTF8) { AutoFlush = true };

        _session.ClientTlsEnabled = true;
        _session.State = SessionState.Connected;

        _logger.LogDebug("TLS upgrade completed for session {SessionId}", _session.Id);
    }

    private async Task SendResponseAsync(int code, string message)
    {
        await _writer.WriteLineAsync($"{code} {message}");
    }

    public void Dispose()
    {
        _dataChannelManager?.CancelDataChannel(_session.Id);
        _backendConnection?.DisposeAsync().AsTask().Wait();
        _reader?.Dispose();
        _writer?.Dispose();
    }
}
