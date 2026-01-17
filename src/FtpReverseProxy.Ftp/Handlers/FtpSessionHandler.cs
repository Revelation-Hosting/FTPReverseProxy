using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FtpReverseProxy.Core.Enums;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Core.Models;
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
            _sessionManager.RemoveSession(_session.Id);
            _session.State = SessionState.Closed;
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
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during authentication for user {Username}", _pendingUsername);
            await SendResponseAsync(FtpResponseParser.Codes.ServiceNotAvailable, "Authentication error");
            _session.State = SessionState.Connected;
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
        features.AppendLine(" SIZE");
        features.AppendLine(" MDTM");
        features.Append("211 End");

        await _writer.WriteLineAsync(features.ToString());
    }

    private async Task HandleProxiedCommandAsync(FtpCommand command, CancellationToken cancellationToken)
    {
        if (_session.State != SessionState.Active || _backendConnection is null)
        {
            await SendResponseAsync(FtpResponseParser.Codes.NotLoggedIn, "Please login first");
            return;
        }

        // Special handling for data channel commands
        if (command.Verb is FtpCommandParser.Commands.Pasv or FtpCommandParser.Commands.Epsv)
        {
            await HandlePassiveModeAsync(command, cancellationToken);
            return;
        }

        if (command.Verb is FtpCommandParser.Commands.Port or FtpCommandParser.Commands.Eprt)
        {
            await HandleActiveModeAsync(command, cancellationToken);
            return;
        }

        // Forward command to backend and relay response
        var response = await _backendConnection.SendCommandAsync(command, cancellationToken);
        await _writer.WriteLineAsync(response.RawResponse);
    }

    private async Task HandlePassiveModeAsync(FtpCommand command, CancellationToken cancellationToken)
    {
        // TODO: Implement data channel relay for passive mode
        // For now, forward to backend and rewrite response
        var response = await _backendConnection!.SendCommandAsync(command, cancellationToken);

        if (response.Code == FtpResponseParser.Codes.EnteringPassiveMode ||
            response.Code == FtpResponseParser.Codes.EnteringExtendedPassiveMode)
        {
            // TODO: Set up data channel relay and rewrite response with proxy's address
            _session.DataChannelMode = DataChannelMode.Passive;
        }

        await _writer.WriteLineAsync(response.RawResponse);
    }

    private async Task HandleActiveModeAsync(FtpCommand command, CancellationToken cancellationToken)
    {
        // TODO: Implement data channel relay for active mode
        _session.DataChannelMode = DataChannelMode.Active;
        var response = await _backendConnection!.SendCommandAsync(command, cancellationToken);
        await _writer.WriteLineAsync(response.RawResponse);
    }

    private async Task UpgradeToTlsAsync(CancellationToken cancellationToken)
    {
        _session.State = SessionState.TlsNegotiation;

        // TODO: Load certificate from configuration
        var certificate = GetServerCertificate();

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

    private static X509Certificate2 GetServerCertificate()
    {
        // TODO: Load from configuration/certificate store
        // For now, create a self-signed certificate
        throw new NotImplementedException("Server certificate configuration required");
    }

    private async Task SendResponseAsync(int code, string message)
    {
        await _writer.WriteLineAsync($"{code} {message}");
    }

    public void Dispose()
    {
        _backendConnection?.DisposeAsync().AsTask().Wait();
        _reader?.Dispose();
        _writer?.Dispose();
    }
}
