using System.Net.Sockets;
using System.Text;
using FtpReverseProxy.Core.Enums;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Core.Models;
using FtpReverseProxy.Ftp.Parsing;
using FtpReverseProxy.Ftp.Tls;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp.Handlers;

/// <summary>
/// Manages connection to a backend FTP server.
/// Uses native OpenSSL for TLS with session resumption support on data channels.
/// </summary>
public class FtpBackendConnection : IBackendConnection
{
    private readonly ILogger<FtpBackendConnection> _logger;
    private readonly IBackendCertificateValidator _certificateValidator;

    private TcpClient? _client;
    private Stream? _stream;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private BackendServer? _server;
    private OpenSslTlsStream? _openSslStream;
    private OpenSslSession? _tlsSession;

    public FtpBackendConnection(
        ILogger<FtpBackendConnection> logger,
        IBackendCertificateValidator certificateValidator)
    {
        _logger = logger;
        _certificateValidator = certificateValidator;
    }

    public bool IsConnected => _client?.Connected ?? false;
    public bool IsTlsEnabled { get; private set; }

    /// <summary>
    /// Gets the TLS session from the control channel for session resumption on data channel.
    /// This is an OpenSslSession that wraps the native OpenSSL session pointer.
    /// </summary>
    public object? TlsSessionForResumption => _tlsSession;

    /// <summary>
    /// Gets the underlying socket for health checking (polling).
    /// </summary>
    public Socket? GetSocket() => _client?.Client;

    public async Task ConnectAsync(BackendServer server, CancellationToken cancellationToken = default)
    {
        _server = server;
        _client = new TcpClient();

        _logger.LogDebug("Connecting to backend {BackendName} at {Host}:{Port}",
            server.Name, server.Host, server.Port);

        var connectTask = _client.ConnectAsync(server.Host, server.Port, cancellationToken);
        var timeoutTask = Task.Delay(server.ConnectionTimeoutMs, cancellationToken);

        if (await Task.WhenAny(connectTask.AsTask(), timeoutTask) == timeoutTask)
        {
            _client.Dispose();
            throw new TimeoutException($"Connection to {server.Host}:{server.Port} timed out");
        }

        await connectTask;

        _stream = _client.GetStream();

        // Handle implicit TLS
        if (server.Protocol == Protocol.FtpsImplicit)
        {
            await UpgradeToTlsAsync(cancellationToken);
        }

        var utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        _reader = new StreamReader(_stream, utf8NoBom);
        _writer = new StreamWriter(_stream, utf8NoBom) { AutoFlush = true };

        // Read welcome banner
        var banner = await ReadResponseAsync(cancellationToken);
        _logger.LogDebug("Backend banner: {Banner}", banner.Message);

        if (!banner.IsSuccess && banner.Code != FtpResponseParser.Codes.ServiceReady)
        {
            throw new InvalidOperationException($"Backend server returned error: {banner.RawResponse}");
        }

        // Handle explicit TLS (upgrade after banner, before authentication)
        if (server.Protocol == Protocol.FtpsExplicit)
        {
            _logger.LogDebug("Upgrading to TLS for explicit FTPS backend {BackendName}", server.Name);
            await UpgradeToTlsAsync(cancellationToken);
        }
    }

    public async Task<bool> AuthenticateAsync(BackendCredentials credentials, CancellationToken cancellationToken = default)
    {
        // Send USER command
        await _writer!.WriteLineAsync($"USER {credentials.Username}");
        var userResponse = await ReadResponseAsync(cancellationToken);

        if (userResponse.Code == FtpResponseParser.Codes.UserLoggedIn)
        {
            // Some servers accept passwordless login
            return true;
        }

        if (userResponse.Code != FtpResponseParser.Codes.UserNameOkNeedPassword)
        {
            _logger.LogWarning("Backend USER command failed: {Response}", userResponse.RawResponse);
            return false;
        }

        // Send PASS command
        await _writer.WriteLineAsync($"PASS {credentials.Password}");
        var passResponse = await ReadResponseAsync(cancellationToken);

        if (passResponse.Code == FtpResponseParser.Codes.UserLoggedIn)
        {
            _logger.LogDebug("Backend authentication successful for user {Username}", credentials.Username);
            return true;
        }

        _logger.LogWarning("Backend authentication failed: {Response}", passResponse.RawResponse);
        return false;
    }

    public async Task<FtpResponse> SendCommandAsync(FtpCommand command, CancellationToken cancellationToken = default)
    {
        if (_writer is null || _reader is null)
        {
            throw new InvalidOperationException("Not connected to backend");
        }

        _logger.LogInformation("Sending to backend: {Command}", command.RawCommand);
        await _writer.WriteLineAsync(command.RawCommand);
        _logger.LogDebug("Command sent, reading backend response...");
        return await ReadResponseAsync(cancellationToken);
    }

    public async Task UpgradeToTlsAsync(CancellationToken cancellationToken = default)
    {
        if (_stream is null || _server is null || _client is null)
        {
            throw new InvalidOperationException("Not connected");
        }

        // Skip if TLS is already enabled
        if (IsTlsEnabled)
        {
            _logger.LogDebug("TLS already enabled for backend {BackendName}, skipping UpgradeToTlsAsync", _server.Name);
            return;
        }

        if (_server.Protocol == Protocol.FtpsExplicit)
        {
            // Send AUTH TLS command first
            await _writer!.WriteLineAsync("AUTH TLS");
            var response = await ReadResponseAsync(cancellationToken);

            if (response.Code != FtpResponseParser.Codes.SecurityDataExchange)
            {
                throw new InvalidOperationException($"AUTH TLS failed: {response.RawResponse}");
            }
        }

        // Use native OpenSSL for TLS with proper session resumption support
        // This allows us to capture the TLS session and resume it on data channels
        _logger.LogInformation("Upgrading to TLS using native OpenSSL for backend {BackendName}", _server.Name);

        // OpenSSL Connect is synchronous, so wrap in Task.Run
        _openSslStream = await Task.Run(() => OpenSslTlsStream.Connect(
            _client,
            _server.Host,
            skipCertificateValidation: _server.SkipCertificateValidation,
            sessionToResume: IntPtr.Zero, // No session to resume for control channel
            logger: _logger), cancellationToken);

        // Capture the session for resumption on data channels
        var sessionPtr = _openSslStream.GetSession();
        if (sessionPtr != IntPtr.Zero)
        {
            _tlsSession = new OpenSslSession(sessionPtr);
            _logger.LogInformation("OpenSSL: Captured TLS session for data channel resumption. SessionID: {SessionId}",
                _tlsSession.SessionId);
        }
        else
        {
            _logger.LogWarning("OpenSSL: Failed to capture TLS session - data channel resumption may not work");
        }

        _stream = _openSslStream;
        var utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);
        _reader = new StreamReader(_stream, utf8NoBom);
        _writer = new StreamWriter(_stream, utf8NoBom) { AutoFlush = true };

        IsTlsEnabled = true;

        _logger.LogInformation("Control channel TLS established using OpenSSL for backend {BackendName}. Protocol: {Protocol}, Cipher: {Cipher}",
            _server.Name, _openSslStream.ProtocolVersion, _openSslStream.CipherSuite);

        // Send PBSZ and PROT P to enable protected data channel
        if (_server.Protocol == Protocol.FtpsExplicit || _server.Protocol == Protocol.FtpsImplicit)
        {
            await _writer.WriteLineAsync("PBSZ 0");
            var pbszResponse = await ReadResponseAsync(cancellationToken);
            _logger.LogDebug("PBSZ response: {Response}", pbszResponse.RawResponse);

            await _writer.WriteLineAsync("PROT P");
            var protResponse = await ReadResponseAsync(cancellationToken);
            _logger.LogDebug("PROT P response: {Response}", protResponse.RawResponse);

            if (protResponse.Code != 200)
            {
                _logger.LogWarning("PROT P failed: {Response}. Data transfers may not be encrypted.", protResponse.RawResponse);
            }
        }
    }

    public async Task DisconnectAsync()
    {
        // Never send QUIT from the proxy on its own.
        // If the client wants to quit, they send QUIT and we forward it.
        // If the client disconnects without QUIT, we just close the socket.
        // The backend will clean up the connection on its own when it detects the socket close.
        await Task.CompletedTask; // Keep method async for interface compatibility

        _reader?.Dispose();
        _writer?.Dispose();
        _openSslStream?.Dispose();
        _tlsSession?.Dispose();
        _client?.Dispose();

        _reader = null;
        _writer = null;
        _openSslStream = null;
        _tlsSession = null;
        _client = null;
        _stream = null;
    }

    public async Task<FtpResponse> ReadResponseAsync(CancellationToken cancellationToken = default)
    {
        var lines = new List<string>();
        string? firstLine = null;

        try
        {
            firstLine = await _reader!.ReadLineAsync(cancellationToken);
        }
        catch (IOException ioEx)
        {
            // Capture underlying exception details
            var innerMsg = ioEx.InnerException?.Message ?? "none";
            var socketConnected = _client?.Client?.Connected ?? false;
            _logger.LogError(ioEx, "IOException reading from backend. SocketConnected: {SocketConnected}, Inner: {Inner}, Server: {Server}",
                socketConnected, innerMsg, _server?.Name ?? "unknown");
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected exception reading from backend: {ExType} - {Message}",
                ex.GetType().Name, ex.Message);
            throw;
        }

        if (firstLine is null)
        {
            // Log additional diagnostics when connection is unexpectedly closed
            var connected = _client?.Connected ?? false;
            var socketConnected = _client?.Client?.Connected ?? false;
            var tlsEnabled = IsTlsEnabled;
            var socketAvailable = 0;
            try { socketAvailable = _client?.Client?.Available ?? 0; } catch { }

            _logger.LogWarning("Backend connection closed unexpectedly. TcpClient.Connected: {Connected}, Socket.Connected: {SocketConnected}, TlsEnabled: {TlsEnabled}, BytesAvailable: {Available}, Server: {Server}",
                connected, socketConnected, tlsEnabled, socketAvailable, _server?.Name ?? "unknown");
            throw new IOException("Connection closed by backend");
        }

        lines.Add(firstLine);

        // Check for multi-line response
        if (FtpResponseParser.IsMultiLineStart(firstLine))
        {
            var expectedCode = int.Parse(firstLine[..3]);

            while (true)
            {
                var line = await _reader.ReadLineAsync(cancellationToken);
                if (line is null)
                {
                    throw new IOException("Connection closed during multi-line response");
                }

                lines.Add(line);

                if (FtpResponseParser.IsMultiLineEnd(line, expectedCode))
                {
                    break;
                }
            }
        }

        return FtpResponseParser.Parse(lines);
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync();
        GC.SuppressFinalize(this);
    }
}
