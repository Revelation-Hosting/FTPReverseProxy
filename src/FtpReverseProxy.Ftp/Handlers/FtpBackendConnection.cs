using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using FtpReverseProxy.Core.Enums;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Core.Models;
using FtpReverseProxy.Ftp.Parsing;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp.Handlers;

/// <summary>
/// Manages connection to a backend FTP server
/// </summary>
public class FtpBackendConnection : IBackendConnection
{
    private readonly ILogger<FtpBackendConnection> _logger;

    private TcpClient? _client;
    private Stream? _stream;
    private StreamReader? _reader;
    private StreamWriter? _writer;
    private BackendServer? _server;

    public FtpBackendConnection(ILogger<FtpBackendConnection> logger)
    {
        _logger = logger;
    }

    public bool IsConnected => _client?.Connected ?? false;
    public bool IsTlsEnabled { get; private set; }

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

        _reader = new StreamReader(_stream, Encoding.UTF8);
        _writer = new StreamWriter(_stream, Encoding.UTF8) { AutoFlush = true };

        // Read welcome banner
        var banner = await ReadResponseAsync(cancellationToken);
        _logger.LogDebug("Backend banner: {Banner}", banner.Message);

        if (!banner.IsSuccess && banner.Code != FtpResponseParser.Codes.ServiceReady)
        {
            throw new InvalidOperationException($"Backend server returned error: {banner.RawResponse}");
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

        await _writer.WriteLineAsync(command.RawCommand);
        return await ReadResponseAsync(cancellationToken);
    }

    public async Task UpgradeToTlsAsync(CancellationToken cancellationToken = default)
    {
        if (_stream is null || _server is null)
        {
            throw new InvalidOperationException("Not connected");
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

        var sslStream = new SslStream(_stream, false, ValidateServerCertificate);
        await sslStream.AuthenticateAsClientAsync(_server.Host);

        _stream = sslStream;
        _reader = new StreamReader(_stream, Encoding.UTF8);
        _writer = new StreamWriter(_stream, Encoding.UTF8) { AutoFlush = true };

        IsTlsEnabled = true;

        _logger.LogDebug("TLS upgrade completed for backend {BackendName}", _server.Name);
    }

    public async Task DisconnectAsync()
    {
        if (_writer is not null && IsConnected)
        {
            try
            {
                await _writer.WriteLineAsync("QUIT");
                await ReadResponseAsync(CancellationToken.None);
            }
            catch
            {
                // Ignore errors during disconnect
            }
        }

        _reader?.Dispose();
        _writer?.Dispose();
        _client?.Dispose();

        _reader = null;
        _writer = null;
        _client = null;
        _stream = null;
    }

    private async Task<FtpResponse> ReadResponseAsync(CancellationToken cancellationToken)
    {
        var lines = new List<string>();
        var firstLine = await _reader!.ReadLineAsync(cancellationToken);

        if (firstLine is null)
        {
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

    private static bool ValidateServerCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        // TODO: Make this configurable - for now accept all certificates
        return true;
    }

    public async ValueTask DisposeAsync()
    {
        await DisconnectAsync();
        GC.SuppressFinalize(this);
    }
}
