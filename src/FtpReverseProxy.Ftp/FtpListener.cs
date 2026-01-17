using System.Net;
using System.Net.Sockets;
using FtpReverseProxy.Core.Enums;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Ftp.Handlers;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp;

/// <summary>
/// TCP listener for FTP connections
/// </summary>
public class FtpListener : IProxyListener
{
    private readonly int _port;
    private readonly IServiceProvider _serviceProvider;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger<FtpListener> _logger;
    private readonly bool _implicitTls;

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    public FtpListener(
        int port,
        IServiceProvider serviceProvider,
        ISessionManager sessionManager,
        ILogger<FtpListener> logger,
        bool implicitTls = false)
    {
        _port = port;
        _serviceProvider = serviceProvider;
        _sessionManager = sessionManager;
        _logger = logger;
        _implicitTls = implicitTls;
    }

    public bool IsListening => _listener?.Server.IsBound ?? false;
    public int Port => _port;
    public string Protocol => _implicitTls ? "FTPS (Implicit)" : "FTP";

    private Core.Enums.Protocol ClientProtocol => _implicitTls ? Core.Enums.Protocol.FtpsImplicit : Core.Enums.Protocol.Ftp;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _listener = new TcpListener(IPAddress.Any, _port);

        try
        {
            _listener.Start();
            _logger.LogInformation("{Protocol} listener started on port {Port}", Protocol, _port);

            while (!_cts.Token.IsCancellationRequested)
            {
                try
                {
                    var client = await _listener.AcceptTcpClientAsync(_cts.Token);
                    _ = HandleClientAsync(client, _cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error accepting client connection");
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error starting {Protocol} listener on port {Port}", Protocol, _port);
            throw;
        }
    }

    public Task StopAsync()
    {
        _cts?.Cancel();
        _listener?.Stop();
        _logger.LogInformation("{Protocol} listener stopped on port {Port}", Protocol, _port);
        return Task.CompletedTask;
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        var endpoint = client.Client.RemoteEndPoint as IPEndPoint;
        _logger.LogInformation("New connection from {RemoteEndpoint}", endpoint);

        try
        {
            using var handler = new FtpSessionHandler(
                client,
                _serviceProvider,
                _sessionManager,
                ClientProtocol,
                _logger);

            await handler.HandleSessionAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error handling client session from {RemoteEndpoint}", endpoint);
        }
        finally
        {
            client.Dispose();
            _logger.LogInformation("Connection closed from {RemoteEndpoint}", endpoint);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _cts?.Dispose();
        GC.SuppressFinalize(this);
    }
}
