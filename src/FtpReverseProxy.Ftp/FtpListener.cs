using System.Net;
using System.Net.Sockets;
using FtpReverseProxy.Core.Enums;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Ftp.Handlers;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp;

/// <summary>
/// TCP listener for FTP connections
/// </summary>
public class FtpListener : IProxyListener
{
    private readonly IPAddress _listenAddress;
    private readonly int _port;
    private readonly IServiceProvider _serviceProvider;
    private readonly ISessionManager _sessionManager;
    private readonly ILogger<FtpListener> _logger;
    private readonly bool _implicitTls;

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;

    public FtpListener(
        string listenAddress,
        int port,
        IServiceProvider serviceProvider,
        ISessionManager sessionManager,
        ILogger<FtpListener> logger,
        bool implicitTls = false)
    {
        _listenAddress = IPAddress.Parse(listenAddress);
        _port = port;
        _serviceProvider = serviceProvider;
        _sessionManager = sessionManager;
        _logger = logger;
        _implicitTls = implicitTls;
    }

    public bool IsListening => _listener?.Server.IsBound ?? false;
    public string ListenAddress => _listenAddress.ToString();
    public int Port => _port;
    public string Protocol => _implicitTls ? "FTPS (Implicit)" : "FTP";

    private Core.Enums.Protocol ClientProtocol => _implicitTls ? Core.Enums.Protocol.FtpsImplicit : Core.Enums.Protocol.Ftp;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _listener = new TcpListener(_listenAddress, _port);

        try
        {
            _listener.Start();
            _logger.LogInformation("{Protocol} listener started on {Address}:{Port}", Protocol, _listenAddress, _port);

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
            _logger.LogError(ex, "Error starting {Protocol} listener on {Address}:{Port}", Protocol, _listenAddress, _port);
            throw;
        }
    }

    public Task StopAsync()
    {
        _cts?.Cancel();
        _listener?.Stop();
        _logger.LogInformation("{Protocol} listener stopped on {Address}:{Port}", Protocol, _listenAddress, _port);
        return Task.CompletedTask;
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        var endpoint = client.Client.RemoteEndPoint as IPEndPoint;

        // Reject new connections during shutdown
        if (_sessionManager.IsShuttingDown)
        {
            _logger.LogDebug("Rejecting connection from {RemoteEndpoint} - server is shutting down", endpoint);
            client.Dispose();
            return;
        }

        _logger.LogInformation("New connection from {RemoteEndpoint}", endpoint);

        // Create a new scope for each connection to ensure proper DbContext isolation
        // This prevents thread-safety issues when multiple connections authenticate concurrently
        await using var scope = _serviceProvider.CreateAsyncScope();

        try
        {
            using var handler = new FtpSessionHandler(
                client,
                scope.ServiceProvider,
                _sessionManager,
                ClientProtocol,
                _logger);

            await handler.HandleSessionAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            // Log with full exception details including type and stack trace
            _logger.LogError(ex, "Error handling client session from {RemoteEndpoint}. ExType={ExType}, Message={ExMessage}",
                endpoint, ex.GetType().FullName, ex.Message);

            // Also log inner exception if present
            if (ex.InnerException != null)
            {
                _logger.LogError("Inner exception: {InnerType}: {InnerMessage}",
                    ex.InnerException.GetType().FullName, ex.InnerException.Message);
            }
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
