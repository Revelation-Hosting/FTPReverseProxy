using System.Net;
using System.Net.Sockets;
using FtpReverseProxy.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Core.TcpRelay;

/// <summary>
/// Transparent TCP relay listener - forwards connections directly to backend.
/// Similar to NGINX streams - no protocol inspection, just byte forwarding.
/// Perfect for SSH/SFTP where backend should handle all authentication.
/// </summary>
public class TcpRelayListener : IProxyListener
{
    private readonly IPAddress _listenAddress;
    private readonly int _listenPort;
    private readonly string _backendHost;
    private readonly int _backendPort;
    private readonly string _name;
    private readonly ILogger _logger;
    private readonly IProxyMetrics? _metrics;

    private TcpListener? _listener;
    private CancellationTokenSource? _cts;
    private Task? _acceptTask;

    public TcpRelayListener(
        string listenAddress,
        int listenPort,
        string backendHost,
        int backendPort,
        string name,
        ILogger logger,
        IProxyMetrics? metrics = null)
    {
        _listenAddress = IPAddress.Parse(listenAddress);
        _listenPort = listenPort;
        _backendHost = backendHost;
        _backendPort = backendPort;
        _name = name;
        _logger = logger;
        _metrics = metrics;
    }

    public bool IsListening => _listener != null;
    public string ListenAddress => _listenAddress.ToString();
    public int Port => _listenPort;
    public string Protocol => "TCP-Relay";

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _listener = new TcpListener(_listenAddress, _listenPort);
        _listener.Start();

        _logger.LogInformation(
            "TCP Relay '{Name}' started on {Address}:{Port} -> {Backend}:{BackendPort}",
            _name, _listenAddress, _listenPort, _backendHost, _backendPort);

        _acceptTask = AcceptConnectionsAsync(_cts.Token);
        return Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        _cts?.Cancel();
        _listener?.Stop();

        if (_acceptTask != null)
        {
            try
            {
                await _acceptTask;
            }
            catch (OperationCanceledException)
            {
                // Expected
            }
        }

        _listener = null;
        _logger.LogInformation("TCP Relay '{Name}' stopped", _name);
    }

    private async Task AcceptConnectionsAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var client = await _listener!.AcceptTcpClientAsync(cancellationToken);
                var clientEndpoint = client.Client.RemoteEndPoint?.ToString() ?? "unknown";

                _logger.LogInformation(
                    "TCP Relay '{Name}': Connection from {Client}",
                    _name, clientEndpoint);

                // Handle connection in background - don't await
                _ = HandleConnectionAsync(client, clientEndpoint, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "TCP Relay '{Name}': Error accepting connection", _name);
            }
        }
    }

    private async Task HandleConnectionAsync(
        TcpClient client,
        string clientEndpoint,
        CancellationToken cancellationToken)
    {
        TcpClient? backend = null;

        try
        {
            // Connect to backend
            backend = new TcpClient();
            await backend.ConnectAsync(_backendHost, _backendPort, cancellationToken);

            _logger.LogDebug(
                "TCP Relay '{Name}': Connected to backend {Backend}:{Port} for {Client}",
                _name, _backendHost, _backendPort, clientEndpoint);

            _metrics?.RecordConnectionOpened("TCP-Relay", _name);

            // Get streams
            var clientStream = client.GetStream();
            var backendStream = backend.GetStream();

            // Relay bidirectionally
            var clientToBackend = RelayAsync(
                clientStream, backendStream,
                $"{clientEndpoint}->backend",
                cancellationToken);

            var backendToClient = RelayAsync(
                backendStream, clientStream,
                $"backend->{clientEndpoint}",
                cancellationToken);

            // Wait for either direction to complete (connection closed)
            await Task.WhenAny(clientToBackend, backendToClient);

            _logger.LogDebug(
                "TCP Relay '{Name}': Connection closed for {Client}",
                _name, clientEndpoint);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex,
                "TCP Relay '{Name}': Error handling connection from {Client}",
                _name, clientEndpoint);
        }
        finally
        {
            _metrics?.RecordConnectionClosed("TCP-Relay", _name);

            try { client.Close(); } catch { }
            try { backend?.Close(); } catch { }
        }
    }

    private async Task RelayAsync(
        NetworkStream source,
        NetworkStream destination,
        string direction,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[65536]; // 64KB buffer

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var bytesRead = await source.ReadAsync(buffer, cancellationToken);

                if (bytesRead == 0)
                {
                    // Connection closed
                    break;
                }

                await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
                await destination.FlushAsync(cancellationToken);
            }
        }
        catch (IOException)
        {
            // Connection reset - normal for TCP relay
        }
        catch (OperationCanceledException)
        {
            // Shutting down
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        _cts?.Dispose();
        GC.SuppressFinalize(this);
    }
}
