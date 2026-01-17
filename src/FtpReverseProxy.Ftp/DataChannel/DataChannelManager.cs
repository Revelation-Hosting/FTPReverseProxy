using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using FtpReverseProxy.Core.Enums;
using FtpReverseProxy.Core.Interfaces;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp.DataChannel;

/// <summary>
/// Manages FTP data channel connections for proxying between clients and backends
/// </summary>
public class DataChannelManager : IDataChannelManager
{
    private readonly ILogger<DataChannelManager> _logger;
    private readonly ConcurrentDictionary<Guid, DataChannelState> _channels = new();

    // Configuration for data channel port range
    private readonly int _minPort;
    private readonly int _maxPort;
    private readonly string? _externalAddress;
    private readonly X509Certificate2? _certificate;

    private int _nextPort;
    private readonly object _portLock = new();

    public DataChannelManager(
        ILogger<DataChannelManager> logger,
        int minPort = 50000,
        int maxPort = 51000,
        string? externalAddress = null,
        X509Certificate2? certificate = null)
    {
        _logger = logger;
        _minPort = minPort;
        _maxPort = maxPort;
        _nextPort = minPort;
        _externalAddress = externalAddress;
        _certificate = certificate;
    }

    public async Task<IPEndPoint> SetupPassiveRelayAsync(
        Guid sessionId,
        IPEndPoint backendEndpoint,
        bool useTls,
        CancellationToken cancellationToken = default)
    {
        // Clean up any existing data channel for this session
        CancelDataChannel(sessionId);

        var state = new DataChannelState
        {
            SessionId = sessionId,
            Mode = DataChannelMode.Passive,
            UseTls = useTls,
            BackendDataEndpoint = backendEndpoint
        };

        // Find an available port and start listening
        var listener = CreateListener();
        state.ClientListener = listener;
        state.LocalEndpoint = (IPEndPoint)listener.LocalEndpoint;

        _channels[sessionId] = state;

        _logger.LogDebug(
            "Passive data channel setup for session {SessionId}: listening on {LocalPort}, backend at {BackendEndpoint}",
            sessionId, state.LocalEndpoint.Port, backendEndpoint);

        // Start accepting connection in background (will be awaited during transfer)
        _ = AcceptPassiveConnectionAsync(state, cancellationToken);

        // Return the endpoint for the client to connect to
        var externalEndpoint = GetExternalEndpoint(state.LocalEndpoint);
        return externalEndpoint;
    }

    public async Task<IPEndPoint> SetupActiveRelayAsync(
        Guid sessionId,
        IPEndPoint clientEndpoint,
        bool useTls,
        CancellationToken cancellationToken = default)
    {
        // Clean up any existing data channel for this session
        CancelDataChannel(sessionId);

        var state = new DataChannelState
        {
            SessionId = sessionId,
            Mode = DataChannelMode.Active,
            UseTls = useTls,
            ClientDataEndpoint = clientEndpoint
        };

        // Create listener for backend to connect to
        var listener = CreateListener();
        state.BackendListener = listener;
        state.LocalEndpoint = (IPEndPoint)listener.LocalEndpoint;

        _channels[sessionId] = state;

        _logger.LogDebug(
            "Active data channel setup for session {SessionId}: listening on {LocalPort} for backend, client at {ClientEndpoint}",
            sessionId, state.LocalEndpoint.Port, clientEndpoint);

        // Start accepting connection in background
        _ = AcceptActiveConnectionAsync(state, cancellationToken);

        return state.LocalEndpoint;
    }

    public async Task<(long BytesUploaded, long BytesDownloaded)> RelayDataAsync(
        Guid sessionId,
        CancellationToken cancellationToken = default)
    {
        if (!_channels.TryGetValue(sessionId, out var state))
        {
            throw new InvalidOperationException($"No data channel found for session {sessionId}");
        }

        state.IsUsed = true;

        try
        {
            // Wait for the transfer to complete (or timeout/cancellation)
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken, state.Cts.Token);

            var result = await state.TransferCompletion.Task.WaitAsync(linkedCts.Token);

            _logger.LogDebug(
                "Data transfer completed for session {SessionId}: {BytesUploaded} uploaded, {BytesDownloaded} downloaded",
                sessionId, result.BytesUploaded, result.BytesDownloaded);

            return result;
        }
        finally
        {
            // Clean up after transfer
            _channels.TryRemove(sessionId, out _);
            state.Dispose();
        }
    }

    public void CancelDataChannel(Guid sessionId)
    {
        if (_channels.TryRemove(sessionId, out var state))
        {
            _logger.LogDebug("Cancelling data channel for session {SessionId}", sessionId);
            state.Dispose();
        }
    }

    public DataChannelMode? GetDataChannelMode(Guid sessionId)
    {
        return _channels.TryGetValue(sessionId, out var state) ? state.Mode : null;
    }

    private TcpListener CreateListener()
    {
        // Try to find an available port in our range
        lock (_portLock)
        {
            for (int attempts = 0; attempts < (_maxPort - _minPort); attempts++)
            {
                var port = _nextPort;
                _nextPort = _nextPort >= _maxPort ? _minPort : _nextPort + 1;

                try
                {
                    var listener = new TcpListener(IPAddress.Any, port);
                    listener.Start();
                    return listener;
                }
                catch (SocketException)
                {
                    // Port in use, try next
                    continue;
                }
            }
        }

        throw new InvalidOperationException("No available ports in data channel range");
    }

    private IPEndPoint GetExternalEndpoint(IPEndPoint localEndpoint)
    {
        if (!string.IsNullOrEmpty(_externalAddress))
        {
            return new IPEndPoint(IPAddress.Parse(_externalAddress), localEndpoint.Port);
        }

        // Try to get a reasonable external address
        // In production, this should be configured explicitly
        var host = Dns.GetHostEntry(Dns.GetHostName());
        var ipv4 = host.AddressList.FirstOrDefault(ip =>
            ip.AddressFamily == AddressFamily.InterNetwork &&
            !IPAddress.IsLoopback(ip));

        return new IPEndPoint(ipv4 ?? IPAddress.Loopback, localEndpoint.Port);
    }

    private async Task AcceptPassiveConnectionAsync(DataChannelState state, CancellationToken cancellationToken)
    {
        try
        {
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken, state.Cts.Token);

            // Set a timeout for client to connect
            linkedCts.CancelAfter(TimeSpan.FromSeconds(30));

            _logger.LogDebug("Waiting for client connection on port {Port}", state.LocalEndpoint!.Port);

            // Accept client connection
            var clientSocket = await state.ClientListener!.AcceptTcpClientAsync(linkedCts.Token);

            _logger.LogDebug("Client connected from {ClientEndpoint}", clientSocket.Client.RemoteEndPoint);

            // Connect to backend
            var backendSocket = new TcpClient();
            await backendSocket.ConnectAsync(
                state.BackendDataEndpoint!.Address,
                state.BackendDataEndpoint.Port,
                linkedCts.Token);

            _logger.LogDebug("Connected to backend data channel at {BackendEndpoint}", state.BackendDataEndpoint);

            // Stop listening for more connections
            state.ClientListener.Stop();

            // Relay data
            await RelayBidirectionalAsync(clientSocket, backendSocket, state, linkedCts.Token);
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Passive data channel cancelled for session {SessionId}", state.SessionId);
            state.TransferCompletion.TrySetCanceled();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in passive data channel for session {SessionId}", state.SessionId);
            state.TransferCompletion.TrySetException(ex);
        }
    }

    private async Task AcceptActiveConnectionAsync(DataChannelState state, CancellationToken cancellationToken)
    {
        try
        {
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken, state.Cts.Token);

            // Set a timeout for backend to connect
            linkedCts.CancelAfter(TimeSpan.FromSeconds(30));

            _logger.LogDebug("Waiting for backend connection on port {Port}", state.LocalEndpoint!.Port);

            // Accept backend connection
            var backendSocket = await state.BackendListener!.AcceptTcpClientAsync(linkedCts.Token);

            _logger.LogDebug("Backend connected from {BackendEndpoint}", backendSocket.Client.RemoteEndPoint);

            // Connect to client
            var clientSocket = new TcpClient();
            await clientSocket.ConnectAsync(
                state.ClientDataEndpoint!.Address,
                state.ClientDataEndpoint.Port,
                linkedCts.Token);

            _logger.LogDebug("Connected to client data channel at {ClientEndpoint}", state.ClientDataEndpoint);

            // Stop listening for more connections
            state.BackendListener.Stop();

            // Relay data
            await RelayBidirectionalAsync(clientSocket, backendSocket, state, linkedCts.Token);
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Active data channel cancelled for session {SessionId}", state.SessionId);
            state.TransferCompletion.TrySetCanceled();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in active data channel for session {SessionId}", state.SessionId);
            state.TransferCompletion.TrySetException(ex);
        }
    }

    private async Task RelayBidirectionalAsync(
        TcpClient clientSocket,
        TcpClient backendSocket,
        DataChannelState state,
        CancellationToken cancellationToken)
    {
        long bytesUploaded = 0;
        long bytesDownloaded = 0;

        try
        {
            Stream clientStream = clientSocket.GetStream();
            Stream backendStream = backendSocket.GetStream();

            // Upgrade to TLS if needed
            if (state.UseTls && _certificate is not null)
            {
                var clientSslStream = new SslStream(clientStream, false);
                await clientSslStream.AuthenticateAsServerAsync(
                    _certificate,
                    clientCertificateRequired: false,
                    checkCertificateRevocation: false);
                clientStream = clientSslStream;

                var backendSslStream = new SslStream(backendStream, false, ValidateServerCertificate);
                await backendSslStream.AuthenticateAsClientAsync(
                    state.BackendDataEndpoint?.Address.ToString() ?? "localhost");
                backendStream = backendSslStream;
            }

            // Create relay tasks
            var uploadTask = RelayStreamAsync(
                clientStream, backendStream,
                b => Interlocked.Add(ref bytesUploaded, b),
                cancellationToken);

            var downloadTask = RelayStreamAsync(
                backendStream, clientStream,
                b => Interlocked.Add(ref bytesDownloaded, b),
                cancellationToken);

            // Wait for both directions to complete
            // In FTP, the server closes the connection when transfer is done
            await Task.WhenAny(uploadTask, downloadTask);

            // Give a short grace period for the other direction
            using var graceCts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            try
            {
                await Task.WhenAll(uploadTask, downloadTask).WaitAsync(graceCts.Token);
            }
            catch (OperationCanceledException)
            {
                // Expected - one direction finished
            }

            state.TransferCompletion.TrySetResult((bytesUploaded, bytesDownloaded));
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Data relay ended for session {SessionId}", state.SessionId);
            state.TransferCompletion.TrySetResult((bytesUploaded, bytesDownloaded));
        }
        finally
        {
            clientSocket.Dispose();
            backendSocket.Dispose();
        }
    }

    private static async Task RelayStreamAsync(
        Stream source,
        Stream destination,
        Action<long> bytesCallback,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[81920]; // 80KB buffer

        try
        {
            int bytesRead;
            while ((bytesRead = await source.ReadAsync(buffer, cancellationToken)) > 0)
            {
                await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
                await destination.FlushAsync(cancellationToken);
                bytesCallback(bytesRead);
            }
        }
        catch (IOException)
        {
            // Connection closed - expected at end of transfer
        }
        catch (OperationCanceledException)
        {
            // Cancelled - expected
        }
    }

    private static bool ValidateServerCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        // TODO: Make configurable
        return true;
    }
}
