using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using FtpReverseProxy.Core.Enums;
using FtpReverseProxy.Core.Interfaces;
using FtpReverseProxy.Ftp.Tls;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp.DataChannel;

/// <summary>
/// Manages FTP data channel connections for proxying between clients and backends.
/// Uses native OpenSSL for backend connections to support TLS session resumption.
/// Uses shared OpenSSL context for client connections to enable client-side session resumption.
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
    private readonly OpenSslServerContext? _sharedSslContext;

    private int _nextPort;
    private readonly object _portLock = new();

    // Limit concurrent TLS handshakes to prevent resource exhaustion
    // A reasonable limit allows good concurrency without overwhelming the system
    private readonly SemaphoreSlim _tlsHandshakeSemaphore = new(10, 10);

    public DataChannelManager(
        ILogger<DataChannelManager> logger,
        IBackendCertificateValidator certificateValidator,
        int minPort = 50000,
        int maxPort = 51000,
        string? externalAddress = null,
        X509Certificate2? certificate = null,
        OpenSslServerContext? sharedSslContext = null)
    {
        _logger = logger;
        _minPort = minPort;
        _maxPort = maxPort;
        _nextPort = minPort;
        _externalAddress = externalAddress;
        _certificate = certificate;
        _sharedSslContext = sharedSslContext;
    }

    /// <summary>
    /// Cleans up any resources associated with a session when the control connection closes.
    /// </summary>
    public void CleanupSession(Guid sessionId)
    {
        // Cancel any pending data channel for this session
        CancelDataChannel(sessionId);
    }

    public async Task<IPEndPoint> SetupPassiveRelayAsync(
        Guid sessionId,
        IPEndPoint backendEndpoint,
        bool useClientTls,
        bool useBackendTls,
        string? backendHostname = null,
        bool skipBackendCertValidation = false,
        object? tlsSessionToResume = null,
        CancellationToken cancellationToken = default)
    {
        // If there's an existing data channel for this session, wait for it to complete
        // before setting up a new one. This prevents cancelling active transfers mid-flight
        // when the client pipelines PASV commands.
        await WaitForExistingDataChannelAsync(sessionId, cancellationToken);

        // Note: We don't call AddRef on the TLS session because FTP data channels
        // for a single control connection are sequential (not concurrent).
        // The FtpSessionHandler owns the OpenSslSession and manages its lifecycle.
        var session = tlsSessionToResume as OpenSslSession;
        if (session is not null)
        {
            _logger.LogDebug("Session {FtpSessionId}: Using TLS session {TlsSessionId}, valid={Valid}",
                sessionId, session.SessionId, session.IsValid);
        }

        var state = new DataChannelState
        {
            SessionId = sessionId,
            Mode = DataChannelMode.Passive,
            UseClientTls = useClientTls,
            UseBackendTls = useBackendTls,
            BackendHostname = backendHostname,
            SkipBackendCertValidation = skipBackendCertValidation,
            TlsSessionToResume = session,
            BackendDataEndpoint = backendEndpoint
        };

        // Find an available port and start listening
        var listener = CreateListener();
        state.ClientListener = listener;
        state.LocalEndpoint = (IPEndPoint)listener.LocalEndpoint;

        _channels[sessionId] = state;

        _logger.LogInformation(
            "Passive data channel setup for session {SessionId}: listening on port {LocalPort}, backend data endpoint at {BackendEndpoint}",
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
        bool useClientTls,
        bool useBackendTls,
        string? backendHostname = null,
        bool skipBackendCertValidation = false,
        object? tlsSessionToResume = null,
        CancellationToken cancellationToken = default)
    {
        // If there's an existing data channel for this session, wait for it to complete
        // before setting up a new one. This prevents cancelling active transfers mid-flight
        // when the client pipelines PORT commands.
        await WaitForExistingDataChannelAsync(sessionId, cancellationToken);

        // Note: We don't call AddRef on the TLS session because FTP data channels
        // for a single control connection are sequential (not concurrent).
        // The FtpSessionHandler owns the OpenSslSession and manages its lifecycle.
        var session = tlsSessionToResume as OpenSslSession;

        var state = new DataChannelState
        {
            SessionId = sessionId,
            Mode = DataChannelMode.Active,
            UseClientTls = useClientTls,
            UseBackendTls = useBackendTls,
            BackendHostname = backendHostname,
            SkipBackendCertValidation = skipBackendCertValidation,
            TlsSessionToResume = session,
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

        // Return the external endpoint for the backend to connect to
        // This resolves 0.0.0.0/:: to an actual reachable IP address
        var externalEndpoint = GetExternalEndpoint(state.LocalEndpoint);
        return externalEndpoint;
    }

    public async Task<(long BytesUploaded, long BytesDownloaded)> RelayDataAsync(
        Guid sessionId,
        bool isUpload,
        CancellationToken cancellationToken = default)
    {
        if (!_channels.TryGetValue(sessionId, out var state))
        {
            throw new InvalidOperationException($"No data channel found for session {sessionId}");
        }

        state.IsUsed = true;
        state.IsUpload = isUpload;

        // CRITICAL: Signal that the transfer direction is now known.
        // The relay task is waiting for this before it starts copying data.
        // Without this signal, the relay would start before we know if it's upload/download,
        // causing it to relay in the wrong direction!
        state.DirectionDetermined.TrySetResult();

        _logger.LogDebug("Session {SessionId}: Direction determined - isUpload={IsUpload}, signaled relay to start",
            sessionId, isUpload);

        try
        {
            // Wait for the transfer to complete (or timeout/cancellation)
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken, state.Cts.Token);

            var result = await state.TransferCompletion.Task.WaitAsync(linkedCts.Token);

            _logger.LogDebug(
                "Data transfer completed for session {SessionId}: {BytesUploaded} uploaded, {BytesDownloaded} downloaded",
                sessionId, result.BytesUploaded, result.BytesDownloaded);

            // CRITICAL: Wait for data channel cleanup to complete before returning
            // This prevents race conditions where cleanup happens in parallel with
            // the control channel reading the 226 response from the backend.
            // FileZilla Server (and possibly others) can get confused if we read from
            // the control channel while data channel TLS is still being torn down.
            try
            {
                await state.CleanupCompletion.Task.WaitAsync(TimeSpan.FromSeconds(5), linkedCts.Token);
                _logger.LogDebug("Session {SessionId}: Data channel cleanup confirmed complete", sessionId);
            }
            catch (TimeoutException)
            {
                _logger.LogWarning("Session {SessionId}: Timed out waiting for data channel cleanup", sessionId);
            }

            return result;
        }
        finally
        {
            // Clean up after transfer
            _channels.TryRemove(sessionId, out _);
            state.Dispose();
        }
    }

    /// <summary>
    /// Waits for an existing data channel to complete if one is in use.
    /// This prevents cancelling active transfers mid-flight when clients pipeline commands.
    /// </summary>
    private async Task WaitForExistingDataChannelAsync(Guid sessionId, CancellationToken cancellationToken)
    {
        if (!_channels.TryGetValue(sessionId, out var existingState))
        {
            // No existing data channel - nothing to wait for
            return;
        }

        if (!existingState.IsUsed)
        {
            // Data channel exists but hasn't been used for a transfer yet.
            // This can happen if the client issued PASV but never sent a transfer command.
            // Just cancel it and proceed.
            _logger.LogDebug("Session {SessionId}: Cancelling unused data channel before setting up new one", sessionId);
            CancelDataChannel(sessionId);
            return;
        }

        // An active transfer is in progress - wait for it to complete
        _logger.LogInformation(
            "Session {SessionId}: Waiting for existing data transfer to complete before setting up new data channel",
            sessionId);

        try
        {
            // Wait for the transfer to complete (TransferCompletion is set when relay finishes)
            // Use a reasonable timeout to avoid hanging forever
            await existingState.TransferCompletion.Task.WaitAsync(TimeSpan.FromMinutes(5), cancellationToken);

            // Also wait for cleanup to complete to avoid resource conflicts
            await existingState.CleanupCompletion.Task.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);

            _logger.LogDebug("Session {SessionId}: Previous data transfer completed, proceeding with new data channel", sessionId);
        }
        catch (TimeoutException)
        {
            _logger.LogWarning(
                "Session {SessionId}: Timed out waiting for previous data transfer to complete, forcing cancellation",
                sessionId);
            CancelDataChannel(sessionId);
        }
        catch (OperationCanceledException)
        {
            // Cancellation requested - just cancel the existing channel and let the exception propagate
            CancelDataChannel(sessionId);
            throw;
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
                    // Try IPv6 dual-stack first, fall back to IPv4 if not supported
                    TcpListener listener;
                    try
                    {
                        listener = new TcpListener(IPAddress.IPv6Any, port);
                        listener.Server.DualMode = true;
                    }
                    catch (SocketException)
                    {
                        // Dual-stack not supported, use IPv4 only
                        listener = new TcpListener(IPAddress.Any, port);
                    }

                    listener.Start();
                    _logger.LogInformation("Data channel listener started on port {Port}", port);
                    return listener;
                }
                catch (SocketException ex)
                {
                    _logger.LogWarning("Port {Port} unavailable: {Message}", port, ex.Message);
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
        // In production, this should be configured explicitly via ExternalAddress
        var host = Dns.GetHostEntry(Dns.GetHostName());
        var ipv4 = host.AddressList.FirstOrDefault(ip =>
            ip.AddressFamily == AddressFamily.InterNetwork &&
            !IPAddress.IsLoopback(ip));

        var detectedIp = ipv4 ?? IPAddress.Loopback;

        // Warn if the detected IP looks like a private/container network IP
        // This often happens in Docker and causes PORT/EPRT commands to fail
        var bytes = detectedIp.GetAddressBytes();
        bool isPrivate = bytes[0] == 10 ||
                        (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
                        (bytes[0] == 192 && bytes[1] == 168);

        if (isPrivate || IPAddress.IsLoopback(detectedIp))
        {
            _logger.LogWarning("No ExternalAddress configured. Using auto-detected IP {DetectedIp} which is a private/loopback address. " +
                "Active mode (PORT/EPRT) may fail if the backend cannot reach this IP. " +
                "Configure Proxy:DataChannel:ExternalAddress for production deployments.",
                detectedIp);
        }
        else
        {
            _logger.LogDebug("No ExternalAddress configured. Using auto-detected IP {DetectedIp}", detectedIp);
        }

        return new IPEndPoint(detectedIp, localEndpoint.Port);
    }

    private async Task AcceptPassiveConnectionAsync(DataChannelState state, CancellationToken cancellationToken)
    {
        TcpClient? clientSocket = null;
        TcpClient? backendSocket = null;

        try
        {
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken, state.Cts.Token);

            // Set a timeout for client to connect
            linkedCts.CancelAfter(TimeSpan.FromSeconds(30));

            _logger.LogInformation("Waiting for client data connection on port {Port}", state.LocalEndpoint!.Port);

            // Accept client connection
            clientSocket = await state.ClientListener!.AcceptTcpClientAsync(linkedCts.Token);

            // Configure client socket for low-latency TLS
            clientSocket.NoDelay = true; // Disable Nagle's algorithm
            clientSocket.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            clientSocket.SendTimeout = 30000; // 30 second send timeout
            clientSocket.ReceiveTimeout = 30000; // 30 second receive timeout

            _logger.LogInformation("Client data channel connected from {ClientEndpoint}", clientSocket.Client.RemoteEndPoint);

            // Connect to backend
            backendSocket = new TcpClient();
            backendSocket.NoDelay = true; // Disable Nagle's algorithm
            await backendSocket.ConnectAsync(
                state.BackendDataEndpoint!.Address,
                state.BackendDataEndpoint.Port,
                linkedCts.Token);

            // Configure backend socket for low-latency TLS
            backendSocket.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
            backendSocket.SendTimeout = 30000;
            backendSocket.ReceiveTimeout = 30000;

            _logger.LogDebug("Connected to backend data channel at {BackendEndpoint}", state.BackendDataEndpoint);

            // Stop listening for more connections
            state.ClientListener.Stop();

            // Relay data - sockets are now owned by RelayBidirectionalAsync which will dispose them
            await RelayBidirectionalAsync(clientSocket, backendSocket, state, linkedCts.Token);

            // RelayBidirectionalAsync disposes sockets, so clear our references
            clientSocket = null;
            backendSocket = null;
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Passive data channel cancelled for session {SessionId}", state.SessionId);
            state.TransferCompletion.TrySetCanceled();
            state.CleanupCompletion.TrySetResult();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in passive data channel for session {SessionId}", state.SessionId);
            state.TransferCompletion.TrySetException(ex);
            state.CleanupCompletion.TrySetResult();
        }
        finally
        {
            // Dispose any sockets that weren't transferred to RelayBidirectionalAsync
            // This handles cases where connection setup failed partway through
            try { clientSocket?.Dispose(); } catch { }
            try { backendSocket?.Dispose(); } catch { }
        }
    }

    private async Task AcceptActiveConnectionAsync(DataChannelState state, CancellationToken cancellationToken)
    {
        TcpClient? backendSocket = null;
        TcpClient? clientSocket = null;

        try
        {
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(
                cancellationToken, state.Cts.Token);

            // Set a timeout for backend to connect
            linkedCts.CancelAfter(TimeSpan.FromSeconds(30));

            _logger.LogDebug("Waiting for backend connection on port {Port}", state.LocalEndpoint!.Port);

            // Accept backend connection
            backendSocket = await state.BackendListener!.AcceptTcpClientAsync(linkedCts.Token);

            _logger.LogDebug("Backend connected from {BackendEndpoint}", backendSocket.Client.RemoteEndPoint);

            // Connect to client
            clientSocket = new TcpClient();
            await clientSocket.ConnectAsync(
                state.ClientDataEndpoint!.Address,
                state.ClientDataEndpoint.Port,
                linkedCts.Token);

            _logger.LogDebug("Connected to client data channel at {ClientEndpoint}", state.ClientDataEndpoint);

            // Stop listening for more connections
            state.BackendListener.Stop();

            // Relay data - sockets are now owned by RelayBidirectionalAsync which will dispose them
            await RelayBidirectionalAsync(clientSocket, backendSocket, state, linkedCts.Token);

            // RelayBidirectionalAsync disposes sockets, so clear our references
            clientSocket = null;
            backendSocket = null;
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("Active data channel cancelled for session {SessionId}", state.SessionId);
            state.TransferCompletion.TrySetCanceled();
            state.CleanupCompletion.TrySetResult();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error in active data channel for session {SessionId}", state.SessionId);
            state.TransferCompletion.TrySetException(ex);
            state.CleanupCompletion.TrySetResult();
        }
        finally
        {
            // Dispose any sockets that weren't transferred to RelayBidirectionalAsync
            // This handles cases where connection setup failed partway through
            try { clientSocket?.Dispose(); } catch { }
            try { backendSocket?.Dispose(); } catch { }
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

        OpenSslServerStream? clientSslStream = null;
        OpenSslTlsStream? backendSslStream = null;

        try
        {
            Stream clientStream = clientSocket.GetStream();
            Stream backendStream = backendSocket.GetStream();

            // Upgrade client side to TLS if needed
            // Use shared OpenSSL context for session resumption support
            // Use semaphore to limit concurrent TLS handshakes
            // IMPORTANT: Set shorter socket timeouts for TLS handshake to prevent indefinite blocking
            if (state.UseClientTls)
            {
                await _tlsHandshakeSemaphore.WaitAsync(cancellationToken);
                try
                {
                    // Set shorter timeouts during TLS handshake - OpenSSL uses blocking I/O
                    // so socket timeouts are the only way to abort a hung handshake
                    clientSocket.SendTimeout = 10000;    // 10 seconds for handshake
                    clientSocket.ReceiveTimeout = 10000; // 10 seconds for handshake

                    if (_sharedSslContext is not null)
                    {
                        _logger.LogInformation("Upgrading client data channel to TLS using shared OpenSSL context (session resumption enabled)");
                        var handshakeTask = Task.Run(() => OpenSslServerStream.Accept(
                            clientSocket,
                            _sharedSslContext,
                            _logger), cancellationToken);

                        // Use WaitAsync with timeout to abort hung handshakes
                        // If timeout fires, close socket to abort blocking SSL_accept
                        clientSslStream = await handshakeTask.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);
                    }
                    else if (_certificate is not null)
                    {
                        _logger.LogInformation("Upgrading client data channel to TLS using standalone OpenSSL context");
                        var handshakeTask = Task.Run(() => OpenSslServerStream.Accept(
                            clientSocket,
                            _certificate,
                            _logger), cancellationToken);

                        clientSslStream = await handshakeTask.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);
                    }
                    else
                    {
                        throw new InvalidOperationException("Client TLS requested but no certificate or SSL context available");
                    }

                    // Restore normal timeouts after handshake
                    clientSocket.SendTimeout = 30000;
                    clientSocket.ReceiveTimeout = 30000;
                }
                catch (TimeoutException tex)
                {
                    _logger.LogError("Session {SessionId}: Client TLS handshake timed out after 15 seconds", state.SessionId);
                    // Close socket to abort the blocking handshake
                    try { clientSocket.Close(); } catch { }
                    throw new IOException("Client TLS handshake timed out", tex);
                }
                finally
                {
                    _tlsHandshakeSemaphore.Release();
                }

                clientStream = clientSslStream;
                _logger.LogInformation("Client data channel TLS established. Protocol: {Protocol}, Cipher: {Cipher}",
                    clientSslStream.ProtocolVersion, clientSslStream.CipherSuite);
            }

            // Upgrade backend side to TLS if needed
            // Use native OpenSSL for explicit session resumption support
            // Use semaphore to limit concurrent TLS handshakes
            // IMPORTANT: Set shorter socket timeouts for TLS handshake to prevent indefinite blocking
            if (state.UseBackendTls)
            {
                await _tlsHandshakeSemaphore.WaitAsync(cancellationToken);
                IntPtr sessionPtr = IntPtr.Zero;
                try
                {
                    // Set shorter timeouts during TLS handshake - OpenSSL uses blocking I/O
                    // so socket timeouts are the only way to abort a hung handshake
                    backendSocket.SendTimeout = 10000;    // 10 seconds for handshake
                    backendSocket.ReceiveTimeout = 10000; // 10 seconds for handshake

                    var tlsTargetHost = state.BackendHostname ?? state.BackendDataEndpoint?.Address.ToString() ?? "localhost";
                    var sessionValid = state.TlsSessionToResume?.IsValid ?? false;

                    // CRITICAL: Create a NEW session object from serialized data for each data channel.
                    // This mirrors how libfilezilla/GnuTLS handles session resumption:
                    // - Each data channel gets its own INDEPENDENT session object
                    // - No shared state between connections
                    // - Prevents issues where freeing one SSL connection affects another's session
                    if (sessionValid)
                    {
                        sessionPtr = state.TlsSessionToResume!.CreateSessionForResumption();
                    }

                    _logger.LogInformation("Session {FtpSessionId}: Upgrading backend data channel to TLS (targetHost={TargetHost}, hasSession={HasSession}, sessionValid={SessionValid}, sessionId={SessionId})",
                        state.SessionId, tlsTargetHost,
                        sessionPtr != IntPtr.Zero, sessionValid, state.TlsSessionToResume?.SessionId ?? "(none)");

                    // Use native OpenSSL TLS with session resumption from control channel
                    var handshakeTask = Task.Run(() => OpenSslTlsStream.Connect(
                        backendSocket,
                        tlsTargetHost,
                        skipCertificateValidation: state.SkipBackendCertValidation,
                        sessionToResume: sessionPtr,
                        logger: _logger), cancellationToken);

                    // Use WaitAsync with timeout to abort hung handshakes
                    backendSslStream = await handshakeTask.WaitAsync(TimeSpan.FromSeconds(15), cancellationToken);

                    // Restore normal timeouts after handshake
                    backendSocket.SendTimeout = 30000;
                    backendSocket.ReceiveTimeout = 30000;

                    _logger.LogInformation("Data channel TLS established using OpenSSL. SessionResumed: {Resumed}, Protocol: {Protocol}, Cipher: {Cipher}",
                        backendSslStream.IsSessionResumed, backendSslStream.ProtocolVersion, backendSslStream.CipherSuite);

                    if (sessionPtr != IntPtr.Zero && !backendSslStream.IsSessionResumed)
                    {
                        _logger.LogWarning("TLS session resumption was requested but NOT achieved on data channel. Backend may reject the connection.");
                    }

                    // Log success - no session rotation needed since we use serialized session data
                    if (state.TlsSessionToResume is not null && backendSslStream.IsSessionResumed)
                    {
                        _logger.LogInformation("Session {FtpSessionId}: Data channel TLS resumed successfully using serialized session (ID={SessionId})",
                            state.SessionId, state.TlsSessionToResume.SessionId);
                    }

                    backendStream = backendSslStream;
                }
                catch (TimeoutException tex)
                {
                    _logger.LogError("Session {SessionId}: Backend TLS handshake timed out after 15 seconds", state.SessionId);
                    // Close socket to abort the blocking handshake
                    try { backendSocket.Close(); } catch { }
                    throw new IOException("Backend TLS handshake timed out", tex);
                }
                catch (Exception tlsEx)
                {
                    _logger.LogError(tlsEx, "Failed to establish TLS on backend data channel for session {SessionId}. This may indicate TLS session resumption is not working.", state.SessionId);
                    throw;
                }
                finally
                {
                    // Free the session pointer we created from serialized data
                    // SSL_set_session increments the ref count, so we need to free our copy
                    if (sessionPtr != IntPtr.Zero)
                    {
                        OpenSslInterop.SSL_SESSION_free(sessionPtr);
                    }
                    _tlsHandshakeSemaphore.Release();
                }
            }

            // FTP data channels are fundamentally UNIDIRECTIONAL:
            // - Uploads (STOR/STOU/APPE): client sends data to backend
            // - Downloads (RETR/LIST/MLSD/NLST): backend sends data to client
            //
            // CRITICAL: We must wait until we know the transfer direction!
            // The data channel is established BEFORE the transfer command (STOR/RETR/LIST) is received.
            // If we start relaying before we know the direction, we'll relay in the wrong direction
            // and the transfer will fail with 0 bytes transferred.
            //
            // The direction is determined when RelayDataAsync is called, which signals DirectionDetermined.
            _logger.LogDebug("Session {SessionId}: Data channel ready, waiting for transfer command to determine direction...",
                state.SessionId);

            try
            {
                // Wait up to 30 seconds for the transfer command to arrive
                await state.DirectionDetermined.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);
            }
            catch (TimeoutException)
            {
                _logger.LogWarning("Session {SessionId}: Timed out waiting for transfer direction (no STOR/RETR/LIST command received)",
                    state.SessionId);
                throw new IOException("Timed out waiting for transfer command");
            }

            var isUpload = state.IsUpload;

            _logger.LogInformation("Session {SessionId}: Transfer direction determined - {Direction}",
                state.SessionId, isUpload ? "UPLOAD (client->backend)" : "DOWNLOAD (backend->client)");

            _logger.LogDebug("Starting {Direction} relay for session {SessionId}",
                isUpload ? "Upload (client->backend)" : "Download (backend->client)", state.SessionId);

            Task relayTask;
            bool relayFailed = false;

            if (isUpload)
            {
                // Upload: only run client -> backend relay
                relayTask = RelayStreamAsync(
                    clientStream, backendStream,
                    b => Interlocked.Add(ref bytesUploaded, b),
                    "upload (client->backend)",
                    cancellationToken);
            }
            else
            {
                // Download: only run backend -> client relay
                relayTask = RelayStreamAsync(
                    backendStream, clientStream,
                    b => Interlocked.Add(ref bytesDownloaded, b),
                    "download (backend->client)",
                    cancellationToken);
            }

            try
            {
                await relayTask;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Session {SessionId}: Relay task failed with exception", state.SessionId);
                relayFailed = true;
            }

            _logger.LogDebug("{Direction} relay completed for session {SessionId}: {Bytes} bytes, failed={Failed}",
                isUpload ? "Upload" : "Download", state.SessionId,
                isUpload ? bytesUploaded : bytesDownloaded, relayFailed);

            // CRITICAL: Check if upload actually transferred data before signaling completion to backend.
            // If upload failed (0 bytes or error), we must NOT signal completion - this would cause
            // the backend to save a 0 byte file, corrupting the destination.
            if (isUpload && (bytesUploaded == 0 || relayFailed))
            {
                _logger.LogWarning("Session {SessionId}: Upload failed or transferred 0 bytes ({Bytes} bytes, failed={Failed}). " +
                    "NOT signaling completion to backend to prevent 0 byte file creation.",
                    state.SessionId, bytesUploaded, relayFailed);

                // Just close sockets abruptly - do NOT send shutdown which signals "upload complete"
                // The backend will see the connection close and should discard any partial data
                try { backendSocket.Client.Close(); } catch { }
                try { clientSocket.Client.Close(); } catch { }

                // Signal failure in the transfer result
                state.TransferCompletion.TrySetResult((bytesUploaded, bytesDownloaded));

                // Throw to indicate failure - this will be caught by the session handler
                throw new IOException($"Upload failed: transferred only {bytesUploaded} bytes");
            }

            // FTP data channels are unidirectional. For graceful shutdown we need:
            // 1. TLS close_notify to CLIENT - required by GnuTLS/OpenSSL clients
            // 2. Socket shutdown to BACKEND - some FTP servers (FileZilla) get confused by TLS close_notify
            //    and close the control channel
            //
            // The order matters: first signal completion to the side that sent data,
            // then close the receiving side.

            if (isUpload)
            {
                // Upload completed successfully - client finished sending data to backend
                _logger.LogDebug("Upload complete for session {SessionId} ({Bytes} bytes), signaling completion",
                    state.SessionId, bytesUploaded);

                // Half-close backend socket (send direction) to signal EOF to backend FTP server
                // This tells FileZilla Server "data upload is complete"
                try { backendSocket.Client.Shutdown(System.Net.Sockets.SocketShutdown.Send); } catch { }

                // Wait briefly for backend to process the data
                await Task.Delay(100);

                // Send TLS close_notify to client (required by GnuTLS)
                if (clientSslStream is not null)
                {
                    try
                    {
                        _logger.LogDebug("Sending TLS close_notify to client for session {SessionId}", state.SessionId);
                        clientSslStream.TlsShutdown();
                        _logger.LogDebug("TLS close_notify sent to client for session {SessionId}", state.SessionId);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Error sending TLS close_notify to client for session {SessionId}", state.SessionId);
                    }
                }

                // Delay to ensure close_notify is fully transmitted before closing socket
                await Task.Delay(100);

                // Close sockets
                try { clientSocket.Client.Shutdown(System.Net.Sockets.SocketShutdown.Both); } catch { }
                try { backendSocket.Client.Shutdown(System.Net.Sockets.SocketShutdown.Both); } catch { }
            }
            else
            {
                // Download completed - backend finished sending data to client
                // Note: 0 bytes downloaded can be valid (empty directory listing), so we don't fail on that
                _logger.LogDebug("Download complete for session {SessionId} ({Bytes} bytes), signaling completion",
                    state.SessionId, bytesDownloaded);

                // Send TLS close_notify to client FIRST (required by GnuTLS)
                // The client is waiting for either more data or a proper close
                if (clientSslStream is not null)
                {
                    try
                    {
                        _logger.LogDebug("Sending TLS close_notify to client for session {SessionId}", state.SessionId);
                        clientSslStream.TlsShutdown();
                        _logger.LogDebug("TLS close_notify sent to client for session {SessionId}", state.SessionId);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Error sending TLS close_notify to client for session {SessionId}", state.SessionId);
                    }
                }

                // Delay to ensure close_notify is fully transmitted before closing socket
                await Task.Delay(100);

                // Close sockets - don't send TLS close_notify to backend (causes control channel issues)
                try { clientSocket.Client.Shutdown(System.Net.Sockets.SocketShutdown.Both); } catch { }
                try { backendSocket.Client.Shutdown(System.Net.Sockets.SocketShutdown.Both); } catch { }
            }

            // Relay completed successfully
            state.TransferCompletion.TrySetResult((bytesUploaded, bytesDownloaded));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Data relay ended with error for session {SessionId}", state.SessionId);
            state.TransferCompletion.TrySetResult((bytesUploaded, bytesDownloaded));
        }
        finally
        {
            _logger.LogInformation("Session {SessionId}: Starting data channel cleanup (sockets and TLS)", state.SessionId);

            // Dispose SSL streams - relay tasks should have exited by now
            // IMPORTANT: Do NOT send TLS close_notify to the backend data channel!
            // FileZilla Server (and possibly other FTP servers) can get confused by TLS close_notify
            // on the data channel and will close the CONTROL channel in response.
            // This causes "Connection closed by server" errors on subsequent commands.
            // Just dispose the stream and let TCP handle the close.
            try
            {
                if (backendSslStream is not null)
                {
                    // Skip TLS shutdown - just close the socket
                    backendSslStream.SkipTlsShutdownOnDispose();
                    backendSslStream.Dispose();
                    _logger.LogDebug("Session {SessionId}: Backend data TLS disposed (no close_notify sent)", state.SessionId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error during backend TLS cleanup for session {SessionId} (socket may already be closed)", state.SessionId);
            }

            try
            {
                if (clientSslStream is not null)
                {
                    clientSslStream.Dispose();
                    _logger.LogDebug("Client TLS cleanup completed for session {SessionId}", state.SessionId);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error during client TLS cleanup for session {SessionId} (socket may already be closed)", state.SessionId);
            }

            try
            {
                backendSocket.Dispose();
            }
            catch { /* Ignore socket dispose errors */ }

            try
            {
                clientSocket.Dispose();
            }
            catch { /* Ignore socket dispose errors */ }

            _logger.LogInformation("Session {SessionId}: Data channel cleanup completed", state.SessionId);

            // Signal that cleanup is complete - callers can now safely continue
            state.CleanupCompletion.TrySetResult();
        }
    }

    private async Task RelayStreamAsync(
        Stream source,
        Stream destination,
        Action<long> bytesCallback,
        string direction,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[81920]; // 80KB buffer
        var startTime = DateTime.UtcNow;

        _logger.LogInformation("[{Timestamp:HH:mm:ss.fff}] RelayStreamAsync starting for {Direction}", startTime, direction);

        try
        {
            int bytesRead;
            int readCount = 0;
            long totalBytes = 0;
            while (true)
            {
                var readStartTime = DateTime.UtcNow;
                _logger.LogInformation("[{Timestamp:HH:mm:ss.fff}] RelayStreamAsync {Direction}: Calling Read (attempt {Count})",
                    readStartTime, direction, ++readCount);

                // Use Task.Run to prevent blocking the async context
                bytesRead = await Task.Run(() => source.Read(buffer, 0, buffer.Length), cancellationToken);

                var readEndTime = DateTime.UtcNow;
                var readDuration = (readEndTime - readStartTime).TotalMilliseconds;
                _logger.LogInformation("[{Timestamp:HH:mm:ss.fff}] RelayStreamAsync {Direction}: Read returned {Bytes} bytes (took {Duration}ms)",
                    readEndTime, direction, bytesRead, readDuration);

                if (bytesRead <= 0)
                    break;

                var writeStartTime = DateTime.UtcNow;
                await destination.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken);
                await destination.FlushAsync(cancellationToken);
                var writeEndTime = DateTime.UtcNow;
                var writeDuration = (writeEndTime - writeStartTime).TotalMilliseconds;

                totalBytes += bytesRead;
                bytesCallback(bytesRead);

                _logger.LogInformation("[{Timestamp:HH:mm:ss.fff}] RelayStreamAsync {Direction}: Wrote {Bytes} bytes (took {Duration}ms), total={Total}",
                    writeEndTime, direction, bytesRead, writeDuration, totalBytes);
            }

            var endTime = DateTime.UtcNow;
            _logger.LogInformation("[{Timestamp:HH:mm:ss.fff}] RelayStreamAsync {Direction}: Completed normally, total={Total} bytes",
                endTime, direction, totalBytes);
        }
        catch (IOException ex)
        {
            _logger.LogDebug("RelayStreamAsync {Direction}: IOException - {Message}", direction, ex.Message);
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("RelayStreamAsync {Direction}: Cancelled", direction);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "RelayStreamAsync {Direction}: Unexpected error", direction);
        }
    }
}
