using System.Net.Sockets;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp.Tls;

/// <summary>
/// OpenSSL-based TLS stream with explicit session resumption support.
/// This is used for FTPS data channels where the TLS session must resume
/// the control channel session.
/// Thread-safe: uses locking to prevent use-after-free races.
/// </summary>
public class OpenSslTlsStream : Stream
{
    private readonly Socket _socket;
    private readonly IntPtr _sslCtx;
    private IntPtr _ssl;  // Mutable: set to Zero after SSL_free
    private readonly ILogger? _logger;
    private bool _disposed;
    private bool _skipTlsShutdownOnDispose;

    // Lock object to synchronize SSL operations and prevent use-after-free
    private readonly object _sslLock = new();

    // Store the session for resumption on other connections
    private IntPtr _session;

    private OpenSslTlsStream(Socket socket, IntPtr sslCtx, IntPtr ssl, ILogger? logger)
    {
        _socket = socket;
        _sslCtx = sslCtx;
        _ssl = ssl;
        _logger = logger;
        _session = IntPtr.Zero;
    }

    /// <summary>
    /// Gets the SSL session for use in resumption on subsequent connections.
    /// This should be called after a successful handshake on the control channel.
    /// </summary>
    public IntPtr GetSession()
    {
        if (_ssl == IntPtr.Zero) return IntPtr.Zero;

        // Get a new reference to the session
        var session = OpenSslInterop.SSL_get1_session(_ssl);
        if (session != IntPtr.Zero)
        {
            var sessionId = OpenSslInterop.GetSessionIdHex(session);
            _logger?.LogInformation("OpenSSL: Got session for resumption. SessionID: {SessionId}", sessionId);
        }
        return session;
    }

    /// <summary>
    /// Returns true if this connection resumed a previous session.
    /// </summary>
    public bool IsSessionResumed
    {
        get
        {
            if (_ssl == IntPtr.Zero) return false;
            return OpenSslInterop.SSL_session_reused(_ssl) == 1;
        }
    }

    /// <summary>
    /// Gets the negotiated TLS protocol version.
    /// </summary>
    public string ProtocolVersion => OpenSslInterop.GetVersionString(_ssl);

    /// <summary>
    /// Gets the negotiated cipher suite name.
    /// </summary>
    public string CipherSuite => OpenSslInterop.GetCipherName(_ssl);

    /// <summary>
    /// Creates a new OpenSSL TLS connection, optionally resuming a previous session.
    /// </summary>
    public static OpenSslTlsStream Connect(
        TcpClient tcpClient,
        string hostname,
        bool skipCertificateValidation = false,
        IntPtr sessionToResume = default,
        ILogger? logger = null)
    {
        var socket = tcpClient.Client;

        // Initialize OpenSSL (safe to call multiple times)
        OpenSslInterop.OPENSSL_init_ssl(0, IntPtr.Zero);

        // Create SSL context
        var method = OpenSslInterop.TLS_client_method();
        if (method == IntPtr.Zero)
        {
            throw new InvalidOperationException($"Failed to get TLS client method: {OpenSslInterop.GetLastErrorString()}");
        }

        var ctx = OpenSslInterop.SSL_CTX_new(method);
        if (ctx == IntPtr.Zero)
        {
            throw new InvalidOperationException($"Failed to create SSL context: {OpenSslInterop.GetLastErrorString()}");
        }

        try
        {
            // Set options - disable old protocols
            OpenSslInterop.SSL_CTX_set_options(ctx,
                OpenSslInterop.SSL_OP_NO_SSLv2 |
                OpenSslInterop.SSL_OP_NO_SSLv3 |
                OpenSslInterop.SSL_OP_NO_COMPRESSION);

            // Set minimum TLS version to 1.2
            OpenSslInterop.SSL_CTX_set_min_proto_version(ctx, OpenSslInterop.TLS1_2_VERSION);

            // Set certificate verification mode
            if (skipCertificateValidation)
            {
                logger?.LogDebug("OpenSSL: Skipping certificate validation");
                OpenSslInterop.SSL_CTX_set_verify(ctx, OpenSslInterop.SSL_VERIFY_NONE, IntPtr.Zero);
            }
            else
            {
                OpenSslInterop.SSL_CTX_set_verify(ctx, OpenSslInterop.SSL_VERIFY_PEER, IntPtr.Zero);
            }

            // Create SSL connection
            var ssl = OpenSslInterop.SSL_new(ctx);
            if (ssl == IntPtr.Zero)
            {
                throw new InvalidOperationException($"Failed to create SSL object: {OpenSslInterop.GetLastErrorString()}");
            }

            try
            {
                // Ensure socket is in blocking mode for OpenSSL
                socket.Blocking = true;

                // Set the socket file descriptor
                var fd = (int)socket.Handle;
                if (OpenSslInterop.SSL_set_fd(ssl, fd) != 1)
                {
                    throw new InvalidOperationException($"Failed to set socket FD: {OpenSslInterop.GetLastErrorString()}");
                }

                // Set SNI hostname (only if it's not an IP address per RFC 6066)
                if (!System.Net.IPAddress.TryParse(hostname, out _))
                {
                    logger?.LogDebug("OpenSSL: Setting SNI hostname: {Hostname}", hostname);
                    OpenSslInterop.SSL_set_tlsext_host_name(ssl, hostname);
                }
                else
                {
                    logger?.LogDebug("OpenSSL: Hostname is IP address, not setting SNI");
                }

                // Set session for resumption if provided
                if (sessionToResume != IntPtr.Zero)
                {
                    var sessionId = OpenSslInterop.GetSessionIdHex(sessionToResume);
                    logger?.LogInformation("OpenSSL: Setting session for resumption. SessionID: {SessionId}", sessionId);

                    if (OpenSslInterop.SSL_set_session(ssl, sessionToResume) != 1)
                    {
                        logger?.LogWarning("OpenSSL: Failed to set session for resumption: {Error}",
                            OpenSslInterop.GetLastErrorString());
                    }
                }
                else
                {
                    logger?.LogDebug("OpenSSL: No session to resume (fresh connection)");
                }

                // Perform TLS handshake with retry for non-blocking I/O
                logger?.LogDebug("OpenSSL: Starting TLS handshake to {Hostname}", hostname);

                int result;
                int attempts = 0;
                const int maxAttempts = 100; // Prevent infinite loop

                while (true)
                {
                    result = OpenSslInterop.SSL_connect(ssl);

                    if (result == 1)
                    {
                        break; // Handshake successful
                    }

                    var sslError = OpenSslInterop.SSL_get_error(ssl, result);

                    if (sslError == OpenSslInterop.SSL_ERROR_WANT_READ ||
                        sslError == OpenSslInterop.SSL_ERROR_WANT_WRITE)
                    {
                        // Non-blocking I/O - need to wait and retry
                        attempts++;
                        if (attempts >= maxAttempts)
                        {
                            throw new InvalidOperationException(
                                $"TLS handshake timed out after {maxAttempts} attempts waiting for I/O");
                        }

                        // Wait briefly and retry
                        Thread.Sleep(10);
                        continue;
                    }

                    // Real error
                    var errorStr = OpenSslInterop.GetLastErrorString();
                    throw new InvalidOperationException(
                        $"TLS handshake failed. SSL_connect returned {result}, SSL_error={sslError}: {errorStr}");
                }

                // Check if session was resumed
                var resumed = OpenSslInterop.SSL_session_reused(ssl) == 1;
                var version = OpenSslInterop.GetVersionString(ssl);
                var cipher = OpenSslInterop.GetCipherName(ssl);

                logger?.LogInformation(
                    "OpenSSL: TLS handshake complete. Resumed: {Resumed}, Protocol: {Protocol}, Cipher: {Cipher}",
                    resumed, version, cipher);

                if (sessionToResume != IntPtr.Zero && !resumed)
                {
                    logger?.LogWarning("OpenSSL: Session resumption was requested but NOT achieved!");
                }

                return new OpenSslTlsStream(socket, ctx, ssl, logger);
            }
            catch
            {
                OpenSslInterop.SSL_free(ssl);
                throw;
            }
        }
        catch
        {
            OpenSslInterop.SSL_CTX_free(ctx);
            throw;
        }
    }

    /// <summary>
    /// Frees a session obtained from GetSession().
    /// </summary>
    public static void FreeSession(IntPtr session)
    {
        if (session != IntPtr.Zero)
        {
            OpenSslInterop.SSL_SESSION_free(session);
        }
    }

    /// <summary>
    /// Marks this stream to skip TLS shutdown when disposed.
    /// Use this for backend data channels where sending close_notify
    /// can cause FileZilla Server to close the control channel.
    /// </summary>
    public void SkipTlsShutdownOnDispose()
    {
        _skipTlsShutdownOnDispose = true;
    }

    /// <summary>
    /// Performs a TLS shutdown, sending close_notify to the peer.
    /// Call this before disposing to ensure proper TLS termination.
    /// Thread-safe: uses locking to prevent race with other SSL operations.
    /// </summary>
    public void TlsShutdown()
    {
        lock (_sslLock)
        {
            if (_disposed || _ssl == IntPtr.Zero) return;

            // Don't call SSL_shutdown if the handshake never completed
            if (OpenSslInterop.SSL_is_init_finished(_ssl) == 0)
            {
                _logger?.LogDebug("OpenSSL Client: Skipping TLS shutdown - handshake not finished");
                return;
            }

            _logger?.LogDebug("OpenSSL Client: Initiating TLS shutdown");

            // First call sends close_notify
            var result = OpenSslInterop.SSL_shutdown(_ssl);

            if (result == 0)
            {
                // Need to call again to complete bidirectional shutdown
                // Wait briefly for peer's close_notify
                int attempts = 0;
                const int maxAttempts = 50; // 500ms total

                while (attempts < maxAttempts)
                {
                    result = OpenSslInterop.SSL_shutdown(_ssl);
                    if (result != 0)
                    {
                        break;
                    }

                    var sslError = OpenSslInterop.SSL_get_error(_ssl, result);
                    if (sslError == OpenSslInterop.SSL_ERROR_WANT_READ ||
                        sslError == OpenSslInterop.SSL_ERROR_WANT_WRITE)
                    {
                        attempts++;
                        Thread.Sleep(10);
                        continue;
                    }

                    break;
                }
            }

            _logger?.LogDebug("OpenSSL Client: TLS shutdown completed with result {Result}", result);
        }
    }

    #region Stream Implementation

    public override bool CanRead => !_disposed;
    public override bool CanSeek => false;
    public override bool CanWrite => !_disposed;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
        // OpenSSL handles buffering internally
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(OpenSslTlsStream));

        // OpenSSL reads directly into buffer at offset 0, so we need a temp buffer if offset != 0
        byte[] readBuffer;
        if (offset == 0)
        {
            readBuffer = buffer;
        }
        else
        {
            readBuffer = new byte[count];
        }

        // Retry loop for non-blocking I/O
        int attempts = 0;
        const int maxAttempts = 500; // ~5 seconds with 10ms sleep

        while (true)
        {
            int result;
            int sslError = OpenSslInterop.SSL_ERROR_NONE;
            string errorString = string.Empty;
            IntPtr ssl;

            // Get SSL pointer under lock, but DON'T hold lock during I/O
            // This prevents deadlock between concurrent Read and Write operations
            lock (_sslLock)
            {
                if (_disposed || _ssl == IntPtr.Zero)
                {
                    return 0;
                }
                ssl = _ssl;
            }

            // Pin the buffer to prevent GC from moving it during the P/Invoke call
            var handle = GCHandle.Alloc(readBuffer, GCHandleType.Pinned);
            try
            {
                result = OpenSslInterop.SSL_read(ssl, readBuffer, count);
            }
            finally
            {
                handle.Free();
            }

            // Get error info under lock if needed
            if (result <= 0)
            {
                lock (_sslLock)
                {
                    if (_disposed || _ssl == IntPtr.Zero)
                    {
                        return 0;
                    }
                    sslError = OpenSslInterop.SSL_get_error(_ssl, result);
                    errorString = OpenSslInterop.GetLastErrorString();
                }
            }

            if (result > 0)
            {
                if (offset != 0)
                {
                    Array.Copy(readBuffer, 0, buffer, offset, result);
                }
                return result;
            }

            if (result == 0)
            {
                _logger?.LogWarning("OpenSSL Client: SSL_read returned 0 (connection closed by backend). SSL_get_error={SslError}",
                    sslError);
                return 0;
            }

            // Check if disposed (could have changed while we weren't holding lock)
            if (_disposed)
            {
                return 0;
            }

            if (sslError == OpenSslInterop.SSL_ERROR_ZERO_RETURN)
            {
                _logger?.LogWarning("OpenSSL Client: SSL_ERROR_ZERO_RETURN (clean TLS shutdown by backend)");
                return 0; // Clean shutdown
            }

            if (sslError == OpenSslInterop.SSL_ERROR_SYSCALL)
            {
                _logger?.LogWarning("OpenSSL Client: SSL_ERROR_SYSCALL. Error={Error}", errorString);
                return 0;
            }

            if (sslError == OpenSslInterop.SSL_ERROR_WANT_READ ||
                sslError == OpenSslInterop.SSL_ERROR_WANT_WRITE)
            {
                // Non-blocking I/O - need to wait and retry
                attempts++;
                if (attempts >= maxAttempts)
                {
                    throw new IOException("SSL_read timed out waiting for data");
                }
                Thread.Sleep(10);
                continue;
            }

            // For SSL_ERROR_SSL, check if it's a connection closure error
            // These errors indicate the peer closed the connection (not cleanly, but still closed)
            if (sslError == OpenSslInterop.SSL_ERROR_SSL)
            {
                // "unexpected eof while reading" - peer closed without TLS shutdown
                // "application data after close notify" - peer sent close_notify, connection is done
                if (errorString.Contains("unexpected eof") || errorString.Contains("close notify"))
                {
                    _logger?.LogDebug("OpenSSL Client: Connection closed by peer: {Error}", errorString);
                    return 0;
                }
                throw new IOException($"SSL_read failed with SSL_error={sslError}: {errorString}");
            }

            throw new IOException($"SSL_read failed with SSL_error={sslError}: {errorString}");
        }
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(OpenSslTlsStream));

        // OpenSSL writes from buffer at offset 0, so we need a temp buffer if offset != 0
        byte[] writeBuffer;
        if (offset == 0 && buffer.Length >= count)
        {
            writeBuffer = buffer;
        }
        else
        {
            writeBuffer = new byte[count];
            Array.Copy(buffer, offset, writeBuffer, 0, count);
        }

        var written = 0;
        int attempts = 0;
        const int maxAttempts = 500; // ~5 seconds with 10ms sleep

        while (written < count)
        {
            int result;
            int sslError = OpenSslInterop.SSL_ERROR_NONE;
            string errorString = string.Empty;
            IntPtr ssl;

            // Get SSL pointer under lock, but DON'T hold lock during I/O
            // This prevents deadlock between concurrent Read and Write operations
            lock (_sslLock)
            {
                if (_disposed || _ssl == IntPtr.Zero)
                {
                    return;
                }
                ssl = _ssl;
            }

            // Create a slice of the remaining data if we've already written some
            // SSL_write receives a pointer to byte[0], so we need to adjust
            byte[] dataToWrite;
            int bytesToWrite;
            if (written == 0)
            {
                dataToWrite = writeBuffer;
                bytesToWrite = count;
            }
            else
            {
                bytesToWrite = count - written;
                dataToWrite = new byte[bytesToWrite];
                Array.Copy(writeBuffer, written, dataToWrite, 0, bytesToWrite);
            }

            // Pin the buffer to prevent GC from moving it during the P/Invoke call
            var handle = GCHandle.Alloc(dataToWrite, GCHandleType.Pinned);
            try
            {
                result = OpenSslInterop.SSL_write(ssl, dataToWrite, bytesToWrite);
            }
            finally
            {
                handle.Free();
            }

            // Get error info under lock if needed
            if (result <= 0)
            {
                lock (_sslLock)
                {
                    if (_disposed || _ssl == IntPtr.Zero)
                    {
                        return;
                    }
                    sslError = OpenSslInterop.SSL_get_error(_ssl, result);
                    errorString = OpenSslInterop.GetLastErrorString();
                }
            }

            if (result > 0)
            {
                written += result;
                attempts = 0; // Reset attempts on success
                continue;
            }

            // Check if we're being disposed - SSL_ERROR_SYSCALL often means socket was closed
            if (_disposed || sslError == OpenSslInterop.SSL_ERROR_SYSCALL)
            {
                return;
            }

            if (sslError == OpenSslInterop.SSL_ERROR_WANT_READ ||
                sslError == OpenSslInterop.SSL_ERROR_WANT_WRITE)
            {
                // Non-blocking I/O - need to wait and retry
                attempts++;
                if (attempts >= maxAttempts)
                {
                    throw new IOException("SSL_write timed out waiting for I/O");
                }
                Thread.Sleep(10);
                continue;
            }

            throw new IOException($"SSL_write failed with SSL_error={sslError}: {errorString}");
        }
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        IntPtr sslToFree = IntPtr.Zero;
        IntPtr sessionToFree = IntPtr.Zero;
        IntPtr ctxToFree = IntPtr.Zero;

        lock (_sslLock)
        {
            if (!_disposed)
            {
                if (disposing && !_skipTlsShutdownOnDispose)
                {
                    // Perform proper bidirectional TLS shutdown to send close_notify
                    if (_ssl != IntPtr.Zero && OpenSslInterop.SSL_is_init_finished(_ssl) != 0)
                    {
                        try
                        {
                            // First call sends our close_notify
                            var result = OpenSslInterop.SSL_shutdown(_ssl);
                            _logger?.LogDebug("OpenSSL Client: SSL_shutdown first call returned {Result}", result);

                            if (result == 0)
                            {
                                // Result 0 means close_notify was sent but we need to wait for peer's response
                                int attempts = 0;
                                const int maxAttempts = 10; // 100ms total

                                while (attempts < maxAttempts)
                                {
                                    result = OpenSslInterop.SSL_shutdown(_ssl);
                                    if (result != 0)
                                    {
                                        break;
                                    }

                                    var sslError = OpenSslInterop.SSL_get_error(_ssl, result);
                                    if (sslError == OpenSslInterop.SSL_ERROR_WANT_READ ||
                                        sslError == OpenSslInterop.SSL_ERROR_WANT_WRITE)
                                    {
                                        attempts++;
                                        Thread.Sleep(10);
                                        continue;
                                    }

                                    break;
                                }
                            }

                            _logger?.LogDebug("OpenSSL Client: TLS shutdown completed with result {Result}", result);
                        }
                        catch (Exception ex)
                        {
                            _logger?.LogDebug(ex, "OpenSSL Client: Error during TLS shutdown in Dispose");
                        }
                    }
                }

                // Capture ALL pointers and set to Zero BEFORE freeing
                // This prevents double-free if Dispose is called twice
                sessionToFree = _session;
                _session = IntPtr.Zero;

                sslToFree = _ssl;
                _ssl = IntPtr.Zero;

                ctxToFree = _sslCtx;
                // Note: _sslCtx is readonly, but we track disposal via _disposed flag

                _disposed = true;
            }
        }

        // Free SSL objects OUTSIDE the lock (order matters: session, ssl, then ctx)
        if (sessionToFree != IntPtr.Zero)
        {
            OpenSslInterop.SSL_SESSION_free(sessionToFree);
        }

        if (sslToFree != IntPtr.Zero)
        {
            OpenSslInterop.SSL_free(sslToFree);
        }

        if (ctxToFree != IntPtr.Zero)
        {
            OpenSslInterop.SSL_CTX_free(ctxToFree);
        }

        base.Dispose(disposing);
    }

    #endregion
}

/// <summary>
/// Wrapper for an OpenSSL TLS session that can be used for session resumption.
/// CRITICAL: This class stores SERIALIZED session data (byte array), not a pointer.
/// This approach mirrors how libfilezilla/GnuTLS handles session resumption:
/// - Each data channel gets its own INDEPENDENT session object
/// - No shared state between connections
/// - Solves the issue where freeing one SSL connection affects the shared session
///
/// The FtpSessionHandler owns this object and manages its lifecycle.
/// </summary>
public class OpenSslSession : IDisposable
{
    /// <summary>
    /// Serialized session data in DER format.
    /// This is an independent copy - no shared pointers with any SSL connection.
    /// </summary>
    public byte[]? SessionData { get; private set; }

    /// <summary>
    /// Session ID for logging/debugging purposes.
    /// </summary>
    public string SessionId { get; private set; }

    private readonly object _lock = new();
    private bool _disposed;

    /// <summary>
    /// Creates an OpenSslSession by serializing the session data.
    /// The original session pointer is freed after serialization.
    /// </summary>
    /// <param name="sessionPtr">Session pointer from SSL_get1_session. Will be freed after use.</param>
    public OpenSslSession(IntPtr sessionPtr)
    {
        if (sessionPtr == IntPtr.Zero)
        {
            SessionData = null;
            SessionId = "(null)";
            return;
        }

        try
        {
            // Get the session ID before serializing (for logging)
            SessionId = OpenSslInterop.GetSessionIdHex(sessionPtr);

            // Serialize the session to bytes - this creates an independent copy
            SessionData = OpenSslInterop.SerializeSession(sessionPtr);

            if (SessionData == null)
            {
                throw new InvalidOperationException("Failed to serialize SSL session");
            }
        }
        finally
        {
            // Free the original session pointer - we have our own copy now
            OpenSslInterop.SSL_SESSION_free(sessionPtr);
        }
    }

    /// <summary>
    /// Creates a NEW session object from the stored serialized data.
    /// This is called each time a data channel needs to resume.
    /// IMPORTANT: The caller MUST free the returned session pointer with SSL_SESSION_free.
    /// </summary>
    /// <returns>A new session pointer, or IntPtr.Zero if no session data is stored.</returns>
    public IntPtr CreateSessionForResumption()
    {
        lock (_lock)
        {
            if (_disposed || SessionData == null) return IntPtr.Zero;

            // Deserialize creates a completely NEW session object
            return OpenSslInterop.DeserializeSession(SessionData);
        }
    }

    /// <summary>
    /// Updates the session with new serialized data.
    /// The new session pointer is serialized and then freed.
    /// </summary>
    public void UpdateSession(IntPtr newSessionPtr)
    {
        if (newSessionPtr == IntPtr.Zero) return;

        lock (_lock)
        {
            if (_disposed)
            {
                // Still need to free the pointer even if we're disposed
                OpenSslInterop.SSL_SESSION_free(newSessionPtr);
                return;
            }

            try
            {
                // Get the new session ID
                var newSessionId = OpenSslInterop.GetSessionIdHex(newSessionPtr);

                // Serialize the new session
                var newData = OpenSslInterop.SerializeSession(newSessionPtr);

                if (newData != null)
                {
                    SessionData = newData;
                    SessionId = newSessionId;
                }
            }
            finally
            {
                // Always free the pointer - we have our own copy
                OpenSslInterop.SSL_SESSION_free(newSessionPtr);
            }
        }
    }

    public bool IsValid
    {
        get
        {
            lock (_lock)
            {
                return SessionData != null && SessionData.Length > 0 && !_disposed;
            }
        }
    }

    public void Dispose()
    {
        lock (_lock)
        {
            if (_disposed) return;
            SessionData = null;
            _disposed = true;
        }
    }
}
