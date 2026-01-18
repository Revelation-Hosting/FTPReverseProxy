using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using System.Runtime.CompilerServices;

namespace FtpReverseProxy.Ftp.Tls;

/// <summary>
/// OpenSSL-based TLS server stream for accepting client connections.
/// Used for data channel connections from FTP clients where we need
/// proper close_notify handling that .NET's SslStream doesn't provide.
/// </summary>
public class OpenSslServerStream : Stream
{
    private readonly Socket _socket;
    private readonly IntPtr _sslCtx;
    private IntPtr _ssl;  // Mutable: set to Zero after SSL_free
    private readonly ILogger? _logger;
    private readonly bool _ownsContext;
    private bool _disposed;

    // Lock object to synchronize SSL operations and prevent use-after-free
    // This is critical because SSL_free must not race with SSL_read/SSL_write
    private readonly object _sslLock = new();

    private OpenSslServerStream(Socket socket, IntPtr sslCtx, IntPtr ssl, bool ownsContext, ILogger? logger)
    {
        _socket = socket;
        _sslCtx = sslCtx;
        _ssl = ssl;
        _ownsContext = ownsContext;
        _logger = logger;
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
    /// Creates a new OpenSSL TLS server connection using a shared context.
    /// This enables TLS session resumption between connections that use the same context.
    /// Thread-safe for concurrent connections.
    /// </summary>
    public static OpenSslServerStream Accept(
        TcpClient tcpClient,
        OpenSslServerContext sharedContext,
        ILogger? logger = null)
    {
        var socket = tcpClient.Client;
        IntPtr ssl = IntPtr.Zero;

        // Capture thread ID for debugging concurrent access
        var threadId = Environment.CurrentManagedThreadId;

        try
        {
            // Create SSL connection from shared context (thread-safe)
            ssl = sharedContext.CreateSsl();

            // Ensure socket is in blocking mode for OpenSSL
            socket.Blocking = true;

            // Set the socket file descriptor
            // DIAGNOSTIC: Log full handle value to check for truncation issues on 64-bit Windows
            var fullHandle = socket.Handle;
            var fd = (int)fullHandle;

            logger?.LogInformation("[Thread {ThreadId}] OpenSSL Server: SSL={Ssl:X}, SocketHandle={FullHandle:X} (truncated to fd={Fd}), truncation safe={IsSafe}",
                threadId, ssl.ToInt64(), fullHandle.ToInt64(), fd, fullHandle.ToInt64() == fd);

            if (OpenSslInterop.SSL_set_fd(ssl, fd) != 1)
            {
                var error = OpenSslInterop.GetLastErrorString();
                throw new InvalidOperationException($"Failed to set socket FD: {error}");
            }

            // Perform TLS server handshake with retry for non-blocking I/O
            logger?.LogDebug("OpenSSL Server: Starting TLS handshake (shared context) for socket {SocketHandle}", fd);

            int result;
            int attempts = 0;
            const int maxAttempts = 100;

            while (true)
            {
                result = OpenSslInterop.SSL_accept(ssl);

                if (result == 1)
                {
                    break; // Handshake successful
                }

                var sslError = OpenSslInterop.SSL_get_error(ssl, result);

                if (sslError == OpenSslInterop.SSL_ERROR_WANT_READ ||
                    sslError == OpenSslInterop.SSL_ERROR_WANT_WRITE)
                {
                    attempts++;
                    if (attempts >= maxAttempts)
                    {
                        throw new InvalidOperationException(
                            $"TLS handshake timed out after {maxAttempts} attempts waiting for I/O");
                    }

                    Thread.Sleep(10);
                    continue;
                }

                // Capture error immediately
                var errorStr = OpenSslInterop.GetLastErrorString();
                throw new InvalidOperationException(
                    $"TLS handshake failed. SSL_accept returned {result}, SSL_error={sslError}: {errorStr}");
            }

            var version = OpenSslInterop.GetVersionString(ssl);
            var cipher = OpenSslInterop.GetCipherName(ssl);
            var resumed = OpenSslInterop.SSL_session_reused(ssl) == 1;

            logger?.LogInformation(
                "[Thread {ThreadId}] OpenSSL Server: TLS handshake complete. SSL={Ssl:X}, Resumed: {Resumed}, Protocol: {Protocol}, Cipher: {Cipher}",
                threadId, ssl.ToInt64(), resumed, version, cipher);

            // Don't own the context - it's shared
            return new OpenSslServerStream(socket, sharedContext.Handle, ssl, ownsContext: false, logger);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "OpenSSL Server: TLS handshake failed for socket");
            if (ssl != IntPtr.Zero)
            {
                try
                {
                    OpenSslInterop.SSL_free(ssl);
                }
                catch
                {
                    // Ignore errors during cleanup
                }
            }
            throw;
        }
    }

    /// <summary>
    /// Creates a new OpenSSL TLS server connection using the provided certificate.
    /// Creates a standalone context - sessions cannot be resumed on other connections.
    /// </summary>
    public static OpenSslServerStream Accept(
        TcpClient tcpClient,
        X509Certificate2 certificate,
        ILogger? logger = null)
    {
        var socket = tcpClient.Client;

        // Initialize OpenSSL (safe to call multiple times)
        OpenSslInterop.OPENSSL_init_ssl(0, IntPtr.Zero);

        // Create SSL context for server
        var method = OpenSslInterop.TLS_server_method();
        if (method == IntPtr.Zero)
        {
            throw new InvalidOperationException($"Failed to get TLS server method: {OpenSslInterop.GetLastErrorString()}");
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

            // Load certificate from X509Certificate2
            var pfxData = certificate.Export(X509ContentType.Pfx, "");
            if (!OpenSslInterop.LoadPkcs12(pfxData, "", out var cert, out var pkey))
            {
                throw new InvalidOperationException($"Failed to load certificate: {OpenSslInterop.GetLastErrorString()}");
            }

            try
            {
                if (OpenSslInterop.SSL_CTX_use_certificate(ctx, cert) != 1)
                {
                    throw new InvalidOperationException($"Failed to use certificate: {OpenSslInterop.GetLastErrorString()}");
                }

                if (OpenSslInterop.SSL_CTX_use_PrivateKey(ctx, pkey) != 1)
                {
                    throw new InvalidOperationException($"Failed to use private key: {OpenSslInterop.GetLastErrorString()}");
                }

                if (OpenSslInterop.SSL_CTX_check_private_key(ctx) != 1)
                {
                    throw new InvalidOperationException($"Certificate and private key don't match: {OpenSslInterop.GetLastErrorString()}");
                }
            }
            finally
            {
                OpenSslInterop.X509_free(cert);
                OpenSslInterop.EVP_PKEY_free(pkey);
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

                // Perform TLS server handshake with retry for non-blocking I/O
                logger?.LogDebug("OpenSSL Server: Starting TLS handshake");

                int result;
                int attempts = 0;
                const int maxAttempts = 100;

                while (true)
                {
                    result = OpenSslInterop.SSL_accept(ssl);

                    if (result == 1)
                    {
                        break; // Handshake successful
                    }

                    var sslError = OpenSslInterop.SSL_get_error(ssl, result);

                    if (sslError == OpenSslInterop.SSL_ERROR_WANT_READ ||
                        sslError == OpenSslInterop.SSL_ERROR_WANT_WRITE)
                    {
                        attempts++;
                        if (attempts >= maxAttempts)
                        {
                            throw new InvalidOperationException(
                                $"TLS handshake timed out after {maxAttempts} attempts waiting for I/O");
                        }

                        Thread.Sleep(10);
                        continue;
                    }

                    var errorStr = OpenSslInterop.GetLastErrorString();
                    throw new InvalidOperationException(
                        $"TLS handshake failed. SSL_accept returned {result}, SSL_error={sslError}: {errorStr}");
                }

                var version = OpenSslInterop.GetVersionString(ssl);
                var cipher = OpenSslInterop.GetCipherName(ssl);

                logger?.LogInformation(
                    "OpenSSL Server: TLS handshake complete. Protocol: {Protocol}, Cipher: {Cipher}",
                    version, cipher);

                return new OpenSslServerStream(socket, ctx, ssl, ownsContext: true, logger);
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
    /// Performs a proper TLS shutdown, sending close_notify and waiting for response.
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
                _logger?.LogDebug("OpenSSL Server: Skipping TLS shutdown - handshake not finished");
                return;
            }

            _logger?.LogDebug("OpenSSL Server: Initiating TLS shutdown");

            // First call sends close_notify
            var result = OpenSslInterop.SSL_shutdown(_ssl);
            _logger?.LogDebug("OpenSSL Server: SSL_shutdown first call returned {Result}", result);

            if (result == 0)
            {
                // Need to call again to complete bidirectional shutdown
                // Wait briefly for peer's close_notify
                int attempts = 0;
                const int maxAttempts = 20; // 200ms total

                while (attempts < maxAttempts)
                {
                    result = OpenSslInterop.SSL_shutdown(_ssl);
                    if (result != 0)
                    {
                        // 1 = successful bidirectional shutdown
                        // -1 = error (peer may have already closed)
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

            _logger?.LogDebug("OpenSSL Server: TLS shutdown completed with result {Result}", result);
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
        if (_disposed) throw new ObjectDisposedException(nameof(OpenSslServerStream));

        byte[] readBuffer;
        if (offset == 0)
        {
            readBuffer = buffer;
        }
        else
        {
            readBuffer = new byte[count];
        }

        int attempts = 0;
        // If SSL_read returns WANT_READ repeatedly, something is wrong with the connection.
        // With blocking sockets, SSL_read should block waiting for data. If it keeps
        // returning WANT_READ, it means the socket is in a half-open state or the peer
        // disconnected. We give it a reasonable number of retries (30 seconds worth at
        // 10ms sleep intervals = 3000 attempts) before treating it as a connection closure.
        const int maxWantReadAttempts = 3000;

        while (true)
        {
            int result;
            int sslError = OpenSslInterop.SSL_ERROR_NONE;
            string errorString = string.Empty;
            long sslPtr = 0;
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
                sslPtr = ssl.ToInt64();
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
                var utcNow = DateTime.UtcNow;
                var threadId = Environment.CurrentManagedThreadId;
                var socketConnected = _socket.Connected;
                var socketAvailable = 0;
                try { socketAvailable = _socket.Available; } catch { }
                var stackTrace = new System.Diagnostics.StackTrace(true);

                _logger?.LogWarning("[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] [Thread {ThreadId}] OpenSSL Server: SSL_read returned 0. " +
                    "SSL={Ssl:X}, SSL_get_error={SslError}, ERR={ErrStr}, SocketConnected={Connected}, SocketAvailable={Available}. Stack:\n{StackTrace}",
                    utcNow, threadId, sslPtr, sslError, errorString, socketConnected, socketAvailable, stackTrace.ToString());
                return 0; // Connection closed
            }

            // Check if disposed (could have changed while we weren't holding lock)
            if (_disposed)
            {
                return 0;
            }

            if (sslError == OpenSslInterop.SSL_ERROR_ZERO_RETURN)
            {
                var utcNow = DateTime.UtcNow;
                var stackTrace = new System.Diagnostics.StackTrace(true);
                _logger?.LogWarning("[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] OpenSSL Server: SSL_ERROR_ZERO_RETURN (clean TLS shutdown by peer). Stack:\n{StackTrace}",
                    utcNow, stackTrace.ToString());
                return 0; // Clean shutdown
            }

            if (sslError == OpenSslInterop.SSL_ERROR_SYSCALL)
            {
                var utcNow = DateTime.UtcNow;
                var stackTrace = new System.Diagnostics.StackTrace(true);
                _logger?.LogWarning("[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] OpenSSL Server: SSL_ERROR_SYSCALL. Error={Error}. Stack:\n{StackTrace}",
                    utcNow, errorString, stackTrace.ToString());
                return 0;
            }

            if (sslError == OpenSslInterop.SSL_ERROR_WANT_READ ||
                sslError == OpenSslInterop.SSL_ERROR_WANT_WRITE)
            {
                attempts++;

                // If we've exceeded the max attempts, the connection is stuck - treat as closed
                if (attempts >= maxWantReadAttempts)
                {
                    _logger?.LogWarning("[{Timestamp:HH:mm:ss.fff}] OpenSSL Server: SSL_read WANT_{WantType} exceeded max attempts ({Attempt}), treating as connection closed",
                        DateTime.UtcNow,
                        sslError == OpenSslInterop.SSL_ERROR_WANT_READ ? "READ" : "WRITE",
                        attempts);
                    return 0;
                }

                // Log every 1000 attempts to help debug (less spam)
                if (attempts % 1000 == 0)
                {
                    _logger?.LogWarning("[{Timestamp:HH:mm:ss.fff}] OpenSSL Server: SSL_read WANT_{WantType}, attempt {Attempt}. SocketBlocking={Blocking}, Connected={Connected}",
                        DateTime.UtcNow,
                        sslError == OpenSslInterop.SSL_ERROR_WANT_READ ? "READ" : "WRITE",
                        attempts,
                        _socket.Blocking,
                        _socket.Connected);
                }
                Thread.Sleep(10);
                continue;
            }

            // For SSL_ERROR_SSL, check if it's a connection closure error
            if (sslError == OpenSslInterop.SSL_ERROR_SSL)
            {
                var utcNow = DateTime.UtcNow;
                // "unexpected eof while reading" - peer closed without TLS shutdown
                // "application data after close notify" - peer sent close_notify, connection is done
                if (errorString.Contains("unexpected eof") || errorString.Contains("close notify"))
                {
                    _logger?.LogDebug("[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] OpenSSL Server: Connection closed by peer: {Error}",
                        utcNow, errorString);
                    return 0;
                }
                throw new IOException($"SSL_read failed with SSL_error={sslError}: {errorString}");
            }

            throw new IOException($"SSL_read failed with SSL_error={sslError}: {errorString}");
        }
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(OpenSslServerStream));

        // Log write start with precise timestamp
        var writeStartUtc = DateTime.UtcNow;
        _logger?.LogDebug("[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] OpenSSL Server: Write starting, count={Count}, disposed={Disposed}",
            writeStartUtc, count, _disposed);

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
        const int maxAttempts = 500;

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
                    _logger?.LogWarning("[{Timestamp:HH:mm:ss.fff}] OpenSSL Server: Write aborted - stream disposed!",
                        DateTime.UtcNow);
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
            var writeStartTime = DateTime.UtcNow;
            try
            {
                _logger?.LogInformation("[{Timestamp:HH:mm:ss.fff}] SSL_write ENTERING: {Bytes} bytes, attempt {Attempt}",
                    writeStartTime, bytesToWrite, attempts + 1);

                result = OpenSslInterop.SSL_write(ssl, dataToWrite, bytesToWrite);

                var writeEndTime = DateTime.UtcNow;
                var writeDuration = (writeEndTime - writeStartTime).TotalMilliseconds;
                _logger?.LogInformation("[{Timestamp:HH:mm:ss.fff}] SSL_write RETURNED: result={Result}, took {Duration}ms",
                    writeEndTime, result, writeDuration);
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
                _logger?.LogWarning("[{Timestamp:HH:mm:ss.fff}] SSL_write ERROR: sslError={SslError}, errStr={ErrStr}",
                    DateTime.UtcNow, sslError, errorString);
            }

            if (result > 0)
            {
                written += result;
                attempts = 0;
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

        // Log write completion
        var writeEndUtc = DateTime.UtcNow;
        _logger?.LogDebug("[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] OpenSSL Server: Write completed, wrote {Written} bytes, disposed={Disposed}",
            writeEndUtc, written, _disposed);
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        IntPtr sslToFree = IntPtr.Zero;
        IntPtr ctxToFree = IntPtr.Zero;

        lock (_sslLock)
        {
            if (!_disposed)
            {
                // Log the caller with millisecond UTC timestamp for Wireshark correlation
                var utcNow = DateTime.UtcNow;
                var stackTrace = new System.Diagnostics.StackTrace(1, true);
                var callerFrame = stackTrace.GetFrame(0);
                var callerMethod = callerFrame?.GetMethod();
                var callerFile = callerFrame?.GetFileName();
                var callerLine = callerFrame?.GetFileLineNumber();
                _logger?.LogInformation("[{Timestamp:yyyy-MM-dd HH:mm:ss.fff}] OpenSSL Server Stream: Dispose called (disposing={Disposing}, caller: {Caller} at {File}:{Line})",
                    utcNow, disposing, callerMethod?.Name ?? "unknown", callerFile ?? "unknown", callerLine);

                if (disposing)
                {
                    // Perform proper bidirectional TLS shutdown to send close_notify
                    // This prevents "TLS connection was non-properly terminated" errors on clients
                    if (_ssl != IntPtr.Zero && OpenSslInterop.SSL_is_init_finished(_ssl) != 0)
                    {
                        _logger?.LogInformation("[{Timestamp:HH:mm:ss.fff}] OpenSSL Server: Performing TLS shutdown from Dispose",
                            DateTime.UtcNow);
                        try
                        {
                            // First call sends our close_notify
                            var result = OpenSslInterop.SSL_shutdown(_ssl);
                            _logger?.LogInformation("[{Timestamp:HH:mm:ss.fff}] OpenSSL Server: SSL_shutdown first call returned {Result}",
                                DateTime.UtcNow, result);

                            if (result == 0)
                            {
                                // Result 0 means close_notify was sent but we need to wait for peer's response
                                // Try to complete bidirectional shutdown with a short timeout
                                int attempts = 0;
                                const int maxAttempts = 10; // 100ms total

                                while (attempts < maxAttempts)
                                {
                                    result = OpenSslInterop.SSL_shutdown(_ssl);
                                    if (result != 0)
                                    {
                                        // 1 = successful bidirectional shutdown
                                        // -1 = error (peer may have already closed)
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

                                    // Some other condition, stop trying
                                    break;
                                }
                            }

                            _logger?.LogInformation("[{Timestamp:HH:mm:ss.fff}] OpenSSL Server: TLS shutdown completed with result {Result}",
                                DateTime.UtcNow, result);
                        }
                        catch (Exception ex)
                        {
                            _logger?.LogDebug(ex, "OpenSSL Server: Error during TLS shutdown in Dispose");
                        }
                    }
                }

                // CRITICAL: Capture ALL pointers and set to Zero BEFORE freeing
                // This prevents double-free if Dispose is called twice and prevents
                // any racing Read/Write from using the freed pointer
                sslToFree = _ssl;
                _ssl = IntPtr.Zero;

                // Only capture context if we own it (not shared)
                if (_ownsContext)
                {
                    ctxToFree = _sslCtx;
                }

                _disposed = true;
            }
        }

        // Free SSL objects OUTSIDE the lock (order matters: ssl first, then ctx)
        // This is safe because pointers are already set to Zero and _disposed is true
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
