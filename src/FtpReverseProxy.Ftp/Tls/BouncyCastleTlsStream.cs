using System.Net.Sockets;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Security;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp.Tls;

/// <summary>
/// Wraps a TCP stream with BouncyCastle TLS, supporting explicit session resumption.
/// This is used to work around .NET's SslStream limitation where automatic session
/// resumption doesn't work reliably for FTP data channels.
/// </summary>
public class BouncyCastleTlsStream : Stream
{
    private readonly TlsClientProtocol _protocol;
    private readonly ResumableTlsClient _tlsClient;
    private readonly Stream _innerStream;
    private bool _disposed;

    private BouncyCastleTlsStream(
        TlsClientProtocol protocol,
        ResumableTlsClient tlsClient,
        Stream innerStream)
    {
        _protocol = protocol;
        _tlsClient = tlsClient;
        _innerStream = innerStream;
    }

    /// <summary>
    /// Gets the established TLS session, which can be used for resumption on subsequent connections.
    /// </summary>
    public TlsSession? EstablishedSession => _tlsClient.EstablishedSession;

    /// <summary>
    /// Gets the session ticket received from the server.
    /// </summary>
    public NewSessionTicket? SessionTicket => _tlsClient.SessionTicket;

    /// <summary>
    /// Gets whether this connection resumed a previous session.
    /// </summary>
    public bool IsResumedSession => _tlsClient.IsResumedSession;

    /// <summary>
    /// Creates a new TLS connection, optionally resuming a previous session.
    /// </summary>
    /// <param name="tcpClient">The TCP client to wrap</param>
    /// <param name="hostname">The server hostname for SNI and certificate validation</param>
    /// <param name="skipCertificateValidation">Whether to skip certificate validation</param>
    /// <param name="sessionToResume">Optional session to resume</param>
    /// <param name="logger">Optional logger</param>
    /// <returns>A stream that handles TLS encryption/decryption</returns>
    public static async Task<BouncyCastleTlsStream> ConnectAsync(
        TcpClient tcpClient,
        string hostname,
        bool skipCertificateValidation = false,
        TlsSession? sessionToResume = null,
        ILogger? logger = null)
    {
        var networkStream = tcpClient.GetStream();

        // Log session resumption details
        if (sessionToResume != null)
        {
            var sessionId = sessionToResume.SessionID;
            var sessionIdHex = sessionId != null ? BitConverter.ToString(sessionId).Replace("-", "") : "(null)";
            logger?.LogInformation(
                "BouncyCastleTlsStream.ConnectAsync: Attempting connection with session resumption. SessionID: {SessionId}, IsResumable: {IsResumable}",
                sessionIdHex,
                sessionToResume.IsResumable);

            // Session resumption enabled
            logger?.LogInformation("Session resumption enabled - will attempt to resume session");
        }
        else
        {
            logger?.LogDebug("BouncyCastleTlsStream.ConnectAsync: No session to resume (fresh connection)");
        }

        // Create the BouncyCastle TLS crypto provider
        var crypto = new BcTlsCrypto(new SecureRandom());

        // Create our custom TLS client with session resumption support
        var tlsClient = new ResumableTlsClient(
            crypto,
            hostname,
            skipCertificateValidation,
            sessionToResume,
            logger);

        // Create the TLS protocol handler
        var protocol = new TlsClientProtocol(networkStream);

        try
        {
            // Perform the TLS handshake
            // This runs synchronously in BouncyCastle, so we wrap it in Task.Run
            await Task.Run(() => protocol.Connect(tlsClient));

            logger?.LogInformation(
                "BouncyCastle TLS connection established to {Hostname}. Resumed: {Resumed}",
                hostname, tlsClient.IsResumedSession);

            return new BouncyCastleTlsStream(protocol, tlsClient, networkStream);
        }
        catch (Exception ex)
        {
            logger?.LogError(ex, "Failed to establish TLS connection to {Hostname}", hostname);
            protocol.Close();
            throw;
        }
    }

    #region Stream Implementation

    public override bool CanRead => !_disposed && _protocol.Stream.CanRead;

    public override bool CanSeek => false;

    public override bool CanWrite => !_disposed && _protocol.Stream.CanWrite;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Flush()
    {
        _protocol.Stream.Flush();
    }

    public override async Task FlushAsync(CancellationToken cancellationToken)
    {
        await _protocol.Stream.FlushAsync(cancellationToken);
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        return _protocol.Stream.Read(buffer, offset, count);
    }

    public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return await _protocol.Stream.ReadAsync(buffer, offset, count, cancellationToken);
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        // BouncyCastle's stream might not support Memory<byte> directly
        var array = new byte[buffer.Length];
        var read = await _protocol.Stream.ReadAsync(array, 0, array.Length, cancellationToken);
        if (read > 0)
        {
            array.AsMemory(0, read).CopyTo(buffer);
        }
        return read;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        _protocol.Stream.Write(buffer, offset, count);
    }

    public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        await _protocol.Stream.WriteAsync(buffer, offset, count, cancellationToken);
    }

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var array = buffer.ToArray();
        await _protocol.Stream.WriteAsync(array, 0, array.Length, cancellationToken);
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            if (disposing)
            {
                try
                {
                    _protocol.Close();
                }
                catch
                {
                    // Ignore errors during close
                }
            }
            _disposed = true;
        }
        base.Dispose(disposing);
    }

    #endregion
}
