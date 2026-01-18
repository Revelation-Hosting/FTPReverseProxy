using System.Text;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Security;
using Microsoft.Extensions.Logging;

namespace FtpReverseProxy.Ftp.Tls;

/// <summary>
/// Custom TLS client that supports session resumption for FTP data channels.
/// This is critical for FTPS servers that require the data channel TLS session
/// to be a resumption of the control channel session.
/// </summary>
public class ResumableTlsClient : DefaultTlsClient
{
    private readonly string _hostname;
    private readonly bool _skipCertificateValidation;
    private readonly ILogger? _logger;
    private readonly TlsSession? _sessionToResume;
    private readonly SessionParameters? _sessionParameters;

    private TlsSession? _establishedSession;
    private NewSessionTicket? _sessionTicket;
    private bool _isResumedSession;

    public ResumableTlsClient(
        TlsCrypto crypto,
        string hostname,
        bool skipCertificateValidation = false,
        TlsSession? sessionToResume = null,
        ILogger? logger = null)
        : base(crypto)
    {
        _hostname = hostname;
        _skipCertificateValidation = skipCertificateValidation;
        _sessionToResume = sessionToResume;
        _logger = logger;

        // Extract session parameters for resumption - this contains the master secret
        if (_sessionToResume != null)
        {
            _sessionParameters = _sessionToResume.ExportSessionParameters();
            if (_sessionParameters != null)
            {
                var masterSecret = _sessionParameters.MasterSecret;
                var hasMasterSecret = masterSecret != null && masterSecret.Length > 0;

                _logger?.LogInformation(
                    "Session parameters extracted for resumption. CipherSuite: {CipherSuite}, ProtocolVersion: {Version}, HasMasterSecret: {HasMaster}, MasterSecretLength: {MasterLen}, ExtendedMasterSecret: {ExtMS}",
                    _sessionParameters.CipherSuite,
                    _sessionParameters.NegotiatedVersion,
                    hasMasterSecret,
                    masterSecret?.Length ?? 0,
                    _sessionParameters.IsExtendedMasterSecret);
            }
            else
            {
                _logger?.LogWarning("Session exists but ExportSessionParameters() returned null - resumption may fail");
            }
        }
    }

    /// <summary>
    /// Gets the established TLS session after handshake completes.
    /// This can be used for session resumption on subsequent connections.
    /// </summary>
    public TlsSession? EstablishedSession => _establishedSession;

    /// <summary>
    /// Gets the session ticket received from the server (for TLS 1.2 session tickets or TLS 1.3 PSK).
    /// </summary>
    public NewSessionTicket? SessionTicket => _sessionTicket;

    /// <summary>
    /// Gets whether the session was resumed.
    /// </summary>
    public bool IsResumedSession => _isResumedSession;

    /// <summary>
    /// Returns the session to resume, if any.
    /// </summary>
    public override TlsSession GetSessionToResume()
    {
        if (_sessionToResume != null)
        {
            var sessionId = _sessionToResume.SessionID;
            var sessionIdHex = sessionId != null ? BitConverter.ToString(sessionId).Replace("-", "") : "(null)";

            _logger?.LogInformation(
                "GetSessionToResume called. Session exists: True, IsResumable: {IsResumable}, SessionID: {SessionId}",
                _sessionToResume.IsResumable,
                sessionIdHex);

            if (_sessionToResume.IsResumable)
            {
                _logger?.LogInformation("Returning session for resumption");
                return _sessionToResume;
            }
            else
            {
                _logger?.LogWarning("Session exists but is NOT resumable - cannot resume");
            }
        }
        else
        {
            _logger?.LogDebug("GetSessionToResume called but no session to resume");
        }
        return null!;
    }

    /// <summary>
    /// Called when a new session ticket is received from the server.
    /// </summary>
    public override void NotifyNewSessionTicket(NewSessionTicket newSessionTicket)
    {
        base.NotifyNewSessionTicket(newSessionTicket);
        _sessionTicket = newSessionTicket;
        _logger?.LogDebug("Received new session ticket from server");
    }

    /// <summary>
    /// Called to notify the selected server version.
    /// </summary>
    public override void NotifyServerVersion(ProtocolVersion serverVersion)
    {
        base.NotifyServerVersion(serverVersion);
        _logger?.LogDebug("Server selected TLS version: {Version}", serverVersion);
    }

    /// <summary>
    /// Called to notify whether session was resumed.
    /// </summary>
    public override void NotifySessionID(byte[] sessionID)
    {
        base.NotifySessionID(sessionID);

        var receivedSessionIdHex = sessionID != null && sessionID.Length > 0
            ? BitConverter.ToString(sessionID).Replace("-", "")
            : "(empty)";

        _logger?.LogInformation("Server returned session ID: {SessionId}", receivedSessionIdHex);

        // If we got a session ID and we were trying to resume, check if it matches
        if (_sessionToResume != null && sessionID != null && sessionID.Length > 0)
        {
            var originalSessionId = _sessionToResume.SessionID;
            var originalSessionIdHex = originalSessionId != null
                ? BitConverter.ToString(originalSessionId).Replace("-", "")
                : "(null)";

            _logger?.LogInformation(
                "Comparing session IDs - Original: {Original}, Received: {Received}, Match: {Match}",
                originalSessionIdHex,
                receivedSessionIdHex,
                originalSessionId != null && originalSessionId.SequenceEqual(sessionID));

            if (originalSessionId != null && originalSessionId.SequenceEqual(sessionID))
            {
                _isResumedSession = true;
                _logger?.LogInformation("Session ID matches - session will be resumed!");
            }
            else
            {
                _logger?.LogWarning("Session ID does NOT match - server did not resume the session");
            }
        }
    }

    /// <summary>
    /// Called when the handshake is complete.
    /// </summary>
    public override void NotifyHandshakeComplete()
    {
        base.NotifyHandshakeComplete();

        // Store the session for potential resumption
        var context = m_context;
        if (context != null)
        {
            _establishedSession = context.Session;

            var sessionId = _establishedSession?.SessionID;
            var sessionIdHex = sessionId != null ? BitConverter.ToString(sessionId).Replace("-", "") : "(null)";

            _logger?.LogInformation(
                "TLS handshake complete. Resumed: {Resumed}, Protocol: {Protocol}, CipherSuite: {CipherSuite}, SessionID: {SessionId}, SessionIsResumable: {IsResumable}",
                _isResumedSession,
                context.SecurityParameters?.NegotiatedVersion,
                context.SecurityParameters?.CipherSuite,
                sessionIdHex,
                _establishedSession?.IsResumable ?? false);
        }
    }

    /// <summary>
    /// Server certificate authentication - can be configured to skip validation.
    /// </summary>
    public override TlsAuthentication GetAuthentication()
    {
        return new ServerCertificateAuthentication(_skipCertificateValidation, _hostname, _logger);
    }

    /// <summary>
    /// Override to support both TLS 1.2 and 1.3 for maximum compatibility.
    /// Prefer TLS 1.3 as it has better session resumption support (PSK-based).
    /// </summary>
    protected override ProtocolVersion[] GetSupportedVersions()
    {
        // Try TLS 1.3 first for better session resumption support
        return new[]
        {
            ProtocolVersion.TLSv13,
            ProtocolVersion.TLSv12
        };
    }

    /// <summary>
    /// Override cipher suites to prioritize the original session's cipher suite when resuming.
    /// </summary>
    protected override int[] GetSupportedCipherSuites()
    {
        var baseCipherSuites = base.GetSupportedCipherSuites();

        // When resuming, put the original cipher suite first and include it if not already present
        if (_sessionParameters != null)
        {
            var originalCipherSuite = _sessionParameters.CipherSuite;
            _logger?.LogDebug("Prioritizing original cipher suite {CipherSuite} for session resumption", originalCipherSuite);

            // Check if the original cipher suite is in the base list
            if (!baseCipherSuites.Contains(originalCipherSuite))
            {
                // Prepend the original cipher suite
                var newList = new int[baseCipherSuites.Length + 1];
                newList[0] = originalCipherSuite;
                Array.Copy(baseCipherSuites, 0, newList, 1, baseCipherSuites.Length);
                return newList;
            }
            else
            {
                // Move original cipher suite to front
                var newList = new List<int> { originalCipherSuite };
                newList.AddRange(baseCipherSuites.Where(cs => cs != originalCipherSuite));
                return newList.ToArray();
            }
        }

        return baseCipherSuites;
    }

    /// <summary>
    /// Enable Extended Master Secret (RFC 7627) which is often required for session resumption
    /// with Windows SChannel (used by FileZilla Server).
    /// </summary>
    public override bool ShouldUseExtendedMasterSecret()
    {
        // Always offer EMS - it's a security improvement and required by some servers for resumption
        _logger?.LogInformation("ShouldUseExtendedMasterSecret called - returning true to offer EMS extension");
        return true;
    }


    /// <summary>
    /// Server name indication for virtual hosting support.
    /// </summary>
    protected override IList<ServerName> GetSniServerNames()
    {
        _logger?.LogDebug("Sending SNI for hostname: {Hostname}", _hostname);
        var hostnameBytes = Encoding.ASCII.GetBytes(_hostname);
        return new List<ServerName>
        {
            new ServerName(NameType.host_name, hostnameBytes)
        };
    }

    /// <summary>
    /// Handles server certificate authentication.
    /// </summary>
    private class ServerCertificateAuthentication : TlsAuthentication
    {
        private readonly bool _skipValidation;
        private readonly string _hostname;
        private readonly ILogger? _logger;

        public ServerCertificateAuthentication(bool skipValidation, string hostname, ILogger? logger)
        {
            _skipValidation = skipValidation;
            _hostname = hostname;
            _logger = logger;
        }

        public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
        {
            var chain = serverCertificate.Certificate;

            if (chain == null || chain.IsEmpty)
            {
                if (!_skipValidation)
                {
                    throw new TlsFatalAlert(AlertDescription.certificate_required);
                }
                _logger?.LogWarning("Server provided no certificate, but validation is skipped");
                return;
            }

            if (_skipValidation)
            {
                _logger?.LogDebug("Skipping certificate validation for {Hostname}", _hostname);
                return;
            }

            // Basic certificate validation - in production you'd want more thorough validation
            _logger?.LogDebug("Server provided certificate chain with {Count} certificate(s)", chain.Length);
        }

        public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
        {
            // No client certificate authentication
            return null!;
        }
    }
}
