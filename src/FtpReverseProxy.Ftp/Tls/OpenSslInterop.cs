using System.Runtime.InteropServices;

namespace FtpReverseProxy.Ftp.Tls;

/// <summary>
/// P/Invoke declarations for OpenSSL library.
/// Supports TLS session resumption which is critical for FTPS data channels.
/// </summary>
internal static class OpenSslInterop
{
    // OpenSSL library names vary by platform
    private const string LIBSSL = "libssl";
    private const string LIBCRYPTO = "libcrypto";

    // SSL method constants
    public const int SSL_FILETYPE_PEM = 1;
    public const int SSL_VERIFY_NONE = 0;
    public const int SSL_VERIFY_PEER = 1;

    // SSL error codes
    public const int SSL_ERROR_NONE = 0;
    public const int SSL_ERROR_SSL = 1;
    public const int SSL_ERROR_WANT_READ = 2;
    public const int SSL_ERROR_WANT_WRITE = 3;
    public const int SSL_ERROR_SYSCALL = 5;
    public const int SSL_ERROR_ZERO_RETURN = 6;

    // SSL options
    public const long SSL_OP_NO_SSLv2 = 0x01000000L;
    public const long SSL_OP_NO_SSLv3 = 0x02000000L;
    public const long SSL_OP_NO_COMPRESSION = 0x00020000L;

    // Control commands for SSL_ctrl and SSL_CTX_ctrl
    public const int SSL_CTRL_SET_TLSEXT_HOSTNAME = 55;
    public const int TLSEXT_NAMETYPE_host_name = 0;
    public const int SSL_CTRL_SET_MIN_PROTO_VERSION = 123;
    public const int SSL_CTRL_SET_MAX_PROTO_VERSION = 124;
    public const int SSL_CTRL_SET_SESS_CACHE_MODE = 44;
    public const int SSL_CTRL_SET_SESS_CACHE_SIZE = 42;

    // Session cache mode constants
    public const int SSL_SESS_CACHE_OFF = 0x0000;
    public const int SSL_SESS_CACHE_CLIENT = 0x0001;
    public const int SSL_SESS_CACHE_SERVER = 0x0002;
    public const int SSL_SESS_CACHE_BOTH = SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_SERVER;

    #region Initialization

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int OPENSSL_init_ssl(ulong opts, IntPtr settings);

    [DllImport(LIBCRYPTO, CallingConvention = CallingConvention.Cdecl)]
    public static extern int OPENSSL_init_crypto(ulong opts, IntPtr settings);

    #endregion

    #region SSL Context

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr TLS_client_method();

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr TLS_server_method();

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SSL_CTX_new(IntPtr method);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_CTX_free(IntPtr ctx);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern long SSL_CTX_set_options(IntPtr ctx, long options);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_CTX_set_verify(IntPtr ctx, int mode, IntPtr callback);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern long SSL_CTX_ctrl(IntPtr ctx, int cmd, long larg, IntPtr parg);

    /// <summary>
    /// Sets the minimum TLS protocol version. This is a wrapper around SSL_CTX_ctrl
    /// since SSL_CTX_set_min_proto_version is a macro in OpenSSL.
    /// </summary>
    public static int SSL_CTX_set_min_proto_version(IntPtr ctx, int version)
    {
        return (int)SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, IntPtr.Zero);
    }

    /// <summary>
    /// Sets the maximum TLS protocol version. This is a wrapper around SSL_CTX_ctrl
    /// since SSL_CTX_set_max_proto_version is a macro in OpenSSL.
    /// </summary>
    public static int SSL_CTX_set_max_proto_version(IntPtr ctx, int version)
    {
        return (int)SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MAX_PROTO_VERSION, version, IntPtr.Zero);
    }

    /// <summary>
    /// Sets the session cache mode. Returns the previous mode.
    /// This is a wrapper around SSL_CTX_ctrl since SSL_CTX_set_session_cache_mode is a macro.
    /// </summary>
    public static int SSL_CTX_set_session_cache_mode(IntPtr ctx, int mode)
    {
        return (int)SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, mode, IntPtr.Zero);
    }

    /// <summary>
    /// Sets the session timeout in seconds. Returns the previous timeout.
    /// </summary>
    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern long SSL_CTX_set_timeout(IntPtr ctx, long t);

    /// <summary>
    /// Gets the session timeout in seconds.
    /// </summary>
    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern long SSL_CTX_get_timeout(IntPtr ctx);

    #endregion

    #region SSL Connection

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SSL_new(IntPtr ctx);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_free(IntPtr ssl);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_set_fd(IntPtr ssl, int fd);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_connect(IntPtr ssl);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_accept(IntPtr ssl);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_read(IntPtr ssl, byte[] buf, int num);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_write(IntPtr ssl, byte[] buf, int num);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_shutdown(IntPtr ssl);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_is_init_finished(IntPtr ssl);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_get_error(IntPtr ssl, int ret);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern long SSL_ctrl(IntPtr ssl, int cmd, long larg, IntPtr parg);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SSL_get_version(IntPtr ssl);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SSL_get_current_cipher(IntPtr ssl);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SSL_CIPHER_get_name(IntPtr cipher);

    #endregion

    #region Session Management - Critical for FTPS

    /// <summary>
    /// Gets the SSL session from a connection. Returns a new reference.
    /// The session can be used to resume the connection on another socket.
    /// </summary>
    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SSL_get1_session(IntPtr ssl);

    /// <summary>
    /// Sets a session to be used for resumption before calling SSL_connect.
    /// </summary>
    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_set_session(IntPtr ssl, IntPtr session);

    /// <summary>
    /// Frees a session obtained from SSL_get1_session.
    /// Decrements the reference count and frees when it reaches 0.
    /// </summary>
    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_SESSION_free(IntPtr session);

    /// <summary>
    /// Increments the reference count of a session.
    /// Must be balanced with a corresponding SSL_SESSION_free call.
    /// Returns 1 on success, 0 on failure.
    /// </summary>
    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_SESSION_up_ref(IntPtr session);

    /// <summary>
    /// Checks if the session was reused (resumed).
    /// Returns 1 if resumed, 0 if new session.
    /// </summary>
    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_session_reused(IntPtr ssl);

    /// <summary>
    /// Gets the session ID from a session.
    /// </summary>
    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr SSL_SESSION_get_id(IntPtr session, out uint len);

    #endregion

    #region Session Serialization - Critical for session resumption

    /// <summary>
    /// Serializes an SSL session to DER format.
    /// If pp is NULL, returns the required buffer size.
    /// If pp is not NULL, writes to *pp and advances *pp.
    /// </summary>
    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int i2d_SSL_SESSION(IntPtr session, ref IntPtr pp);

    /// <summary>
    /// Serializes an SSL session to DER format (returns size only).
    /// </summary>
    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl, EntryPoint = "i2d_SSL_SESSION")]
    public static extern int i2d_SSL_SESSION_size(IntPtr session, IntPtr pp);

    /// <summary>
    /// Deserializes an SSL session from DER format.
    /// Creates a new session object from the serialized data.
    /// </summary>
    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr d2i_SSL_SESSION(IntPtr a, ref IntPtr pp, int length);

    /// <summary>
    /// Serializes a session to a byte array.
    /// This creates an independent copy of the session data.
    /// </summary>
    public static byte[]? SerializeSession(IntPtr session)
    {
        if (session == IntPtr.Zero) return null;

        // Get required buffer size
        var size = i2d_SSL_SESSION_size(session, IntPtr.Zero);
        if (size <= 0) return null;

        var buffer = new byte[size];
        var handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            var ptr = handle.AddrOfPinnedObject();
            var written = i2d_SSL_SESSION(session, ref ptr);
            if (written != size)
            {
                return null;
            }
            return buffer;
        }
        finally
        {
            handle.Free();
        }
    }

    /// <summary>
    /// Deserializes a session from a byte array.
    /// This creates a NEW session object from the serialized data.
    /// The caller is responsible for freeing the returned session.
    /// </summary>
    public static IntPtr DeserializeSession(byte[] sessionData)
    {
        if (sessionData == null || sessionData.Length == 0) return IntPtr.Zero;

        var handle = GCHandle.Alloc(sessionData, GCHandleType.Pinned);
        try
        {
            var ptr = handle.AddrOfPinnedObject();
            var session = d2i_SSL_SESSION(IntPtr.Zero, ref ptr, sessionData.Length);
            return session;
        }
        finally
        {
            handle.Free();
        }
    }

    #endregion

    #region BIO (Basic I/O) - For socket integration

    [DllImport(LIBCRYPTO, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr BIO_new_socket(int sock, int close_flag);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern void SSL_set_bio(IntPtr ssl, IntPtr rbio, IntPtr wbio);

    public const int BIO_NOCLOSE = 0;
    public const int BIO_CLOSE = 1;

    #endregion

    #region Error Handling

    [DllImport(LIBCRYPTO, CallingConvention = CallingConvention.Cdecl)]
    public static extern ulong ERR_get_error();

    [DllImport(LIBCRYPTO, CallingConvention = CallingConvention.Cdecl)]
    public static extern void ERR_error_string_n(ulong e, byte[] buf, int len);

    public static string GetErrorString(ulong error)
    {
        var buf = new byte[256];
        ERR_error_string_n(error, buf, buf.Length);
        var nullIndex = Array.IndexOf(buf, (byte)0);
        return System.Text.Encoding.ASCII.GetString(buf, 0, nullIndex > 0 ? nullIndex : buf.Length);
    }

    public static string GetLastErrorString()
    {
        var error = ERR_get_error();
        return error != 0 ? GetErrorString(error) : "No error";
    }

    #endregion

    #region Helper Methods

    /// <summary>
    /// Sets the SNI hostname for the connection.
    /// </summary>
    public static int SSL_set_tlsext_host_name(IntPtr ssl, string hostname)
    {
        var hostnamePtr = Marshal.StringToHGlobalAnsi(hostname);
        try
        {
            return (int)SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, hostnamePtr);
        }
        finally
        {
            Marshal.FreeHGlobal(hostnamePtr);
        }
    }

    /// <summary>
    /// Gets the protocol version string.
    /// </summary>
    public static string GetVersionString(IntPtr ssl)
    {
        var ptr = SSL_get_version(ssl);
        return ptr != IntPtr.Zero ? Marshal.PtrToStringAnsi(ptr) ?? "Unknown" : "Unknown";
    }

    /// <summary>
    /// Gets the cipher name.
    /// </summary>
    public static string GetCipherName(IntPtr ssl)
    {
        var cipher = SSL_get_current_cipher(ssl);
        if (cipher == IntPtr.Zero) return "Unknown";

        var namePtr = SSL_CIPHER_get_name(cipher);
        return namePtr != IntPtr.Zero ? Marshal.PtrToStringAnsi(namePtr) ?? "Unknown" : "Unknown";
    }

    /// <summary>
    /// Gets the session ID as a hex string.
    /// </summary>
    public static string GetSessionIdHex(IntPtr session)
    {
        if (session == IntPtr.Zero) return "(null)";

        var idPtr = SSL_SESSION_get_id(session, out var len);
        if (idPtr == IntPtr.Zero || len == 0) return "(empty)";

        var bytes = new byte[len];
        Marshal.Copy(idPtr, bytes, 0, (int)len);
        return BitConverter.ToString(bytes).Replace("-", "");
    }

    #endregion

    #region TLS Version Constants

    public const int TLS1_VERSION = 0x0301;
    public const int TLS1_1_VERSION = 0x0302;
    public const int TLS1_2_VERSION = 0x0303;
    public const int TLS1_3_VERSION = 0x0304;

    #endregion

    #region Certificate Loading

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_CTX_use_certificate(IntPtr ctx, IntPtr x509);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_CTX_use_PrivateKey(IntPtr ctx, IntPtr pkey);

    [DllImport(LIBSSL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int SSL_CTX_check_private_key(IntPtr ctx);

    #endregion

    #region PKCS12 (PFX) Support

    [DllImport(LIBCRYPTO, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr d2i_PKCS12(IntPtr a, ref IntPtr pp, int length);

    [DllImport(LIBCRYPTO, CallingConvention = CallingConvention.Cdecl)]
    public static extern int PKCS12_parse(IntPtr p12, string pass, out IntPtr pkey, out IntPtr cert, out IntPtr ca);

    [DllImport(LIBCRYPTO, CallingConvention = CallingConvention.Cdecl)]
    public static extern void PKCS12_free(IntPtr p12);

    [DllImport(LIBCRYPTO, CallingConvention = CallingConvention.Cdecl)]
    public static extern void X509_free(IntPtr x509);

    [DllImport(LIBCRYPTO, CallingConvention = CallingConvention.Cdecl)]
    public static extern void EVP_PKEY_free(IntPtr pkey);

    /// <summary>
    /// Loads a certificate and private key from PKCS12 (PFX) data.
    /// </summary>
    public static bool LoadPkcs12(byte[] pfxData, string password, out IntPtr cert, out IntPtr pkey)
    {
        cert = IntPtr.Zero;
        pkey = IntPtr.Zero;

        // Pin the byte array and get a pointer to it
        var handle = GCHandle.Alloc(pfxData, GCHandleType.Pinned);
        try
        {
            var dataPtr = handle.AddrOfPinnedObject();

            // Parse PKCS12 structure
            var p12 = d2i_PKCS12(IntPtr.Zero, ref dataPtr, pfxData.Length);
            if (p12 == IntPtr.Zero)
            {
                return false;
            }

            try
            {
                // Extract certificate and private key
                if (PKCS12_parse(p12, password ?? "", out pkey, out cert, out var ca) != 1)
                {
                    return false;
                }

                // We don't need the CA chain for now
                if (ca != IntPtr.Zero)
                {
                    // Free CA stack if needed (sk_X509_pop_free)
                }

                return true;
            }
            finally
            {
                PKCS12_free(p12);
            }
        }
        finally
        {
            handle.Free();
        }
    }

    #endregion
}
