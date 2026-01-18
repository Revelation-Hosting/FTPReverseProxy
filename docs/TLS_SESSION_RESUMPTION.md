# TLS Session Resumption in the FTP Reverse Proxy

This document explains why TLS session resumption is required for FTPS proxying and
how it's implemented using native OpenSSL.

## Why Session Resumption is Required

Many FTPS servers (including FileZilla Server) require TLS session resumption on data
channels as a security measure. The requirement is:

> The data channel TLS session must be a resumption of the control channel TLS session.

This proves that the data channel connection comes from the same authenticated client
that established the control channel.

### The Problem with .NET's SslStream

.NET's `SslStream` doesn't expose the TLS session for resumption. You can't:
- Extract the session from a control channel SslStream
- Resume that session on a data channel SslStream

This is why we had to implement native OpenSSL integration.

## Architecture Overview

```
Client <--TLS--> Proxy <--TLS--> Backend
         ^               ^
         |               |
    OpenSslServer   OpenSslClient
    Stream          TlsStream
         |               |
         |               +-- Session from control channel
         |                   resumed on data channels
         |
         +-- Shared SSL context for
             client-side session resumption
```

### Components

1. **OpenSslInterop.cs** - P/Invoke declarations for OpenSSL functions
2. **OpenSslTlsStream.cs** - Client-side TLS (proxy -> backend) with session resumption
3. **OpenSslServerStream.cs** - Server-side TLS (client -> proxy)
4. **OpenSslServerContext.cs** - Shared SSL_CTX for session ID-based resumption
5. **OpenSslSession.cs** - Wrapper for SSL_SESSION with serialization support

## Session Resumption Flow

### Control Channel (Initial Connection)

```
1. Client connects to proxy on port 21
2. Proxy connects to backend
3. AUTH TLS on both connections
4. Proxy captures backend TLS session:
   - OpenSslTlsStream.GetSession() returns SSL_SESSION pointer
   - OpenSslSession wraps it, serializes with i2d_SSL_SESSION
5. Session stored in FtpBackendConnection.TlsSessionForResumption
```

### Data Channel (Transfer)

```
1. PASV establishes data channel endpoints
2. Data channel connects, needs TLS
3. Proxy retrieves stored session from control channel
4. OpenSslSession.CreateSessionForResumption():
   - Deserializes session with d2i_SSL_SESSION
   - Creates NEW independent session object
5. OpenSslTlsStream.Connect() with sessionToResume:
   - SSL_set_session() before handshake
   - SSL_connect() performs resumption
6. Backend validates session matches control channel
7. If resumed: IsSessionResumed = true, transfer proceeds
8. If not resumed: Backend may reject connection
```

### Why Serialization?

We serialize the session (i2d_SSL_SESSION) and deserialize for each data channel
(d2i_SSL_SESSION) instead of sharing the SSL_SESSION pointer directly because:

1. **Thread safety** - Each data channel gets its own independent session object
2. **Lifetime management** - No shared state between connections
3. **Matches libfilezilla behavior** - This is how FileZilla client does it

## Key OpenSSL Functions Used

```c
// Session capture
SSL_SESSION* SSL_get1_session(SSL* ssl);  // Get session, increments refcount

// Session serialization
int i2d_SSL_SESSION(SSL_SESSION* in, unsigned char** pp);  // Serialize
SSL_SESSION* d2i_SSL_SESSION(SSL_SESSION** a, const unsigned char** pp, long length);  // Deserialize

// Session resumption
int SSL_set_session(SSL* ssl, SSL_SESSION* session);  // Set session to resume
int SSL_session_reused(SSL* ssl);  // Check if resumption succeeded

// Lifecycle
void SSL_SESSION_free(SSL_SESSION* session);  // Decrement refcount
```

## Client-Side Session Resumption (Proxy -> Client)

The proxy also supports session resumption for clients connecting to it:

1. **OpenSslServerContext** creates a shared SSL_CTX with:
   - Session ID context set
   - Session caching enabled
   - Session timeout configured

2. All client data channels use the same SSL_CTX

3. OpenSSL automatically handles session ID-based resumption

This allows FileZilla client to resume sessions when connecting to the proxy.

## Debugging Session Resumption

### Log Messages

**Successful resumption:**
```
Data channel TLS established using OpenSSL. SessionResumed: True, Protocol: TLSv1.2, Cipher: ECDHE-RSA-AES256-GCM-SHA384
Session XXX: Data channel TLS resumed successfully using serialized session
```

**Failed resumption:**
```
TLS session resumption was requested but NOT achieved on data channel. Backend may reject the connection.
```

### Common Issues

1. **Session expired** - Sessions have a timeout (typically 300 seconds)
2. **Session cache full** - Backend may evict old sessions
3. **Cipher mismatch** - Data channel must use compatible ciphers
4. **Server configuration** - "Require TLS session resumption" must be handled

## Thread Safety

OpenSSL documentation states:
> "Only one thread may be using any given SSL object at any given time."

This is why:
1. Each connection has its own SSL object
2. We serialize/deserialize sessions instead of sharing pointers
3. Data relay is unidirectional (only one thread reads/writes at a time)

## Files Reference

| File | Purpose |
|------|---------|
| `Tls/OpenSslInterop.cs` | P/Invoke declarations |
| `Tls/OpenSslTlsStream.cs` | Client TLS with resumption |
| `Tls/OpenSslServerStream.cs` | Server TLS |
| `Tls/OpenSslServerContext.cs` | Shared context for client resumption |
| `Handlers/FtpBackendConnection.cs` | Stores control channel session |
| `DataChannel/DataChannelManager.cs` | Uses session for data channels |
