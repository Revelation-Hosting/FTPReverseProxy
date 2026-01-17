# FTP Reverse Proxy - Architecture Design

## Overview

A reverse proxy that terminates FTP/FTPS/SFTP connections and routes to backend servers based on username patterns. Connections are fully terminated at the proxy, with new connections established to backends.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            FTP Reverse Proxy                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│  │ FTP Listener│  │FTPS Listener│  │SFTP Listener│                     │
│  │   (21)      │  │  (990/21)   │  │    (22)     │                     │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                     │
│         │                │                │                             │
│         └────────────────┼────────────────┘                             │
│                          ▼                                              │
│              ┌───────────────────────┐                                  │
│              │   Connection Manager  │                                  │
│              │  (accepts, tracks)    │                                  │
│              └───────────┬───────────┘                                  │
│                          ▼                                              │
│              ┌───────────────────────┐                                  │
│              │   Protocol Handler    │                                  │
│              │  (FTP state machine)  │                                  │
│              └───────────┬───────────┘                                  │
│                          ▼                                              │
│              ┌───────────────────────┐      ┌──────────────────┐       │
│              │    Username Router    │◄────►│  Route Config    │       │
│              │ (parses, determines   │      │  (rules, maps)   │       │
│              │  backend target)      │      └──────────────────┘       │
│              └───────────┬───────────┘                                  │
│                          ▼                                              │
│              ┌───────────────────────┐      ┌──────────────────┐       │
│              │  Credential Mapper    │◄────►│ Credential Store │       │
│              │ (transforms creds)    │      │ (vault, config)  │       │
│              └───────────┬───────────┘                                  │
│                          ▼                                              │
│              ┌───────────────────────┐                                  │
│              │  Backend Connector    │                                  │
│              │ (establishes upstream)│                                  │
│              └───────────┬───────────┘                                  │
│                          ▼                                              │
│              ┌───────────────────────┐                                  │
│              │    Session Relay      │                                  │
│              │ (control + data)      │                                  │
│              └───────────────────────┘                                  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
        ┌──────────────────────────┼──────────────────────────┐
        ▼                          ▼                          ▼
┌───────────────┐        ┌───────────────┐        ┌───────────────┐
│ Backend FTP 1 │        │ Backend FTP 2 │        │ Backend FTP N │
│ (on-prem)     │        │ (cloud)       │        │ (anywhere)    │
└───────────────┘        └───────────────┘        └───────────────┘
```

## Core Components

### 1. Listeners

Each protocol needs its own listener due to fundamental protocol differences:

#### FTP Listener (Port 21)
- Plain TCP socket
- Waits for client connection
- Hands off to FTP Protocol Handler

#### FTPS Listener (Port 990 implicit, or 21 with AUTH TLS)
- Implicit: TLS handshake immediately on connect
- Explicit: Plain connection, upgrades via AUTH TLS command
- Uses SslStream for TLS termination

#### SFTP Listener (Port 22)
- SSH protocol (completely different from FTP)
- Requires SSH server implementation
- Consider SSH.NET or similar library
- Subsystem: sftp

### 2. Protocol Handlers

State machines that understand each protocol:

```
FTP Session States:
┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│Connected├───►│AwaitUser├───►│AwaitPass├───►│Authenticated│
└─────────┘    └─────────┘    └─────────┘    └─────────┘
                                                   │
                    ┌──────────────────────────────┘
                    ▼
              ┌───────────┐
              │  Active   │◄──── Normal operation
              │ (proxying)│      Commands relayed to backend
              └───────────┘
```

**Key FTP Commands to Handle Specially:**
| Command | Action |
|---------|--------|
| USER | Extract username, determine route |
| PASS | Authenticate, possibly transform credentials |
| PASV/EPSV | Intercept, set up proxy data channel |
| PORT/EPRT | Intercept, set up proxy data channel (active mode) |
| AUTH TLS | Upgrade to TLS (explicit FTPS) |
| PBSZ/PROT | Data channel protection negotiation |
| QUIT | Clean shutdown of both connections |

### 3. Username Router

Determines which backend server handles a connection.

**Routing Strategies:**

```csharp
// Pattern-based routing
public interface IRoutingStrategy
{
    BackendServer? ResolveBackend(string username, string? clientIp);
}

// Example implementations:
// 1. Suffix routing: "john@server1" -> routes to server1
// 2. Prefix routing: "server1_john" -> routes to server1
// 3. Lookup table: "john" -> configured backend
// 4. Regex matching: matches patterns to backends
// 5. Default/fallback: catch-all backend
```

**Configuration Example:**
```json
{
  "routing": {
    "rules": [
      {
        "pattern": "^(?<user>.+)@(?<backend>.+)$",
        "type": "regex",
        "backendFromCapture": "backend",
        "usernameFromCapture": "user"
      },
      {
        "pattern": "*",
        "type": "default",
        "backend": "legacy-ftp-server"
      }
    ],
    "backends": {
      "cloud-ftp": {
        "host": "ftp.cloud.internal",
        "port": 21,
        "protocol": "ftps-explicit"
      },
      "legacy-ftp-server": {
        "host": "192.168.1.50",
        "port": 21,
        "protocol": "ftp"
      }
    }
  }
}
```

### 4. Credential Mapper

Transforms credentials between client and backend:

```csharp
public interface ICredentialMapper
{
    // Returns credentials to use with backend
    Task<BackendCredentials> MapCredentialsAsync(
        string clientUsername,
        string clientPassword,
        BackendServer backend);
}

// Modes:
// 1. Passthrough - same credentials
// 2. ServiceAccount - fixed credentials per backend
// 3. Mapped - lookup table transformation
// 4. Hybrid - same user, different password
```

### 5. Data Channel Relay

The trickiest part - handling FTP's separate data connections:

```
PASSIVE MODE FLOW:

Client                    Proxy                      Backend
  │                         │                           │
  │──── PASV ──────────────►│                           │
  │                         │──── PASV ────────────────►│
  │                         │◄─── 227 (backend:port) ───│
  │                         │                           │
  │                         │ [Opens proxy data port]   │
  │                         │                           │
  │◄─── 227 (proxy:port) ───│                           │
  │                         │                           │
  │==== Data Connect ======►│                           │
  │                         │==== Data Connect ========►│
  │                         │                           │
  │◄==== Data Transfer ====►│◄==== Data Transfer ======►│
  │                         │                           │
```

**Data Channel Manager:**
```csharp
public class DataChannelManager
{
    // Maps control sessions to their pending/active data channels
    private ConcurrentDictionary<Guid, DataChannelState> _channels;

    // Called when PASV response received from backend
    public async Task<int> SetupPassiveRelayAsync(
        Guid sessionId,
        IPEndPoint backendDataEndpoint)
    {
        // 1. Open a listening port for client
        // 2. Store mapping: sessionId -> (clientListener, backendEndpoint)
        // 3. Return the port number for client
    }

    // Called when client connects to our data port
    public async Task RelayDataAsync(Guid sessionId)
    {
        // 1. Accept client connection
        // 2. Connect to backend data port
        // 3. Bidirectional relay until transfer complete
    }
}
```

### 6. Session State

Each proxied session maintains:

```csharp
public class ProxySession
{
    public Guid Id { get; }
    public SessionState State { get; set; }

    // Client side
    public Stream ClientControlStream { get; }
    public IPEndPoint ClientEndpoint { get; }
    public string? ClientUsername { get; set; }

    // Backend side
    public Stream? BackendControlStream { get; set; }
    public BackendServer? Backend { get; set; }

    // Data channel
    public DataChannelState? PendingDataChannel { get; set; }

    // TLS state
    public bool ClientTlsEnabled { get; set; }
    public bool BackendTlsEnabled { get; set; }

    // Audit/logging
    public DateTime ConnectedAt { get; }
    public List<CommandLogEntry> CommandLog { get; }
}
```

## Protocol-Specific Notes

### FTP (Plain)
- Straightforward implementation
- Commands are line-based, responses are numeric codes
- Watch for multi-line responses (e.g., 220-Welcome\n220 Ready)

### FTPS
**Implicit (Port 990):**
- TLS handshake immediately on connect
- Client and backend streams are SslStream from the start

**Explicit (AUTH TLS on Port 21):**
- Connection starts plain
- Client sends `AUTH TLS` command
- Proxy upgrades client connection to TLS
- Proxy should also upgrade backend connection
- Complexity: timing of when to upgrade backend

**Data Channel Protection:**
- `PBSZ 0` and `PROT P` commands indicate protected data channels
- Need to TLS-wrap data connections too

### SFTP
Entirely separate implementation needed:

```csharp
// Conceptually similar but different protocol
public class SftpProxyHandler
{
    // Uses SSH.NET or similar
    // 1. Accept SSH connection from client
    // 2. Authenticate (extract username for routing)
    // 3. Establish SSH connection to backend
    // 4. Relay SFTP subsystem commands
}
```

## Project Structure

```
FtpReverseProxy/
├── src/
│   ├── FtpReverseProxy.Core/
│   │   ├── Configuration/
│   │   │   ├── ProxyConfiguration.cs
│   │   │   ├── BackendServer.cs
│   │   │   └── RoutingRule.cs
│   │   ├── Routing/
│   │   │   ├── IRoutingStrategy.cs
│   │   │   ├── RegexRoutingStrategy.cs
│   │   │   └── UsernameRouter.cs
│   │   ├── Credentials/
│   │   │   ├── ICredentialMapper.cs
│   │   │   ├── PassthroughCredentialMapper.cs
│   │   │   └── MappedCredentialMapper.cs
│   │   └── Session/
│   │       ├── ProxySession.cs
│   │       └── SessionManager.cs
│   │
│   ├── FtpReverseProxy.Ftp/
│   │   ├── FtpListener.cs
│   │   ├── FtpProtocolHandler.cs
│   │   ├── FtpCommandParser.cs
│   │   ├── FtpResponseParser.cs
│   │   └── DataChannel/
│   │       ├── DataChannelManager.cs
│   │       ├── PassiveDataChannel.cs
│   │       └── ActiveDataChannel.cs
│   │
│   ├── FtpReverseProxy.Ftps/
│   │   ├── FtpsListener.cs
│   │   ├── ImplicitFtpsHandler.cs
│   │   └── ExplicitFtpsHandler.cs
│   │
│   ├── FtpReverseProxy.Sftp/
│   │   ├── SftpListener.cs
│   │   └── SftpProxyHandler.cs
│   │
│   └── FtpReverseProxy.Service/
│       ├── Program.cs
│       ├── ProxyHostedService.cs
│       └── appsettings.json
│
├── tests/
│   ├── FtpReverseProxy.Tests.Unit/
│   └── FtpReverseProxy.Tests.Integration/
│
└── FtpReverseProxy.sln
```

## Implementation Phases

### Phase 1: Basic FTP Proxy
- [ ] FTP listener accepting connections
- [ ] FTP protocol handler (state machine)
- [ ] Basic username parsing (user@backend format)
- [ ] Backend connection establishment
- [ ] Control channel relay
- [ ] Passive mode data channel relay

### Phase 2: FTPS Support
- [ ] Implicit FTPS listener
- [ ] Explicit FTPS (AUTH TLS handling)
- [ ] TLS data channel support

### Phase 3: Advanced Routing
- [ ] Configurable routing rules
- [ ] Credential mapping
- [ ] Multiple backend support

### Phase 4: SFTP Support
- [ ] SSH listener integration
- [ ] SFTP subsystem proxying
- [ ] Unified username routing

### Phase 5: Production Hardening
- [ ] Connection pooling to backends
- [ ] Health checks for backends
- [ ] Metrics and monitoring
- [ ] Graceful shutdown
- [ ] Rate limiting

## Key Libraries (C# / .NET)

| Purpose | Library |
|---------|---------|
| Async networking | System.Net.Sockets (built-in) |
| TLS/SSL | System.Net.Security.SslStream (built-in) |
| SSH/SFTP | SSH.NET (Renci.SshNet) |
| Configuration | Microsoft.Extensions.Configuration |
| DI | Microsoft.Extensions.DependencyInjection |
| Logging | Microsoft.Extensions.Logging + Serilog |
| Hosting | Microsoft.Extensions.Hosting (for service) |

## Open Questions

1. **Active mode support?**
   - Less common, more complex
   - Could defer or skip entirely

2. **Connection pooling to backends?**
   - Reuse backend connections?
   - Complexity vs performance tradeoff

3. **Protocol translation?**
   - Client speaks SFTP, backend is FTP?
   - Significant complexity, maybe out of scope

4. **IPv6 support?**
   - EPSV/EPRT vs PASV/PORT

5. **FTP over HTTP proxy (SOCKS)?**
   - Probably out of scope
