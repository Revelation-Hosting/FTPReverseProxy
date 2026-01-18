# FTP Reverse Proxy

A high-performance reverse proxy for FTP, FTPS, and SFTP connections built with .NET 10. Routes connections to backend servers based on configurable username patterns with full protocol termination and credential mapping.

**Perfect for consolidating FTP infrastructure** from multiple domains, acquisitions, or data centers into a single entry point while maintaining separate backend servers.

## Key Features

### Multi-Domain SNI Support (NEW)

Consolidate multiple FTP domains behind a single proxy with **SNI-based certificate selection**:

```
ftp.companya.com  ─┐
ftp.companyb.org  ─┼─► FTP Reverse Proxy ─┬─► Backend Server A
ftp.companyc.net  ─┘   (single IP)        ├─► Backend Server B
                                          └─► Backend Server C
```

- **One proxy, multiple domains** - Each domain gets its own TLS certificate
- **Seamless acquisitions** - Add new company domains without infrastructure changes
- **Zero client changes** - Clients connect to their familiar hostnames
- **Per-backend certificates** - Configure different certificates for different backends

### Core Features

- **Multi-Protocol Support**: FTP (port 21), FTPS Implicit (port 990), and SFTP (port 22)
- **Username-Based Routing**: Route connections to different backends based on username patterns
  - Suffix format: `user@backend`
  - Prefix format: `backend_user`
  - Domain format: `user@domain.com`
  - Direct lookup by username
- **Credential Mapping**: Transform credentials between client and backend
  - Passthrough (same credentials)
  - Service account (fixed credentials per backend)
  - Mapped credentials (lookup table)
- **TLS/SSL Support**: Full FTPS support with configurable certificate validation
- **TLS Session Resumption**: Automatic session resumption for FTPS data channels (required by many FTP servers)
- **Data Channel Proxying**: Transparent handling of PASV/EPSV passive mode connections
- **Database Storage**: PostgreSQL or SQL Server for routing rules and backend configuration
- **Optional Redis Caching**: High-performance caching for route lookups
- **OpenTelemetry Metrics**: Prometheus-compatible metrics endpoint
- **Graceful Shutdown**: Configurable drain period for active sessions

## Use Cases

### Consolidate Acquired Companies
After acquiring companies, each with their own FTP servers (`ftp.acquired1.com`, `ftp.acquired2.net`), route all traffic through one proxy while keeping existing client configurations working.

### Cloud Migration
Abstract backend FTP servers during migration from on-premises to cloud. Move backends transparently without client changes.

### Multi-Tenant Hosting
Provide branded FTP endpoints (`ftp.client1.com`, `ftp.client2.com`) that all route through your infrastructure with proper certificate handling.

### Load Distribution
Route different usernames or patterns to different backend servers for load distribution or data segregation.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            FTP Reverse Proxy                            │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                      │
│  │ FTP Listener│  │FTPS Listener│  │SFTP Listener│                      │
│  │   (21)      │  │   (990)     │  │    (22)     │                      │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                      │
│         └────────────────┼────────────────┘                             │
│                          ▼                                              │
│              ┌───────────────────────┐      ┌──────────────────┐        │
│              │    Username Router    │◄────►│  Route Config    │        │
│              └───────────┬───────────┘      │  (PostgreSQL/    │        │
│                          │                  │   SQL Server)    │        │
│              ┌───────────▼───────────┐      └──────────────────┘        │
│              │  Credential Mapper    │                                  │
│              └───────────┬───────────┘                                  │
│                          ▼                                              │
│              ┌───────────────────────┐                                  │
│              │    Session Relay      │                                  │
│              │ (control + data)      │                                  │
│              └───────────────────────┘                                  │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
        ┌──────────────────────────┼──────────────────────────┐
        ▼                          ▼                          ▼
┌───────────────┐          ┌───────────────┐          ┌───────────────┐
│ Backend FTP 1 │          │ Backend FTP 2 │          │ Backend FTP N │
└───────────────┘          └───────────────┘          └───────────────┘
```

## Requirements

- .NET 10 SDK or later
- PostgreSQL 13+ or SQL Server 2019+ (for persistent configuration)
- Redis 6+ (optional, for caching)

## Quick Start

### 1. Clone and Build

```bash
git clone https://github.com/yourusername/FTPReverseProxy.git
cd FTPReverseProxy
dotnet build
```

### 2. Configure Database

Update `appsettings.json` with your database connection:

```json
{
  "Proxy": {
    "Database": {
      "Provider": "PostgreSQL",
      "ConnectionString": "Host=localhost;Database=ftpproxy;Username=postgres;Password=yourpassword"
    }
  }
}
```

### 3. Run Migrations

```bash
cd src/FtpReverseProxy.Data
dotnet ef database update --startup-project ../FtpReverseProxy.Service
```

### 4. Start the Proxy

```bash
cd src/FtpReverseProxy.Service
dotnet run
```

## Multi-Domain Setup

This section explains how to configure the proxy to handle multiple domains with their own TLS certificates.

### How SNI Works

When a client connects via FTPS, the TLS handshake includes the hostname they're connecting to (Server Name Indication). The proxy uses this to select the appropriate certificate:

```
1. Client connects to ftp.companya.com:990
2. TLS handshake includes SNI: "ftp.companya.com"
3. Proxy looks up certificate for that hostname
4. Proxy presents Company A's certificate
5. Client validates certificate, connection proceeds
6. Username determines which backend to route to
```

### Step-by-Step Setup

#### 1. Prepare Your Certificates

Convert your certificates to PFX format if needed:

```bash
# From PEM files
openssl pkcs12 -export -out companya.pfx -inkey companya.key -in companya.crt -certfile ca-chain.crt

# From existing PFX, just copy it
cp /path/to/companya.pfx ./certs/
```

#### 2. Mount Certificates in Docker

```yaml
# docker-compose.yml
services:
  ftp-proxy:
    volumes:
      - ./certs:/app/certs:ro
```

#### 3. Configure Backends with Certificates

```bash
# Create backend for Company A
curl -X POST http://localhost:8080/api/backends \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Company A FTP",
    "host": "10.0.1.50",
    "port": 21,
    "protocol": 1,
    "clientFacingHostnames": "ftp.companya.com,sftp.companya.com",
    "clientCertificatePath": "/app/certs/companya.pfx",
    "clientCertificatePassword": "password1",
    "isEnabled": true
  }'

# Create backend for Company B
curl -X POST http://localhost:8080/api/backends \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Company B FTP",
    "host": "10.0.2.50",
    "port": 21,
    "protocol": 1,
    "clientFacingHostnames": "ftp.companyb.org",
    "clientCertificatePath": "/app/certs/companyb.pfx",
    "clientCertificatePassword": "password2",
    "isEnabled": true
  }'
```

#### 4. Create Route Mappings

```bash
# Route users to appropriate backends
curl -X POST http://localhost:8080/api/routes \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "backendServerId": "company-a-backend-id",
    "isEnabled": true
  }'
```

#### 5. Update DNS

Point all your domain DNS records to the proxy's IP address:

```
ftp.companya.com    A    203.0.113.10
ftp.companyb.org    A    203.0.113.10
ftp.companyc.net    A    203.0.113.10
```

### SFTP Considerations

SFTP uses SSH, which doesn't support SNI. For multi-domain SFTP:

- **Single host key** - All domains share one SSH host key
- **Document the fingerprint** - Tell users to accept the proxy's host key
- **Routing still works** - Username-based routing functions normally

## Configuration

### Full Configuration Example

```json
{
  "Proxy": {
    "Ftp": {
      "Enabled": true,
      "ListenAddress": "0.0.0.0",
      "Port": 21
    },
    "FtpsImplicit": {
      "Enabled": true,
      "ListenAddress": "0.0.0.0",
      "Port": 990
    },
    "Sftp": {
      "Enabled": true,
      "ListenAddress": "0.0.0.0",
      "Port": 22,
      "HostKeyPath": "/path/to/ssh_host_key",
      "HostKeyPassword": null
    },
    "DataChannel": {
      "MinPort": 50000,
      "MaxPort": 51000,
      "ExternalAddress": "203.0.113.10"
    },
    "TlsCertificate": {
      "Path": "/path/to/certificate.pfx",
      "Password": "certpassword"
    },
    "Database": {
      "Provider": "PostgreSQL",
      "ConnectionString": "Host=localhost;Database=ftpproxy;Username=postgres;Password=yourpassword"
    },
    "Redis": {
      "Enabled": true,
      "ConnectionString": "localhost:6379",
      "CacheTtlSeconds": 300
    },
    "BackendTls": {
      "ValidationMode": "SystemDefault",
      "AllowExpired": false,
      "AllowNameMismatch": false,
      "TrustedCertificatesPath": null,
      "TrustedThumbprints": []
    },
    "Shutdown": {
      "DrainTimeoutSeconds": 30,
      "RejectNewConnections": true
    }
  }
}
```

### Configuration Options

| Section | Option | Description | Default |
|---------|--------|-------------|---------|
| Ftp | Enabled | Enable FTP listener | true |
| Ftp | ListenAddress | IP to bind to | 0.0.0.0 |
| Ftp | Port | FTP port | 21 |
| FtpsImplicit | Enabled | Enable implicit FTPS | false |
| FtpsImplicit | Port | FTPS port | 990 |
| Sftp | Enabled | Enable SFTP listener | false |
| Sftp | HostKeyPath | Path to SSH host key | null |
| DataChannel | MinPort | Minimum passive port | 50000 |
| DataChannel | MaxPort | Maximum passive port | 51000 |
| DataChannel | ExternalAddress | Public IP for NAT | null |
| Database | Provider | PostgreSQL or SqlServer | PostgreSQL |
| Redis | Enabled | Enable Redis caching | false |
| Redis | CacheTtlSeconds | Cache TTL | 300 |
| BackendTls | ValidationMode | Certificate validation mode | SystemDefault |
| Shutdown | DrainTimeoutSeconds | Graceful shutdown timeout | 30 |

### Backend TLS Validation Modes

- `SystemDefault`: Use system certificate store (recommended for production)
- `AcceptAll`: Accept any certificate (development only)
- `TrustedThumbprintsOnly`: Only accept certificates matching configured thumbprints
- `Custom`: Custom validation with configurable options

### TLS Session Resumption for FTPS Backends

Many FTPS servers (including FileZilla Server, vsftpd, and others) enforce a security requirement that the TLS session on the data channel must be a resumption of the control channel's TLS session. This prevents man-in-the-middle attacks on the data channel.

**The Problem for Proxies**

When an FTP proxy sits between client and server, it terminates TLS on both sides:
- Client <--TLS--> Proxy <--TLS--> Backend

This means the proxy establishes its own TLS sessions with the backend. Without proper session resumption, the backend will reject data channel connections with errors like:

```
450 TLS session of data connection has not resumed or the session does not match the control connection
```

**How This Proxy Handles It**

The proxy automatically handles TLS session resumption by:

1. Storing the TLS session parameters from the control channel connection
2. Reusing the same `SslClientAuthenticationOptions` (including `TargetHost`) for data channel connections
3. Leveraging .NET's built-in TLS session cache to resume sessions

This is completely transparent - no configuration required. The proxy will work with backends that require session resumption without any changes to the backend server settings.

**Compatibility**

This feature ensures compatibility with:
- FileZilla Server (requires session resumption by default)
- vsftpd with `require_ssl_reuse=YES`
- ProFTPD with `TLSOptions RequireValidClientCert`
- Any FTPS server enforcing RFC 4217 session resumption recommendations

## Management API

The proxy includes a REST API for managing backends and routing rules.

### Backend Servers

```bash
# List all backends
GET /api/backends

# Create a backend with SNI certificate support
POST /api/backends
{
  "name": "Company A FTP",
  "host": "10.0.1.50",
  "port": 21,
  "protocol": "FtpsExplicit",
  "isEnabled": true,
  "clientFacingHostnames": "ftp.companya.com,sftp.companya.com",
  "clientCertificatePath": "/app/certs/companya.pfx",
  "clientCertificatePassword": "cert-password"
}

# Update a backend
PUT /api/backends/{id}

# Delete a backend
DELETE /api/backends/{id}
```

### Backend Server Fields

| Field | Description |
|-------|-------------|
| `name` | Display name for this backend |
| `host` | Hostname or IP of the backend server |
| `port` | Port number (default: 21) |
| `protocol` | `Ftp`, `FtpsExplicit`, `FtpsImplicit`, or `Sftp` |
| `credentialMapping` | `Passthrough`, `ServiceAccount`, or `Mapped` |
| `clientFacingHostnames` | Comma-separated hostnames for SNI certificate selection |
| `clientCertificatePath` | Path to PFX certificate for these hostnames |
| `clientCertificatePassword` | Password for the certificate file |
| `maxConnections` | Max concurrent connections (0 = unlimited) |

### Route Mappings

```bash
# List all routes
GET /api/routes

# Create a route mapping
POST /api/routes
{
  "username": "john@prod",
  "backendServerId": "your-backend-id",
  "backendUsername": "john",
  "isEnabled": true,
  "priority": 100,
  "description": "Route for john to production"
}

# Lookup route for a username
GET /api/routes/lookup/{username}

# Update a route
PUT /api/routes/{id}

# Delete a route
DELETE /api/routes/{id}
```

### Route Mapping Fields

- `username`: The FTP username to match (exact match)
- `backendServerId`: ID of the target backend server
- `backendUsername`: (Optional) Username to use when connecting to backend
- `backendPassword`: (Optional) Password to use when connecting to backend
- `priority`: Lower values = higher priority (default: 100)
- `isEnabled`: Whether this route is active

## Metrics

Prometheus metrics are exposed at `/metrics` when the API is running.

Available metrics:
- `ftp_proxy_active_sessions`: Current number of active sessions
- `ftp_proxy_total_connections`: Total connections received
- `ftp_proxy_bytes_transferred`: Total bytes transferred
- `ftp_proxy_command_duration_seconds`: Command processing duration

## Project Structure

```
FtpReverseProxy/
├── src/
│   ├── FtpReverseProxy.Core/      # Core abstractions and models
│   ├── FtpReverseProxy.Data/      # Entity Framework, database access
│   ├── FtpReverseProxy.Ftp/       # FTP/FTPS protocol implementation
│   ├── FtpReverseProxy.Sftp/      # SFTP protocol implementation
│   ├── FtpReverseProxy.Service/   # Windows/Linux service host
│   └── FtpReverseProxy.Api/       # Management REST API
├── tests/
│   ├── FtpReverseProxy.Tests.Unit/
│   └── FtpReverseProxy.Tests.Integration/
├── ARCHITECTURE.md
└── README.md
```

## Running Tests

```bash
# Run all tests
dotnet test

# Run unit tests only
dotnet test tests/FtpReverseProxy.Tests.Unit

# Run with coverage
dotnet test --collect:"XPlat Code Coverage"
```

## Docker

Quick start with Docker Compose:

```bash
# Start all services
docker-compose up -d

# Check logs
docker logs -f ftp-reverse-proxy

# Rebuild after code changes
docker-compose down && docker-compose build --no-cache ftp-proxy && docker-compose up -d
```

For comprehensive Docker instructions including configuration, rebuilding, and troubleshooting, see **[docs/DOCKER.md](docs/DOCKER.md)**.

## Security Considerations

- **TLS Certificates**: Always use valid TLS certificates in production
- **Backend Validation**: Use `SystemDefault` or `TrustedThumbprintsOnly` for backend TLS validation
- **TLS Session Resumption**: The proxy automatically handles TLS session resumption for data channels, ensuring compatibility with security-hardened FTPS servers
- **Firewall**: Restrict access to management API and passive port range
- **Credentials**: Store sensitive configuration in environment variables or a secrets manager

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
