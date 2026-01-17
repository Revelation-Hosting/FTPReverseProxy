# FTP Reverse Proxy

A high-performance reverse proxy for FTP, FTPS, and SFTP connections built with .NET 10. Routes connections to backend servers based on configurable username patterns with full protocol termination and credential mapping.

## Features

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
- **Data Channel Proxying**: Transparent handling of PASV/EPSV passive mode connections
- **Database Storage**: PostgreSQL or SQL Server for routing rules and backend configuration
- **Optional Redis Caching**: High-performance caching for route lookups
- **OpenTelemetry Metrics**: Prometheus-compatible metrics endpoint
- **Graceful Shutdown**: Configurable drain period for active sessions

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                            FTP Reverse Proxy                            │
├─────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                     │
│  │ FTP Listener│  │FTPS Listener│  │SFTP Listener│                     │
│  │   (21)      │  │   (990)     │  │    (22)     │                     │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘                     │
│         └────────────────┼────────────────┘                             │
│                          ▼                                              │
│              ┌───────────────────────┐      ┌──────────────────┐       │
│              │    Username Router    │◄────►│  Route Config    │       │
│              └───────────┬───────────┘      │  (PostgreSQL/    │       │
│                          │                  │   SQL Server)    │       │
│              ┌───────────▼───────────┐      └──────────────────┘       │
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
┌───────────────┐        ┌───────────────┐        ┌───────────────┐
│ Backend FTP 1 │        │ Backend FTP 2 │        │ Backend FTP N │
└───────────────┘        └───────────────┘        └───────────────┘
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

## Management API

The proxy includes a REST API for managing backends and routing rules.

### Backend Servers

```bash
# List all backends
GET /api/backends

# Create a backend
POST /api/backends
{
  "name": "Production FTP",
  "host": "ftp.internal.local",
  "port": 21,
  "protocol": "Ftp",
  "isEnabled": true
}

# Update a backend
PUT /api/backends/{id}

# Delete a backend
DELETE /api/backends/{id}
```

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

```dockerfile
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app
EXPOSE 21 990 22 50000-51000

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish src/FtpReverseProxy.Service -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "FtpReverseProxy.Service.dll"]
```

## Security Considerations

- **TLS Certificates**: Always use valid TLS certificates in production
- **Backend Validation**: Use `SystemDefault` or `TrustedThumbprintsOnly` for backend TLS validation
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
