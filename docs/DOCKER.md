# Docker Deployment Guide

This guide covers deploying and managing the FTP Reverse Proxy using Docker.

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running
- Docker Compose (included with Docker Desktop)

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/FTPReverseProxy.git
cd FTPReverseProxy
```

### 2. Start the Services

```bash
docker-compose up -d
```

This starts:
- **ftp-reverse-proxy** - The FTP proxy service (port 21)
- **ftp-proxy-api** - Management REST API (port 8080)
- **ftp-proxy-postgres** - PostgreSQL database
- **ftp-proxy-redis** - Redis cache

### 3. Verify Services are Running

```bash
docker-compose ps
```

Check the proxy logs:
```bash
docker logs -f ftp-reverse-proxy
```

Check the API health:
```bash
curl http://localhost:8080/health
```

## Managing the Services

### Stop All Services

```bash
docker-compose down
```

### Stop Services and Remove Data Volumes

```bash
docker-compose down -v
```

### Restart a Specific Service

```bash
docker-compose restart ftp-proxy
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker logs -f ftp-reverse-proxy
docker logs -f ftp-proxy-api
```

## Rebuilding After Code Changes

When you make changes to the source code, you need to rebuild the Docker images.

### Rebuild and Restart (Recommended)

```bash
# Stop services
docker-compose down

# Rebuild with no cache (ensures fresh build)
docker-compose build --no-cache ftp-proxy

# Start services
docker-compose up -d

# Verify with logs
docker logs -f ftp-reverse-proxy
```

### Quick Rebuild (Single Command)

```bash
docker-compose down && docker-compose build --no-cache ftp-proxy && docker-compose up -d
```

### Rebuild All Services

```bash
docker-compose down && docker-compose build --no-cache && docker-compose up -d
```

## Configuration

### Environment Variables

The proxy is configured via environment variables in `docker-compose.yml`. Key settings:

| Variable | Description | Default |
|----------|-------------|---------|
| `Proxy__Ftp__Enabled` | Enable FTP listener | `true` |
| `Proxy__Ftp__Port` | FTP listen port | `21` |
| `Proxy__FtpsImplicit__Enabled` | Enable implicit FTPS | `false` |
| `Proxy__Sftp__Enabled` | Enable SFTP | `false` |
| `Proxy__DataChannel__MinPort` | Passive mode min port | `50000` |
| `Proxy__DataChannel__MaxPort` | Passive mode max port | `51000` |
| `Proxy__DataChannel__ExternalAddress` | Public IP for NAT | (none) |
| `Proxy__Redis__Enabled` | Enable Redis caching | `true` |

### TLS Certificates

For FTPS support, mount your certificate:

1. Place your `.pfx` certificate in the `./certs` directory
2. Update `docker-compose.yml`:
   ```yaml
   environment:
     - Proxy__TlsCertificate__Path=/app/certs/your-cert.pfx
     - Proxy__TlsCertificate__Password=your-password
     - Proxy__FtpsImplicit__Enabled=true
   ports:
     - "990:990"  # Uncomment FTPS port
   ```

### External IP (NAT/Firewall)

If the proxy is behind NAT, set the external IP for passive mode:

```yaml
environment:
  - Proxy__DataChannel__ExternalAddress=YOUR_PUBLIC_IP
```

## Multi-Domain Setup (SNI)

The proxy supports multiple domains with different TLS certificates using SNI (Server Name Indication). This is ideal for consolidating FTP infrastructure from multiple acquired companies or providing multi-tenant hosting.

### How It Works

```
ftp.companya.com  ─┐
ftp.companyb.org  ─┼─► Single Proxy IP ─┬─► Backend A (10.0.1.50)
ftp.companyc.net  ─┘                    ├─► Backend B (10.0.2.50)
                                        └─► Backend C (10.0.3.50)
```

Each domain gets its own certificate. When clients connect, the proxy presents the correct certificate based on the hostname they used.

### Setup Steps

#### 1. Prepare Certificates

Place PFX certificates in the `./certs` directory:

```bash
mkdir -p certs
cp /path/to/companya.pfx certs/
cp /path/to/companyb.pfx certs/
```

#### 2. Mount Certificates in Docker

The `docker-compose.yml` already mounts the certs directory:

```yaml
volumes:
  - ./certs:/app/certs:ro
```

#### 3. Create Backends with Certificates

```bash
# Backend for Company A
curl -X POST http://localhost:8080/api/backends \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Company A FTP",
    "host": "10.0.1.50",
    "port": 21,
    "protocol": 1,
    "clientFacingHostnames": "ftp.companya.com",
    "clientCertificatePath": "/app/certs/companya.pfx",
    "clientCertificatePassword": "password1",
    "isEnabled": true
  }'

# Backend for Company B
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

#### 4. Point DNS to Proxy

Update DNS records to point all domains to the proxy's IP:

```
ftp.companya.com    A    YOUR_PROXY_IP
ftp.companyb.org    A    YOUR_PROXY_IP
```

### Multi-Domain Backend Fields

| Field | Description |
|-------|-------------|
| `clientFacingHostnames` | Comma-separated hostnames (e.g., `ftp.company.com,sftp.company.com`) |
| `clientCertificatePath` | Path to PFX certificate inside container |
| `clientCertificatePassword` | Password for the PFX file |

## Managing Backends via API

### List All Backends

```bash
curl http://localhost:8080/api/backends
```

PowerShell:
```powershell
Invoke-RestMethod -Uri "http://localhost:8080/api/backends" | ConvertTo-Json -Depth 3
```

### Create a Backend

```bash
curl -X POST http://localhost:8080/api/backends \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My FTP Server",
    "host": "ftp.example.com",
    "port": 21,
    "protocol": 1,
    "credentialMapping": 0,
    "isEnabled": true,
    "clientFacingHostnames": "ftp.mydomain.com",
    "clientCertificatePath": "/app/certs/mydomain.pfx",
    "clientCertificatePassword": "cert-password"
  }'
```

Protocol values:
- `0` = FTP (plain, unencrypted)
- `1` = FtpsExplicit (AUTH TLS)
- `2` = FtpsImplicit (TLS from start)
- `3` = Sftp

SNI Certificate fields (optional):
- `clientFacingHostnames` = Hostnames for SNI matching (comma-separated)
- `clientCertificatePath` = Path to PFX certificate
- `clientCertificatePassword` = Certificate password

### Update a Backend

```bash
curl -X PUT http://localhost:8080/api/backends/{id} \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My FTP Server",
    "host": "ftp.example.com",
    "port": 21,
    "protocol": 1,
    "credentialMapping": 0,
    "isEnabled": true,
    "connectionTimeoutMs": 30000,
    "maxConnections": 0,
    "clientFacingHostnames": "ftp.mydomain.com,sftp.mydomain.com",
    "clientCertificatePath": "/app/certs/mydomain.pfx",
    "clientCertificatePassword": "cert-password"
  }'
```

### Delete a Backend

```bash
curl -X DELETE http://localhost:8080/api/backends/{id}
```

## Managing Routes via API

### List All Routes

```bash
curl http://localhost:8080/api/routes
```

### Create a Route

```bash
curl -X POST http://localhost:8080/api/routes \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john@prod",
    "backendServerId": "your-backend-id",
    "isEnabled": true,
    "priority": 100
  }'
```

### Lookup Route for Username

```bash
curl http://localhost:8080/api/routes/lookup/john@prod
```

## Troubleshooting

### Container Won't Start

Check logs for errors:
```bash
docker logs ftp-reverse-proxy
docker logs ftp-proxy-api
```

### Database Connection Issues

Ensure PostgreSQL is healthy:
```bash
docker-compose ps postgres
docker logs ftp-proxy-postgres
```

### Port Conflicts

If port 21 is already in use:
```yaml
# In docker-compose.yml, change the port mapping
ports:
  - "2121:21"  # Use port 2121 externally
```

### Reset Everything

To completely reset and start fresh:
```bash
docker-compose down -v
docker-compose up -d
```

## Production Considerations

1. **Change default passwords** in `docker-compose.yml`
2. **Use TLS certificates** for FTPS
3. **Set external IP** if behind NAT
4. **Restrict API access** - don't expose port 8080 publicly
5. **Back up PostgreSQL data** regularly
6. **Monitor logs** for authentication failures

## Useful Commands Reference

| Task | Command |
|------|---------|
| Start services | `docker-compose up -d` |
| Stop services | `docker-compose down` |
| View logs | `docker logs -f ftp-reverse-proxy` |
| Rebuild proxy | `docker-compose build --no-cache ftp-proxy` |
| Rebuild all | `docker-compose build --no-cache` |
| Check status | `docker-compose ps` |
| Shell into container | `docker exec -it ftp-reverse-proxy /bin/sh` |
| Reset everything | `docker-compose down -v && docker-compose up -d` |
