# Installation Guide

This guide covers installation and configuration of the FTP Reverse Proxy on Windows and Linux systems.

## Prerequisites

### Required
- .NET 10 SDK or .NET 10 Runtime
- PostgreSQL 13+ or SQL Server 2019+

### Optional
- Redis 6+ (for caching)
- Docker (for containerized deployment)

## Installation Methods

### Option 1: Build from Source

#### Windows

```powershell
# Clone the repository
git clone https://github.com/yourusername/FTPReverseProxy.git
cd FTPReverseProxy

# Build the solution
dotnet build -c Release

# Publish the service
dotnet publish src/FtpReverseProxy.Service -c Release -o C:\FtpProxy

# Publish the API (optional)
dotnet publish src/FtpReverseProxy.Api -c Release -o C:\FtpProxyApi
```

#### Linux

```bash
# Clone the repository
git clone https://github.com/yourusername/FTPReverseProxy.git
cd FTPReverseProxy

# Build the solution
dotnet build -c Release

# Publish the service
dotnet publish src/FtpReverseProxy.Service -c Release -o /opt/ftpproxy

# Publish the API (optional)
dotnet publish src/FtpReverseProxy.Api -c Release -o /opt/ftpproxy-api
```

### Option 2: Docker

```bash
# Build the image
docker build -t ftpproxy .

# Run the container
docker run -d \
  --name ftpproxy \
  -p 21:21 \
  -p 990:990 \
  -p 50000-51000:50000-51000 \
  -v /path/to/config:/app/config \
  -e Proxy__Database__ConnectionString="Host=dbhost;Database=ftpproxy;..." \
  ftpproxy
```

## Database Setup

### PostgreSQL

```bash
# Create the database
psql -U postgres -c "CREATE DATABASE ftpproxy;"

# Create a dedicated user (recommended)
psql -U postgres -c "CREATE USER ftpproxy WITH PASSWORD 'your_secure_password';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE ftpproxy TO ftpproxy;"
```

### SQL Server

```sql
CREATE DATABASE ftpproxy;
GO

CREATE LOGIN ftpproxy WITH PASSWORD = 'your_secure_password';
GO

USE ftpproxy;
CREATE USER ftpproxy FOR LOGIN ftpproxy;
EXEC sp_addrolemember 'db_owner', 'ftpproxy';
GO
```

### Run Migrations

```bash
# Navigate to the data project
cd src/FtpReverseProxy.Data

# Apply migrations
dotnet ef database update --startup-project ../FtpReverseProxy.Service
```

## Configuration

### Create Configuration File

Create or edit `appsettings.json` in the service directory:

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.Hosting.Lifetime": "Information"
    }
  },
  "Proxy": {
    "Ftp": {
      "Enabled": true,
      "ListenAddress": "0.0.0.0",
      "Port": 21
    },
    "FtpsImplicit": {
      "Enabled": false,
      "ListenAddress": "0.0.0.0",
      "Port": 990
    },
    "Sftp": {
      "Enabled": false,
      "ListenAddress": "0.0.0.0",
      "Port": 22,
      "HostKeyPath": null
    },
    "DataChannel": {
      "MinPort": 50000,
      "MaxPort": 51000,
      "ExternalAddress": null
    },
    "Database": {
      "Provider": "PostgreSQL",
      "ConnectionString": "Host=localhost;Database=ftpproxy;Username=ftpproxy;Password=your_secure_password"
    },
    "Redis": {
      "Enabled": false,
      "ConnectionString": "localhost:6379",
      "CacheTtlSeconds": 300
    },
    "BackendTls": {
      "ValidationMode": "SystemDefault"
    },
    "Shutdown": {
      "DrainTimeoutSeconds": 30,
      "RejectNewConnections": true
    }
  }
}
```

### Environment Variables

Configuration can also be set via environment variables using double underscore notation:

```bash
# Database connection
export Proxy__Database__ConnectionString="Host=localhost;Database=ftpproxy;..."
export Proxy__Database__Provider="PostgreSQL"

# Redis
export Proxy__Redis__Enabled="true"
export Proxy__Redis__ConnectionString="redis:6379"

# Listeners
export Proxy__Ftp__Port="2121"
export Proxy__FtpsImplicit__Enabled="true"
```

## Enabling FTPS

### Generate or Obtain a Certificate

```bash
# Generate a self-signed certificate (development only)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Convert to PFX format
openssl pkcs12 -export -out certificate.pfx -inkey key.pem -in cert.pem
```

### Configure FTPS

```json
{
  "Proxy": {
    "FtpsImplicit": {
      "Enabled": true,
      "Port": 990
    },
    "TlsCertificate": {
      "Path": "/path/to/certificate.pfx",
      "Password": "pfx_password"
    }
  }
}
```

## Enabling SFTP

### Generate SSH Host Key

```bash
# Generate an Ed25519 key (recommended)
ssh-keygen -t ed25519 -f /etc/ftpproxy/ssh_host_ed25519_key -N ""

# Or generate an RSA key
ssh-keygen -t rsa -b 4096 -f /etc/ftpproxy/ssh_host_rsa_key -N ""
```

### Configure SFTP

```json
{
  "Proxy": {
    "Sftp": {
      "Enabled": true,
      "Port": 22,
      "HostKeyPath": "/etc/ftpproxy/ssh_host_ed25519_key"
    }
  }
}
```

## Running as a Service

### Windows Service

```powershell
# Install as a Windows service
sc.exe create FtpReverseProxy binPath= "C:\FtpProxy\FtpReverseProxy.Service.exe" start= auto

# Start the service
sc.exe start FtpReverseProxy

# Check status
sc.exe query FtpReverseProxy
```

### Linux systemd

Create `/etc/systemd/system/ftpproxy.service`:

```ini
[Unit]
Description=FTP Reverse Proxy
After=network.target postgresql.service

[Service]
Type=notify
WorkingDirectory=/opt/ftpproxy
ExecStart=/usr/bin/dotnet /opt/ftpproxy/FtpReverseProxy.Service.dll
Restart=always
RestartSec=10
User=ftpproxy
Group=ftpproxy
Environment=DOTNET_ENVIRONMENT=Production

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable ftpproxy
sudo systemctl start ftpproxy
sudo systemctl status ftpproxy
```

## Firewall Configuration

### Windows Firewall

```powershell
# FTP control port
netsh advfirewall firewall add rule name="FTP Proxy" dir=in action=allow protocol=TCP localport=21

# FTPS port
netsh advfirewall firewall add rule name="FTPS Proxy" dir=in action=allow protocol=TCP localport=990

# SFTP port
netsh advfirewall firewall add rule name="SFTP Proxy" dir=in action=allow protocol=TCP localport=22

# Passive data ports
netsh advfirewall firewall add rule name="FTP Passive" dir=in action=allow protocol=TCP localport=50000-51000
```

### Linux iptables/nftables

```bash
# Using firewalld
sudo firewall-cmd --permanent --add-port=21/tcp
sudo firewall-cmd --permanent --add-port=990/tcp
sudo firewall-cmd --permanent --add-port=22/tcp
sudo firewall-cmd --permanent --add-port=50000-51000/tcp
sudo firewall-cmd --reload

# Using ufw
sudo ufw allow 21/tcp
sudo ufw allow 990/tcp
sudo ufw allow 22/tcp
sudo ufw allow 50000:51000/tcp
```

## NAT/Port Forwarding

If the proxy is behind NAT, configure the external address:

```json
{
  "Proxy": {
    "DataChannel": {
      "ExternalAddress": "203.0.113.10"
    }
  }
}
```

This address is advertised in PASV responses to clients.

## Adding Backend Servers

Use the Management API or direct database access.

### Via API

```bash
# Start the API
cd src/FtpReverseProxy.Api
dotnet run

# Create a backend server
curl -X POST http://localhost:5000/api/backends \
  -H "Content-Type: application/json" \
  -d '{
    "id": "prod-ftp",
    "name": "Production FTP Server",
    "host": "ftp.internal.local",
    "port": 21,
    "protocol": "Ftp",
    "isEnabled": true
  }'

# Create a routing rule
curl -X POST http://localhost:5000/api/routingrules \
  -H "Content-Type: application/json" \
  -d '{
    "backendServerId": "prod-ftp",
    "matchType": "Suffix",
    "pattern": "@prod",
    "priority": 10,
    "isEnabled": true,
    "credentialMapping": {
      "mappingType": "Passthrough"
    }
  }'
```

## Verification

### Check Service Status

```bash
# Linux
sudo systemctl status ftpproxy
journalctl -u ftpproxy -f

# Windows
sc.exe query FtpReverseProxy
Get-Content C:\FtpProxy\logs\ftpproxy-*.log -Tail 50 -Wait
```

### Test FTP Connection

```bash
# Test with username routing
ftp
> open localhost 21
> user testuser@prod
> pass testpassword
> ls
> quit
```

### Check Metrics

```bash
curl http://localhost:5000/metrics
```

## Troubleshooting

### Common Issues

**Port already in use**
```bash
# Linux
sudo lsof -i :21
# Windows
netstat -ano | findstr :21
```

**Permission denied on port < 1024 (Linux)**
```bash
# Option 1: Run as root (not recommended)
# Option 2: Use setcap
sudo setcap CAP_NET_BIND_SERVICE=+eip /opt/ftpproxy/FtpReverseProxy.Service

# Option 3: Use port > 1024 and redirect with iptables
sudo iptables -t nat -A PREROUTING -p tcp --dport 21 -j REDIRECT --to-port 2121
```

**Database connection failed**
- Verify connection string
- Check database server is running
- Verify network connectivity
- Check firewall rules

**TLS handshake failed**
- Verify certificate path and password
- Check certificate is valid and not expired
- Ensure certificate includes private key

### Enable Debug Logging

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "FtpReverseProxy": "Debug"
    }
  }
}
```

## Upgrading

1. Stop the service
2. Backup configuration and database
3. Deploy new binaries
4. Run any new migrations
5. Start the service

```bash
# Linux
sudo systemctl stop ftpproxy
cp /opt/ftpproxy/appsettings.json /tmp/
# Deploy new version
cp /tmp/appsettings.json /opt/ftpproxy/
cd /path/to/source/src/FtpReverseProxy.Data
dotnet ef database update --startup-project ../FtpReverseProxy.Service
sudo systemctl start ftpproxy
```
