# Build stage
FROM mcr.microsoft.com/dotnet/sdk:10.0-preview AS build
WORKDIR /src

# Copy solution and project files
COPY FtpReverseProxy.sln .
COPY src/FtpReverseProxy.Core/*.csproj src/FtpReverseProxy.Core/
COPY src/FtpReverseProxy.Data/*.csproj src/FtpReverseProxy.Data/
COPY src/FtpReverseProxy.Ftp/*.csproj src/FtpReverseProxy.Ftp/
COPY src/FtpReverseProxy.Sftp/*.csproj src/FtpReverseProxy.Sftp/
COPY src/FtpReverseProxy.Service/*.csproj src/FtpReverseProxy.Service/
COPY src/FtpReverseProxy.Api/*.csproj src/FtpReverseProxy.Api/

# Restore dependencies
RUN dotnet restore src/FtpReverseProxy.Service/FtpReverseProxy.Service.csproj

# Copy source code
COPY src/ src/

# Build and publish
RUN dotnet publish src/FtpReverseProxy.Service/FtpReverseProxy.Service.csproj \
    -c Release \
    -o /app/publish \
    --no-restore

# Runtime stage
FROM mcr.microsoft.com/dotnet/aspnet:10.0-preview AS runtime
WORKDIR /app

# Install OpenSSL runtime libraries (required for native TLS session resumption)
# and useful network debugging tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/lib/x86_64-linux-gnu/libssl.so.3 /usr/lib/x86_64-linux-gnu/libssl.so \
    && ln -sf /usr/lib/x86_64-linux-gnu/libcrypto.so.3 /usr/lib/x86_64-linux-gnu/libcrypto.so

# Copy published application
COPY --from=build /app/publish .

# Create directories for certificates and configuration
RUN mkdir -p /app/certs /app/config

# Expose ports
# FTP control
EXPOSE 21
# FTPS implicit
EXPOSE 990
# SFTP
EXPOSE 22
# Data channel port range
EXPOSE 50000-51000

# Set environment variables for configuration
ENV DOTNET_ENVIRONMENT=Production
ENV Proxy__Ftp__ListenAddress=0.0.0.0
ENV Proxy__Ftp__Port=21
ENV Proxy__FtpsImplicit__ListenAddress=0.0.0.0
ENV Proxy__FtpsImplicit__Port=990
ENV Proxy__Sftp__ListenAddress=0.0.0.0
ENV Proxy__Sftp__Port=22

# Run as non-root user for security (requires NET_BIND_SERVICE capability for ports < 1024)
# Uncomment these lines if running with higher ports or with proper capabilities
# RUN adduser --disabled-password --gecos '' appuser
# USER appuser

ENTRYPOINT ["dotnet", "FtpReverseProxy.Service.dll"]
