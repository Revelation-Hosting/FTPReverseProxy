using FtpReverseProxy.Core.Configuration;
using FtpReverseProxy.Data;
using FtpReverseProxy.Ftp;
using FtpReverseProxy.Service;

var builder = Host.CreateApplicationBuilder(args);

// Bind configuration
builder.Services.Configure<ProxyConfiguration>(
    builder.Configuration.GetSection("Proxy"));

var proxyConfig = builder.Configuration
    .GetSection("Proxy")
    .Get<ProxyConfiguration>() ?? new ProxyConfiguration();

// Add data services (database and Redis)
if (!string.IsNullOrEmpty(proxyConfig.Database.ConnectionString))
{
    builder.Services.AddFtpProxyData(options =>
    {
        options.ConnectionString = proxyConfig.Database.ConnectionString;
        options.Provider = proxyConfig.Database.Provider;
        options.UseRedis = proxyConfig.Redis?.Enabled ?? false;
        options.RedisConnectionString = proxyConfig.Redis?.ConnectionString ?? "localhost:6379";
    });
}

// Add FTP services
builder.Services.AddFtpProxyServices(options =>
{
    options.MinPort = proxyConfig.DataChannel.MinPort;
    options.MaxPort = proxyConfig.DataChannel.MaxPort;
    options.ExternalAddress = proxyConfig.DataChannel.ExternalAddress;
    options.CertificatePath = proxyConfig.TlsCertificate?.Path;
    options.CertificatePassword = proxyConfig.TlsCertificate?.Password;
});

builder.Services.AddHostedService<Worker>();

var host = builder.Build();
host.Run();
