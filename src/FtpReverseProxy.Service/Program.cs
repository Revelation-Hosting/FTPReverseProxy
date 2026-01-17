using FtpReverseProxy.Core.Configuration;
using FtpReverseProxy.Data;
using FtpReverseProxy.Data.Services;
using FtpReverseProxy.Ftp;
using FtpReverseProxy.Service;
using FtpReverseProxy.Sftp;
using OpenTelemetry.Metrics;
using Serilog;
using Serilog.Events;

// Configure Serilog
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Information()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
    .MinimumLevel.Override("System", LogEventLevel.Warning)
    .Enrich.FromLogContext()
    .Enrich.WithProperty("Application", "FtpReverseProxy")
    .WriteTo.Console(
        outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {SourceContext}: {Message:lj}{NewLine}{Exception}")
    .WriteTo.File(
        path: "logs/ftpproxy-.log",
        rollingInterval: RollingInterval.Day,
        retainedFileCountLimit: 30,
        outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {SourceContext} {Message:lj}{NewLine}{Exception}")
    .CreateLogger();

try
{
    Log.Information("Starting FTP Reverse Proxy");

    var builder = Host.CreateApplicationBuilder(args);
    builder.Services.AddSerilog();

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

    // Add SFTP services
    builder.Services.AddSftpProxyServices();

    builder.Services.AddHostedService<Worker>();

    // Configure OpenTelemetry metrics
    builder.Services.AddOpenTelemetry()
        .WithMetrics(metrics =>
        {
            metrics
                .AddMeter(ProxyMetrics.MeterName)
                .AddRuntimeInstrumentation()
                .AddPrometheusExporter();
        });

    var host = builder.Build();
    host.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
