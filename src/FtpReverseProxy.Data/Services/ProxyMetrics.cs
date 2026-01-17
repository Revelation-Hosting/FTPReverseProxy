using System.Diagnostics.Metrics;
using FtpReverseProxy.Core.Interfaces;

namespace FtpReverseProxy.Data.Services;

/// <summary>
/// OpenTelemetry-compatible metrics implementation
/// </summary>
public class ProxyMetrics : IProxyMetrics
{
    public const string MeterName = "FtpReverseProxy";

    private readonly Counter<long> _connectionsOpened;
    private readonly Counter<long> _connectionsClosed;
    private readonly Counter<long> _bytesTransferred;
    private readonly Counter<long> _authAttempts;
    private readonly Counter<long> _authFailures;
    private readonly Histogram<double> _commandLatency;
    private readonly Histogram<double> _dataTransferDuration;
    private readonly Counter<long> _dataTransferBytes;
    private readonly UpDownCounter<long> _activeConnections;

    public ProxyMetrics(IMeterFactory meterFactory)
    {
        var meter = meterFactory.Create(MeterName);

        _connectionsOpened = meter.CreateCounter<long>(
            "ftpproxy.connections.opened",
            "connections",
            "Total connections opened");

        _connectionsClosed = meter.CreateCounter<long>(
            "ftpproxy.connections.closed",
            "connections",
            "Total connections closed");

        _activeConnections = meter.CreateUpDownCounter<long>(
            "ftpproxy.connections.active",
            "connections",
            "Current active connections");

        _bytesTransferred = meter.CreateCounter<long>(
            "ftpproxy.bytes.transferred",
            "bytes",
            "Total bytes transferred");

        _authAttempts = meter.CreateCounter<long>(
            "ftpproxy.auth.attempts",
            "attempts",
            "Total authentication attempts");

        _authFailures = meter.CreateCounter<long>(
            "ftpproxy.auth.failures",
            "failures",
            "Total authentication failures");

        _commandLatency = meter.CreateHistogram<double>(
            "ftpproxy.command.latency",
            "ms",
            "Command execution latency");

        _dataTransferDuration = meter.CreateHistogram<double>(
            "ftpproxy.datatransfer.duration",
            "ms",
            "Data transfer duration");

        _dataTransferBytes = meter.CreateCounter<long>(
            "ftpproxy.datatransfer.bytes",
            "bytes",
            "Data transfer bytes");
    }

    public void RecordConnectionOpened(string protocol, string? backendId)
    {
        var tags = CreateTags(protocol, backendId);
        _connectionsOpened.Add(1, tags);
        _activeConnections.Add(1, tags);
    }

    public void RecordConnectionClosed(string protocol, string? backendId)
    {
        var tags = CreateTags(protocol, backendId);
        _connectionsClosed.Add(1, tags);
        _activeConnections.Add(-1, tags);
    }

    public void RecordBytesTransferred(string direction, long bytes, string? backendId)
    {
        _bytesTransferred.Add(bytes,
            new KeyValuePair<string, object?>("direction", direction),
            new KeyValuePair<string, object?>("backend_id", backendId ?? "unknown"));
    }

    public void RecordAuthentication(bool success, string protocol, string? backendId)
    {
        var tags = CreateTags(protocol, backendId);
        _authAttempts.Add(1, tags);

        if (!success)
        {
            _authFailures.Add(1, tags);
        }
    }

    public void RecordCommandLatency(string command, double milliseconds)
    {
        _commandLatency.Record(milliseconds,
            new KeyValuePair<string, object?>("command", command));
    }

    public void RecordDataTransfer(string operation, long bytes, double durationMs)
    {
        var tags = new[]
        {
            new KeyValuePair<string, object?>("operation", operation)
        };

        _dataTransferBytes.Add(bytes, tags);
        _dataTransferDuration.Record(durationMs, tags);
    }

    private static KeyValuePair<string, object?>[] CreateTags(string protocol, string? backendId)
    {
        return
        [
            new("protocol", protocol),
            new("backend_id", backendId ?? "unknown")
        ];
    }
}
