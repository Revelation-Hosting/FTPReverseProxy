namespace FtpReverseProxy.Core.Interfaces;

/// <summary>
/// Interface for collecting proxy metrics
/// </summary>
public interface IProxyMetrics
{
    /// <summary>
    /// Records a new connection being established
    /// </summary>
    void RecordConnectionOpened(string protocol, string? backendId);

    /// <summary>
    /// Records a connection being closed
    /// </summary>
    void RecordConnectionClosed(string protocol, string? backendId);

    /// <summary>
    /// Records bytes transferred
    /// </summary>
    void RecordBytesTransferred(string direction, long bytes, string? backendId);

    /// <summary>
    /// Records authentication attempt
    /// </summary>
    void RecordAuthentication(bool success, string protocol, string? backendId);

    /// <summary>
    /// Records command execution time
    /// </summary>
    void RecordCommandLatency(string command, double milliseconds);

    /// <summary>
    /// Records a data transfer operation
    /// </summary>
    void RecordDataTransfer(string operation, long bytes, double durationMs);
}
