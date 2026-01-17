namespace FtpReverseProxy.Core.Models;

/// <summary>
/// Represents a parsed FTP command from a client
/// </summary>
public class FtpCommand
{
    /// <summary>
    /// The FTP command verb (e.g., USER, PASS, LIST, RETR)
    /// </summary>
    public required string Verb { get; set; }

    /// <summary>
    /// The argument(s) to the command, if any
    /// </summary>
    public string? Argument { get; set; }

    /// <summary>
    /// The raw command line as received
    /// </summary>
    public required string RawCommand { get; set; }

    /// <summary>
    /// Timestamp when command was received
    /// </summary>
    public DateTime ReceivedAt { get; } = DateTime.UtcNow;

    public override string ToString() =>
        string.IsNullOrEmpty(Argument) ? Verb : $"{Verb} {Argument}";
}
