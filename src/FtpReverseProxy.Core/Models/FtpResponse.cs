namespace FtpReverseProxy.Core.Models;

/// <summary>
/// Represents an FTP response from the server
/// </summary>
public class FtpResponse
{
    /// <summary>
    /// The three-digit response code
    /// </summary>
    public required int Code { get; set; }

    /// <summary>
    /// The response message(s)
    /// </summary>
    public required string Message { get; set; }

    /// <summary>
    /// Whether this is a multi-line response
    /// </summary>
    public bool IsMultiLine { get; set; }

    /// <summary>
    /// The raw response as received
    /// </summary>
    public required string RawResponse { get; set; }

    /// <summary>
    /// Whether the response indicates success (2xx)
    /// </summary>
    public bool IsSuccess => Code >= 200 && Code < 300;

    /// <summary>
    /// Whether the response indicates a positive preliminary (1xx)
    /// </summary>
    public bool IsPreliminary => Code >= 100 && Code < 200;

    /// <summary>
    /// Whether the response indicates an intermediate response (3xx)
    /// </summary>
    public bool IsIntermediate => Code >= 300 && Code < 400;

    /// <summary>
    /// Whether the response indicates an error (4xx or 5xx)
    /// </summary>
    public bool IsError => Code >= 400;

    public override string ToString() => $"{Code} {Message}";
}
