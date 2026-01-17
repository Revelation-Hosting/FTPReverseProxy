using System.Text;
using FtpReverseProxy.Core.Models;

namespace FtpReverseProxy.Ftp.Parsing;

/// <summary>
/// Parses FTP responses from server output
/// </summary>
public static class FtpResponseParser
{
    /// <summary>
    /// Parses FTP response lines into an FtpResponse object
    /// Handles both single-line and multi-line responses
    /// </summary>
    /// <param name="lines">The response lines (without CRLF)</param>
    /// <returns>The parsed response</returns>
    public static FtpResponse Parse(IReadOnlyList<string> lines)
    {
        if (lines.Count == 0)
        {
            return new FtpResponse
            {
                Code = 0,
                Message = string.Empty,
                IsMultiLine = false,
                RawResponse = string.Empty
            };
        }

        var firstLine = lines[0];

        if (firstLine.Length < 3 || !int.TryParse(firstLine[..3], out var code))
        {
            return new FtpResponse
            {
                Code = 0,
                Message = firstLine,
                IsMultiLine = false,
                RawResponse = string.Join("\r\n", lines)
            };
        }

        var isMultiLine = lines.Count > 1 || (firstLine.Length > 3 && firstLine[3] == '-');

        var messageBuilder = new StringBuilder();
        foreach (var line in lines)
        {
            if (line.Length > 4)
            {
                messageBuilder.AppendLine(line[4..]);
            }
            else if (line.Length > 3)
            {
                messageBuilder.AppendLine(line[4..]);
            }
        }

        return new FtpResponse
        {
            Code = code,
            Message = messageBuilder.ToString().TrimEnd(),
            IsMultiLine = isMultiLine,
            RawResponse = string.Join("\r\n", lines)
        };
    }

    /// <summary>
    /// Parses a single FTP response line
    /// </summary>
    /// <param name="line">The response line</param>
    /// <returns>The parsed response</returns>
    public static FtpResponse ParseLine(string line)
    {
        return Parse([line]);
    }

    /// <summary>
    /// Determines if a response line indicates more lines follow (multi-line response)
    /// </summary>
    /// <param name="line">The response line</param>
    /// <returns>True if more lines expected</returns>
    public static bool IsMultiLineStart(string line)
    {
        return line.Length > 3 && line[3] == '-';
    }

    /// <summary>
    /// Determines if a response line is the final line of a multi-line response
    /// </summary>
    /// <param name="line">The response line</param>
    /// <param name="expectedCode">The code from the first line</param>
    /// <returns>True if this is the final line</returns>
    public static bool IsMultiLineEnd(string line, int expectedCode)
    {
        if (line.Length < 4) return false;

        if (!int.TryParse(line[..3], out var code)) return false;

        return code == expectedCode && line[3] == ' ';
    }

    /// <summary>
    /// Parses the IP and port from a PASV (227) response
    /// Format: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
    /// </summary>
    public static (string? Host, int Port) ParsePasvResponse(string message)
    {
        var start = message.IndexOf('(');
        var end = message.IndexOf(')');

        if (start == -1 || end == -1 || end <= start)
            return (null, 0);

        var parts = message[(start + 1)..end].Split(',');
        if (parts.Length != 6)
            return (null, 0);

        var host = $"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}";

        if (!int.TryParse(parts[4], out var p1) || !int.TryParse(parts[5], out var p2))
            return (null, 0);

        var port = (p1 * 256) + p2;

        return (host, port);
    }

    /// <summary>
    /// Parses the port from an EPSV (229) response
    /// Format: 229 Entering Extended Passive Mode (|||port|)
    /// </summary>
    public static int ParseEpsvResponse(string message)
    {
        var start = message.IndexOf("|||");
        var end = message.LastIndexOf('|');

        if (start == -1 || end == -1 || end <= start + 3)
            return 0;

        var portStr = message[(start + 3)..end];

        return int.TryParse(portStr, out var port) ? port : 0;
    }

    /// <summary>
    /// Standard FTP response codes
    /// </summary>
    public static class Codes
    {
        // Positive preliminary
        public const int RestartMarker = 110;
        public const int ServiceReadyInMinutes = 120;
        public const int DataConnectionAlreadyOpen = 125;
        public const int FileStatusOk = 150;

        // Positive completion
        public const int CommandOk = 200;
        public const int CommandNotImplementedSuperfulous = 202;
        public const int SystemStatus = 211;
        public const int DirectoryStatus = 212;
        public const int FileStatus = 213;
        public const int HelpMessage = 214;
        public const int SystemType = 215;
        public const int ServiceReady = 220;
        public const int ServiceClosing = 221;
        public const int DataConnectionOpen = 225;
        public const int ClosingDataConnection = 226;
        public const int EnteringPassiveMode = 227;
        public const int EnteringExtendedPassiveMode = 229;
        public const int UserLoggedIn = 230;
        public const int SecurityDataExchange = 234;
        public const int FileActionOk = 250;
        public const int PathCreated = 257;

        // Positive intermediate
        public const int UserNameOkNeedPassword = 331;
        public const int NeedAccountForLogin = 332;
        public const int FileActionPending = 350;

        // Transient negative
        public const int ServiceNotAvailable = 421;
        public const int CantOpenDataConnection = 425;
        public const int ConnectionClosed = 426;
        public const int FileActionNotTaken = 450;
        public const int ActionAborted = 451;
        public const int InsufficientStorage = 452;

        // Permanent negative
        public const int SyntaxError = 500;
        public const int SyntaxErrorInArguments = 501;
        public const int CommandNotImplemented = 502;
        public const int BadSequence = 503;
        public const int CommandNotImplementedForParameter = 504;
        public const int NotLoggedIn = 530;
        public const int NeedAccountForStoring = 532;
        public const int FileNotFound = 550;
        public const int PageTypeUnknown = 551;
        public const int ExceededStorageAllocation = 552;
        public const int FileNameNotAllowed = 553;
    }
}
