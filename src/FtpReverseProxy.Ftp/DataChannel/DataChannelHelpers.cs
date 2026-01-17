using System.Net;
using System.Text.RegularExpressions;

namespace FtpReverseProxy.Ftp.DataChannel;

/// <summary>
/// Helper methods for parsing and formatting FTP data channel commands/responses
/// </summary>
public static partial class DataChannelHelpers
{
    /// <summary>
    /// Parses IP and port from a PASV (227) response
    /// Format: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
    /// </summary>
    public static IPEndPoint? ParsePasvResponse(string response)
    {
        var match = PasvRegex().Match(response);
        if (!match.Success)
            return null;

        var h1 = int.Parse(match.Groups[1].Value);
        var h2 = int.Parse(match.Groups[2].Value);
        var h3 = int.Parse(match.Groups[3].Value);
        var h4 = int.Parse(match.Groups[4].Value);
        var p1 = int.Parse(match.Groups[5].Value);
        var p2 = int.Parse(match.Groups[6].Value);

        var ip = new IPAddress(new byte[] { (byte)h1, (byte)h2, (byte)h3, (byte)h4 });
        var port = (p1 * 256) + p2;

        return new IPEndPoint(ip, port);
    }

    /// <summary>
    /// Formats a PASV (227) response with the given endpoint
    /// </summary>
    public static string FormatPasvResponse(IPEndPoint endpoint)
    {
        var bytes = endpoint.Address.GetAddressBytes();
        var p1 = endpoint.Port / 256;
        var p2 = endpoint.Port % 256;

        return $"227 Entering Passive Mode ({bytes[0]},{bytes[1]},{bytes[2]},{bytes[3]},{p1},{p2})";
    }

    /// <summary>
    /// Parses port from an EPSV (229) response
    /// Format: 229 Entering Extended Passive Mode (|||port|)
    /// </summary>
    public static int ParseEpsvResponse(string response)
    {
        var match = EpsvRegex().Match(response);
        if (!match.Success)
            return 0;

        return int.Parse(match.Groups[1].Value);
    }

    /// <summary>
    /// Formats an EPSV (229) response with the given port
    /// </summary>
    public static string FormatEpsvResponse(int port)
    {
        return $"229 Entering Extended Passive Mode (|||{port}|)";
    }

    /// <summary>
    /// Parses IP and port from a PORT command
    /// Format: PORT h1,h2,h3,h4,p1,p2
    /// </summary>
    public static IPEndPoint? ParsePortCommand(string argument)
    {
        var parts = argument.Split(',');
        if (parts.Length != 6)
            return null;

        if (!int.TryParse(parts[0], out var h1) ||
            !int.TryParse(parts[1], out var h2) ||
            !int.TryParse(parts[2], out var h3) ||
            !int.TryParse(parts[3], out var h4) ||
            !int.TryParse(parts[4], out var p1) ||
            !int.TryParse(parts[5], out var p2))
            return null;

        var ip = new IPAddress(new byte[] { (byte)h1, (byte)h2, (byte)h3, (byte)h4 });
        var port = (p1 * 256) + p2;

        return new IPEndPoint(ip, port);
    }

    /// <summary>
    /// Formats a PORT command with the given endpoint
    /// </summary>
    public static string FormatPortCommand(IPEndPoint endpoint)
    {
        var bytes = endpoint.Address.GetAddressBytes();
        var p1 = endpoint.Port / 256;
        var p2 = endpoint.Port % 256;

        return $"PORT {bytes[0]},{bytes[1]},{bytes[2]},{bytes[3]},{p1},{p2}";
    }

    /// <summary>
    /// Parses IP and port from an EPRT command
    /// Format: EPRT |protocol|address|port|
    /// protocol: 1 = IPv4, 2 = IPv6
    /// </summary>
    public static IPEndPoint? ParseEprtCommand(string argument)
    {
        var match = EprtRegex().Match(argument);
        if (!match.Success)
            return null;

        var protocol = int.Parse(match.Groups[1].Value);
        var address = match.Groups[2].Value;
        var port = int.Parse(match.Groups[3].Value);

        if (!IPAddress.TryParse(address, out var ip))
            return null;

        return new IPEndPoint(ip, port);
    }

    /// <summary>
    /// Formats an EPRT command with the given endpoint
    /// </summary>
    public static string FormatEprtCommand(IPEndPoint endpoint)
    {
        var protocol = endpoint.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ? 1 : 2;
        return $"EPRT |{protocol}|{endpoint.Address}|{endpoint.Port}|";
    }

    [GeneratedRegex(@"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)")]
    private static partial Regex PasvRegex();

    [GeneratedRegex(@"\(\|\|\|(\d+)\|\)")]
    private static partial Regex EpsvRegex();

    [GeneratedRegex(@"\|(\d)\|([^|]+)\|(\d+)\|")]
    private static partial Regex EprtRegex();
}
