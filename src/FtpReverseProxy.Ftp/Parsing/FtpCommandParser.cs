using FtpReverseProxy.Core.Models;

namespace FtpReverseProxy.Ftp.Parsing;

/// <summary>
/// Parses FTP commands from client input
/// </summary>
public static class FtpCommandParser
{
    /// <summary>
    /// Parses a raw FTP command line into an FtpCommand object
    /// </summary>
    /// <param name="line">The raw command line (without CRLF)</param>
    /// <returns>The parsed command</returns>
    public static FtpCommand Parse(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return new FtpCommand
            {
                Verb = string.Empty,
                Argument = null,
                RawCommand = line
            };
        }

        var trimmed = line.Trim();
        var spaceIndex = trimmed.IndexOf(' ');

        if (spaceIndex == -1)
        {
            // Command with no argument
            return new FtpCommand
            {
                Verb = trimmed.ToUpperInvariant(),
                Argument = null,
                RawCommand = line
            };
        }

        // Command with argument
        return new FtpCommand
        {
            Verb = trimmed[..spaceIndex].ToUpperInvariant(),
            Argument = trimmed[(spaceIndex + 1)..],
            RawCommand = line
        };
    }

    /// <summary>
    /// Known FTP commands that should be handled specially by the proxy
    /// </summary>
    public static class Commands
    {
        // Authentication
        public const string User = "USER";
        public const string Pass = "PASS";
        public const string Acct = "ACCT";

        // Connection
        public const string Quit = "QUIT";
        public const string Rein = "REIN";

        // Data channel
        public const string Pasv = "PASV";
        public const string Epsv = "EPSV";
        public const string Port = "PORT";
        public const string Eprt = "EPRT";

        // TLS
        public const string Auth = "AUTH";
        public const string Pbsz = "PBSZ";
        public const string Prot = "PROT";

        // Transfer
        public const string Retr = "RETR";
        public const string Stor = "STOR";
        public const string Stou = "STOU";
        public const string Appe = "APPE";
        public const string List = "LIST";
        public const string Nlst = "NLST";
        public const string Mlsd = "MLSD";
        public const string Mlst = "MLST";

        // Directory
        public const string Cwd = "CWD";
        public const string Cdup = "CDUP";
        public const string Pwd = "PWD";
        public const string Mkd = "MKD";
        public const string Rmd = "RMD";

        // File operations
        public const string Dele = "DELE";
        public const string Rnfr = "RNFR";
        public const string Rnto = "RNTO";
        public const string Size = "SIZE";
        public const string Mdtm = "MDTM";

        // Transfer mode
        public const string Type = "TYPE";
        public const string Mode = "MODE";
        public const string Stru = "STRU";
        public const string Rest = "REST";

        // Information
        public const string Syst = "SYST";
        public const string Stat = "STAT";
        public const string Help = "HELP";
        public const string Noop = "NOOP";
        public const string Feat = "FEAT";
        public const string Opts = "OPTS";
    }
}
