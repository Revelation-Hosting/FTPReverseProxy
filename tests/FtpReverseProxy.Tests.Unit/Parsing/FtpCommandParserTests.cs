using FtpReverseProxy.Ftp.Parsing;

namespace FtpReverseProxy.Tests.Unit.Parsing;

public class FtpCommandParserTests
{
    [Fact]
    public void Parse_SimpleCommand_ReturnsCorrectVerb()
    {
        var result = FtpCommandParser.Parse("USER");

        Assert.Equal("USER", result.Verb);
        Assert.Null(result.Argument);
        Assert.Equal("USER", result.RawCommand);
    }

    [Fact]
    public void Parse_CommandWithArgument_ReturnsVerbAndArgument()
    {
        var result = FtpCommandParser.Parse("USER testuser");

        Assert.Equal("USER", result.Verb);
        Assert.Equal("testuser", result.Argument);
        Assert.Equal("USER testuser", result.RawCommand);
    }

    [Fact]
    public void Parse_CommandWithSpacesInArgument_PreservesFullArgument()
    {
        var result = FtpCommandParser.Parse("CWD /path/with spaces/test");

        Assert.Equal("CWD", result.Verb);
        Assert.Equal("/path/with spaces/test", result.Argument);
    }

    [Fact]
    public void Parse_LowercaseCommand_ConvertsToUppercase()
    {
        var result = FtpCommandParser.Parse("user testuser");

        Assert.Equal("USER", result.Verb);
        Assert.Equal("testuser", result.Argument);
    }

    [Fact]
    public void Parse_MixedCaseCommand_ConvertsVerbToUppercase()
    {
        var result = FtpCommandParser.Parse("UsEr TestUser");

        Assert.Equal("USER", result.Verb);
        Assert.Equal("TestUser", result.Argument);
    }

    [Fact]
    public void Parse_EmptyString_ReturnsEmptyVerb()
    {
        var result = FtpCommandParser.Parse("");

        Assert.Equal(string.Empty, result.Verb);
        Assert.Null(result.Argument);
    }

    [Fact]
    public void Parse_WhitespaceOnly_ReturnsEmptyVerb()
    {
        var result = FtpCommandParser.Parse("   ");

        Assert.Equal(string.Empty, result.Verb);
        Assert.Null(result.Argument);
    }

    [Fact]
    public void Parse_CommandWithLeadingWhitespace_TrimsWhitespace()
    {
        var result = FtpCommandParser.Parse("  USER testuser  ");

        Assert.Equal("USER", result.Verb);
        Assert.Equal("testuser", result.Argument);
    }

    [Theory]
    [InlineData("PASS secret123", "PASS", "secret123")]
    [InlineData("RETR file.txt", "RETR", "file.txt")]
    [InlineData("STOR upload.dat", "STOR", "upload.dat")]
    [InlineData("TYPE A", "TYPE", "A")]
    [InlineData("TYPE I", "TYPE", "I")]
    [InlineData("CWD /home/user", "CWD", "/home/user")]
    [InlineData("MKD newfolder", "MKD", "newfolder")]
    [InlineData("RMD oldfolder", "RMD", "oldfolder")]
    [InlineData("DELE file.txt", "DELE", "file.txt")]
    [InlineData("RNFR oldname.txt", "RNFR", "oldname.txt")]
    [InlineData("RNTO newname.txt", "RNTO", "newname.txt")]
    [InlineData("SIZE file.txt", "SIZE", "file.txt")]
    [InlineData("AUTH TLS", "AUTH", "TLS")]
    [InlineData("PBSZ 0", "PBSZ", "0")]
    [InlineData("PROT P", "PROT", "P")]
    public void Parse_VariousCommands_ParsesCorrectly(string input, string expectedVerb, string expectedArg)
    {
        var result = FtpCommandParser.Parse(input);

        Assert.Equal(expectedVerb, result.Verb);
        Assert.Equal(expectedArg, result.Argument);
    }

    [Theory]
    [InlineData("QUIT")]
    [InlineData("PWD")]
    [InlineData("PASV")]
    [InlineData("EPSV")]
    [InlineData("CDUP")]
    [InlineData("NOOP")]
    [InlineData("SYST")]
    [InlineData("FEAT")]
    public void Parse_CommandsWithoutArguments_ReturnsNullArgument(string command)
    {
        var result = FtpCommandParser.Parse(command);

        Assert.Equal(command.ToUpperInvariant(), result.Verb);
        Assert.Null(result.Argument);
    }

    [Fact]
    public void Parse_PortCommand_ParsesCorrectly()
    {
        var result = FtpCommandParser.Parse("PORT 192,168,1,100,4,1");

        Assert.Equal("PORT", result.Verb);
        Assert.Equal("192,168,1,100,4,1", result.Argument);
    }

    [Fact]
    public void Parse_EprtCommand_ParsesCorrectly()
    {
        var result = FtpCommandParser.Parse("EPRT |1|192.168.1.100|1025|");

        Assert.Equal("EPRT", result.Verb);
        Assert.Equal("|1|192.168.1.100|1025|", result.Argument);
    }

    [Fact]
    public void Parse_ListWithPath_ParsesCorrectly()
    {
        var result = FtpCommandParser.Parse("LIST /home/user/documents");

        Assert.Equal("LIST", result.Verb);
        Assert.Equal("/home/user/documents", result.Argument);
    }

    [Fact]
    public void Parse_ListWithoutPath_ParsesCorrectly()
    {
        var result = FtpCommandParser.Parse("LIST");

        Assert.Equal("LIST", result.Verb);
        Assert.Null(result.Argument);
    }

    [Fact]
    public void Parse_RestCommand_ParsesCorrectly()
    {
        var result = FtpCommandParser.Parse("REST 1024");

        Assert.Equal("REST", result.Verb);
        Assert.Equal("1024", result.Argument);
    }

    [Fact]
    public void Parse_PreservesRawCommand()
    {
        var input = "user TestUser";
        var result = FtpCommandParser.Parse(input);

        Assert.Equal(input, result.RawCommand);
    }
}
