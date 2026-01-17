using FtpReverseProxy.Ftp.Parsing;

namespace FtpReverseProxy.Tests.Unit.Parsing;

public class FtpResponseParserTests
{
    [Fact]
    public void Parse_SingleLineResponse_ParsesCorrectly()
    {
        var lines = new[] { "220 FTP Server Ready" };
        var result = FtpResponseParser.Parse(lines);

        Assert.Equal(220, result.Code);
        Assert.Equal("FTP Server Ready", result.Message);
        Assert.False(result.IsMultiLine);
    }

    [Fact]
    public void Parse_MultiLineResponse_ParsesCorrectly()
    {
        var lines = new[]
        {
            "211-Features:",
            " PASV",
            " UTF8",
            "211 End"
        };
        var result = FtpResponseParser.Parse(lines);

        Assert.Equal(211, result.Code);
        Assert.True(result.IsMultiLine);
        Assert.Contains("Features:", result.Message);
        Assert.Contains("End", result.Message);
    }

    [Fact]
    public void Parse_EmptyLines_ReturnsEmptyResponse()
    {
        var lines = Array.Empty<string>();
        var result = FtpResponseParser.Parse(lines);

        Assert.Equal(0, result.Code);
        Assert.Equal(string.Empty, result.Message);
        Assert.False(result.IsMultiLine);
    }

    [Theory]
    [InlineData("220 Service ready", 220, "Service ready")]
    [InlineData("230 User logged in", 230, "User logged in")]
    [InlineData("331 Password required", 331, "Password required")]
    [InlineData("530 Login incorrect", 530, "Login incorrect")]
    [InlineData("550 File not found", 550, "File not found")]
    public void Parse_StandardResponses_ParsesCorrectly(string line, int expectedCode, string expectedMessage)
    {
        var result = FtpResponseParser.ParseLine(line);

        Assert.Equal(expectedCode, result.Code);
        Assert.Equal(expectedMessage, result.Message);
    }

    [Fact]
    public void Parse_InvalidResponse_ReturnsZeroCode()
    {
        var result = FtpResponseParser.ParseLine("Invalid response");

        Assert.Equal(0, result.Code);
        Assert.Equal("Invalid response", result.Message);
    }

    [Fact]
    public void Parse_ResponseWithoutMessage_ParsesCode()
    {
        var result = FtpResponseParser.ParseLine("200");

        Assert.Equal(200, result.Code);
    }

    [Fact]
    public void IsMultiLineStart_WithHyphen_ReturnsTrue()
    {
        Assert.True(FtpResponseParser.IsMultiLineStart("211-Features:"));
    }

    [Fact]
    public void IsMultiLineStart_WithSpace_ReturnsFalse()
    {
        Assert.False(FtpResponseParser.IsMultiLineStart("211 End"));
    }

    [Fact]
    public void IsMultiLineStart_TooShort_ReturnsFalse()
    {
        Assert.False(FtpResponseParser.IsMultiLineStart("21"));
    }

    [Theory]
    [InlineData("211 End", 211, true)]
    [InlineData("211-More", 211, false)]
    [InlineData("200 OK", 200, true)]
    [InlineData("200-More", 200, false)]
    [InlineData("211 End", 200, false)] // Wrong code
    public void IsMultiLineEnd_VariousInputs_ReturnsExpected(string line, int code, bool expected)
    {
        Assert.Equal(expected, FtpResponseParser.IsMultiLineEnd(line, code));
    }

    [Theory]
    [InlineData("227 Entering Passive Mode (192,168,1,100,4,1)", "192.168.1.100", 1025)]
    [InlineData("227 Entering Passive Mode (10,0,0,1,39,16)", "10.0.0.1", 10000)]
    [InlineData("227 Entering Passive Mode (127,0,0,1,0,21)", "127.0.0.1", 21)]
    public void ParsePasvResponse_ValidResponse_ReturnsHostAndPort(string response, string expectedHost, int expectedPort)
    {
        var (host, port) = FtpResponseParser.ParsePasvResponse(response);

        Assert.Equal(expectedHost, host);
        Assert.Equal(expectedPort, port);
    }

    [Theory]
    [InlineData("Invalid response")]
    [InlineData("227 No parentheses")]
    [InlineData("227 (1,2,3)")]  // Not enough parts
    [InlineData("227 (1,2,3,4,5,6,7)")]  // Too many parts
    public void ParsePasvResponse_InvalidResponse_ReturnsNullHost(string response)
    {
        var (host, port) = FtpResponseParser.ParsePasvResponse(response);

        Assert.Null(host);
        Assert.Equal(0, port);
    }

    [Theory]
    [InlineData("229 Entering Extended Passive Mode (|||1025|)", 1025)]
    [InlineData("229 Entering Extended Passive Mode (|||50000|)", 50000)]
    [InlineData("229 Entering Extended Passive Mode (|||21|)", 21)]
    public void ParseEpsvResponse_ValidResponse_ReturnsPort(string response, int expectedPort)
    {
        var port = FtpResponseParser.ParseEpsvResponse(response);

        Assert.Equal(expectedPort, port);
    }

    [Theory]
    [InlineData("Invalid response")]
    [InlineData("229 No pipes")]
    [InlineData("229 (||1025|)")]  // Wrong number of pipes
    public void ParseEpsvResponse_InvalidResponse_ReturnsZero(string response)
    {
        var port = FtpResponseParser.ParseEpsvResponse(response);

        Assert.Equal(0, port);
    }

    [Fact]
    public void Parse_RawResponse_ContainsAllLines()
    {
        var lines = new[] { "211-Line1", "211 Line2" };
        var result = FtpResponseParser.Parse(lines);

        Assert.Contains("211-Line1", result.RawResponse);
        Assert.Contains("211 Line2", result.RawResponse);
    }

    [Fact]
    public void IsPreliminary_150Response_ReturnsTrue()
    {
        var result = FtpResponseParser.ParseLine("150 Opening data connection");

        Assert.True(result.IsPreliminary);
    }

    [Fact]
    public void IsSuccess_200Response_ReturnsTrue()
    {
        var result = FtpResponseParser.ParseLine("200 OK");

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void IsSuccess_500Response_ReturnsFalse()
    {
        var result = FtpResponseParser.ParseLine("500 Syntax error");

        Assert.False(result.IsSuccess);
    }

    [Fact]
    public void Codes_ContainsStandardCodes()
    {
        Assert.Equal(220, FtpResponseParser.Codes.ServiceReady);
        Assert.Equal(230, FtpResponseParser.Codes.UserLoggedIn);
        Assert.Equal(331, FtpResponseParser.Codes.UserNameOkNeedPassword);
        Assert.Equal(530, FtpResponseParser.Codes.NotLoggedIn);
        Assert.Equal(227, FtpResponseParser.Codes.EnteringPassiveMode);
        Assert.Equal(229, FtpResponseParser.Codes.EnteringExtendedPassiveMode);
        Assert.Equal(150, FtpResponseParser.Codes.FileStatusOk);
        Assert.Equal(226, FtpResponseParser.Codes.ClosingDataConnection);
    }
}
