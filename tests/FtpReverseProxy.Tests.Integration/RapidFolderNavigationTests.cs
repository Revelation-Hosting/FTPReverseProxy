using System.Diagnostics;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Xunit.Abstractions;

namespace FtpReverseProxy.Tests.Integration;

/// <summary>
/// Tests that simulate rapid folder navigation to reproduce connection drop issues.
/// These tests send rapid PASV + LIST commands to stress test the proxy's data channel handling.
/// </summary>
public class RapidFolderNavigationTests : IDisposable
{
    private readonly ITestOutputHelper _output;
    private readonly StringBuilder _log = new();
    private readonly Stopwatch _stopwatch = Stopwatch.StartNew();

    // Configuration - can be overridden via environment variables
    // Set FTP_TEST_HOST, FTP_TEST_PORT, FTP_TEST_USER, FTP_TEST_PASS
    private static readonly string ProxyHost = Environment.GetEnvironmentVariable("FTP_TEST_HOST") ?? "localhost";
    private static readonly int ProxyPort = int.TryParse(Environment.GetEnvironmentVariable("FTP_TEST_PORT"), out var p) ? p : 21;
    private static readonly string Username = Environment.GetEnvironmentVariable("FTP_TEST_USER") ?? "test";
    private static readonly string Password = Environment.GetEnvironmentVariable("FTP_TEST_PASS") ?? "test";

    public RapidFolderNavigationTests(ITestOutputHelper output)
    {
        _output = output;
    }

    public void Dispose()
    {
        // Output all collected logs at the end
        _output.WriteLine("=== Complete Test Log ===");
        _output.WriteLine(_log.ToString());
    }

    private void Log(string message)
    {
        var timestamp = _stopwatch.Elapsed.TotalMilliseconds;
        var line = $"[{timestamp:F3}ms] {message}";
        _log.AppendLine(line);
        _output.WriteLine(line);
    }

    /// <summary>
    /// Simulates rapid folder navigation by sending multiple PASV + LIST commands in quick succession.
    /// This test reproduces the scenario where FileZilla rapidly navigates folders.
    /// </summary>
    [Theory]
    [InlineData(5, 0)]      // 5 iterations, no delay - maximum stress
    [InlineData(10, 0)]     // 10 iterations, no delay
    [InlineData(20, 0)]     // 20 iterations, no delay
    [InlineData(10, 10)]    // 10 iterations, 10ms delay
    [InlineData(10, 50)]    // 10 iterations, 50ms delay
    public async Task RapidFolderNavigation_ShouldNotDropConnection(int iterations, int delayBetweenMs)
    {
        Log($"Starting rapid folder navigation test: {iterations} iterations, {delayBetweenMs}ms delay");

        using var client = new TcpClient();
        await client.ConnectAsync(ProxyHost, ProxyPort);
        Log($"Connected to {ProxyHost}:{ProxyPort}");

        Stream stream = client.GetStream();
        var reader = new StreamReader(stream, Encoding.UTF8);
        var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };

        // Read welcome banner
        var banner = await ReadResponseAsync(reader, "Banner");
        Assert.StartsWith("220", banner);

        // AUTH TLS
        await SendCommandAsync(writer, "AUTH TLS");
        var authResponse = await ReadResponseAsync(reader, "AUTH TLS");
        Assert.StartsWith("234", authResponse);

        // Upgrade to TLS
        Log("Upgrading to TLS...");
        var sslStream = new SslStream(stream, false, (sender, cert, chain, errors) => true);
        await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = ProxyHost,
            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
        });
        Log($"TLS established: {sslStream.SslProtocol}, {sslStream.NegotiatedCipherSuite}");

        // Create new reader/writer for TLS stream
        reader = new StreamReader(sslStream, Encoding.UTF8);
        writer = new StreamWriter(sslStream, Encoding.UTF8) { AutoFlush = true };

        // PBSZ 0
        await SendCommandAsync(writer, "PBSZ 0");
        var pbszResponse = await ReadResponseAsync(reader, "PBSZ");
        Assert.StartsWith("200", pbszResponse);

        // PROT P
        await SendCommandAsync(writer, "PROT P");
        var protResponse = await ReadResponseAsync(reader, "PROT P");
        Assert.StartsWith("200", protResponse);

        // USER
        await SendCommandAsync(writer, $"USER {Username}");
        var userResponse = await ReadResponseAsync(reader, "USER");
        Assert.True(userResponse.StartsWith("331") || userResponse.StartsWith("230"), $"Unexpected USER response: {userResponse}");

        if (userResponse.StartsWith("331"))
        {
            // PASS
            await SendCommandAsync(writer, $"PASS {Password}");
            var passResponse = await ReadResponseAsync(reader, "PASS");
            Assert.StartsWith("230", passResponse);
        }

        Log("Authentication successful, starting rapid folder navigation test...");

        // Rapid folder navigation simulation
        var successCount = 0;
        var failureCount = 0;
        var folders = new[] { "/", "/test", "/", "/uploads", "/", "/downloads", "/" };

        for (int i = 0; i < iterations; i++)
        {
            var folder = folders[i % folders.Length];
            Log($"--- Iteration {i + 1}/{iterations}: Navigating to '{folder}' ---");

            try
            {
                // CWD to folder (except for root)
                if (folder != "/")
                {
                    await SendCommandAsync(writer, $"CWD {folder}");
                    var cwdResponse = await ReadResponseAsync(reader, "CWD");
                    if (!cwdResponse.StartsWith("250") && !cwdResponse.StartsWith("550"))
                    {
                        Log($"WARNING: Unexpected CWD response: {cwdResponse}");
                    }
                }

                // PASV
                await SendCommandAsync(writer, "EPSV");
                var pasvResponse = await ReadResponseAsync(reader, "EPSV");

                if (!pasvResponse.StartsWith("229"))
                {
                    Log($"FAILURE: EPSV failed with: {pasvResponse}");
                    failureCount++;
                    continue;
                }

                // Parse EPSV response to get data port
                var dataPort = ParseEpsvPort(pasvResponse);
                Log($"Data port: {dataPort}");

                // Connect to data channel
                using var dataClient = new TcpClient();
                await dataClient.ConnectAsync(ProxyHost, dataPort);
                Log("Data channel connected");

                // Upgrade data channel to TLS
                var dataSslStream = new SslStream(dataClient.GetStream(), false, (sender, cert, chain, errors) => true);
                await dataSslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = ProxyHost,
                    EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
                });
                Log($"Data channel TLS: {dataSslStream.SslProtocol}");

                // Send LIST command
                await SendCommandAsync(writer, "LIST");
                var listResponse = await ReadResponseAsync(reader, "LIST");

                if (!listResponse.StartsWith("150") && !listResponse.StartsWith("125"))
                {
                    Log($"FAILURE: LIST preliminary response failed: {listResponse}");
                    failureCount++;
                    continue;
                }

                // Read directory listing from data channel
                var dataReader = new StreamReader(dataSslStream, Encoding.UTF8);
                var listing = new StringBuilder();
                string? line;
                while ((line = await dataReader.ReadLineAsync()) != null)
                {
                    listing.AppendLine(line);
                }
                Log($"Received {listing.Length} bytes of directory listing");

                // Data channel should close after listing
                dataSslStream.Close();
                dataClient.Close();

                // Read 226 completion response
                var completionResponse = await ReadResponseAsync(reader, "226 Completion");

                if (!completionResponse.StartsWith("226"))
                {
                    Log($"FAILURE: Did not receive 226, got: {completionResponse}");
                    failureCount++;
                    continue;
                }

                Log($"SUCCESS: LIST completed successfully");
                successCount++;

                // Optional delay between iterations
                if (delayBetweenMs > 0)
                {
                    await Task.Delay(delayBetweenMs);
                }
            }
            catch (IOException ex)
            {
                Log($"FAILURE: IOException on iteration {i + 1}: {ex.Message}");
                Log($"Inner exception: {ex.InnerException?.Message}");
                failureCount++;

                // Check if connection is still alive
                if (!client.Connected)
                {
                    Log("CONNECTION DROPPED - Test cannot continue");
                    break;
                }
            }
            catch (Exception ex)
            {
                Log($"FAILURE: {ex.GetType().Name} on iteration {i + 1}: {ex.Message}");
                failureCount++;

                if (!client.Connected)
                {
                    Log("CONNECTION DROPPED - Test cannot continue");
                    break;
                }
            }
        }

        Log($"=== Test Complete ===");
        Log($"Success: {successCount}, Failures: {failureCount}");

        // Send QUIT
        try
        {
            await SendCommandAsync(writer, "QUIT");
            var quitResponse = await ReadResponseAsync(reader, "QUIT");
            Log($"QUIT response: {quitResponse}");
        }
        catch (Exception ex)
        {
            Log($"Error during QUIT: {ex.Message}");
        }

        Assert.Equal(0, failureCount);
    }

    /// <summary>
    /// Test that sends commands as fast as possible without waiting for data channel completion.
    /// This simulates aggressive client behavior.
    /// </summary>
    [Fact]
    public async Task AggressiveCommandPipelining_ShouldNotDropConnection()
    {
        Log("Starting aggressive command pipelining test");

        using var client = new TcpClient();
        await client.ConnectAsync(ProxyHost, ProxyPort);

        Stream stream = client.GetStream();
        var reader = new StreamReader(stream, Encoding.UTF8);
        var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };

        // Read welcome banner
        var banner = await ReadResponseAsync(reader, "Banner");

        // AUTH TLS
        await SendCommandAsync(writer, "AUTH TLS");
        var authResponse = await ReadResponseAsync(reader, "AUTH TLS");

        // Upgrade to TLS
        var sslStream = new SslStream(stream, false, (sender, cert, chain, errors) => true);
        await sslStream.AuthenticateAsClientAsync(ProxyHost);

        reader = new StreamReader(sslStream, Encoding.UTF8);
        writer = new StreamWriter(sslStream, Encoding.UTF8) { AutoFlush = true };

        // PBSZ, PROT, USER, PASS
        await SendCommandAsync(writer, "PBSZ 0");
        await ReadResponseAsync(reader, "PBSZ");
        await SendCommandAsync(writer, "PROT P");
        await ReadResponseAsync(reader, "PROT P");
        await SendCommandAsync(writer, $"USER {Username}");
        var userResponse = await ReadResponseAsync(reader, "USER");
        if (userResponse.StartsWith("331"))
        {
            await SendCommandAsync(writer, $"PASS {Password}");
            await ReadResponseAsync(reader, "PASS");
        }

        Log("Authenticated, starting aggressive pipelining...");

        // Send multiple SYST, PWD, TYPE commands rapidly
        var commands = new[] { "SYST", "PWD", "TYPE I", "FEAT", "PWD", "SYST" };

        foreach (var cmd in commands)
        {
            await SendCommandAsync(writer, cmd);
        }

        // Now read all responses
        foreach (var cmd in commands)
        {
            var response = await ReadResponseAsync(reader, cmd);
            Log($"Response for {cmd}: {response.Substring(0, Math.Min(50, response.Length))}...");
        }

        // Verify connection is still alive
        await SendCommandAsync(writer, "NOOP");
        var noopResponse = await ReadResponseAsync(reader, "NOOP");
        Assert.StartsWith("200", noopResponse);

        Log("Aggressive pipelining test passed");

        await SendCommandAsync(writer, "QUIT");
        await ReadResponseAsync(reader, "QUIT");
    }

    /// <summary>
    /// Test concurrent TLS connections to identify race conditions.
    /// This test launches multiple connections simultaneously.
    /// </summary>
    [Theory]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    public async Task ConcurrentTlsConnections_ShouldNotInterfere(int concurrentCount)
    {
        Log($"Starting concurrent TLS connection test - {concurrentCount} simultaneous connections");

        var tasks = new List<Task<bool>>();
        var barrier = new Barrier(concurrentCount); // Synchronize connection starts

        for (int i = 0; i < concurrentCount; i++)
        {
            var connectionId = i + 1;
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    using var client = new TcpClient();
                    await client.ConnectAsync(ProxyHost, ProxyPort);

                    Stream stream = client.GetStream();
                    var reader = new StreamReader(stream, Encoding.UTF8);
                    var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };

                    // Read banner
                    var banner = await reader.ReadLineAsync();
                    if (banner == null || !banner.StartsWith("220"))
                    {
                        Log($"[Conn {connectionId}] FAIL: Banner was null or invalid: {banner}");
                        return false;
                    }

                    // AUTH TLS
                    await writer.WriteLineAsync("AUTH TLS");
                    var authResponse = await reader.ReadLineAsync();
                    if (authResponse == null || !authResponse.StartsWith("234"))
                    {
                        Log($"[Conn {connectionId}] FAIL: AUTH TLS failed: {authResponse}");
                        return false;
                    }

                    // Wait for all connections to reach TLS upgrade point
                    barrier.SignalAndWait();

                    // Upgrade to TLS simultaneously
                    var sslStream = new SslStream(stream, false, (sender, cert, chain, errors) => true);
                    await sslStream.AuthenticateAsClientAsync(ProxyHost);

                    reader = new StreamReader(sslStream, Encoding.UTF8);
                    writer = new StreamWriter(sslStream, Encoding.UTF8) { AutoFlush = true };

                    // Send commands
                    await writer.WriteLineAsync("PBSZ 0");
                    var pbszResp = await reader.ReadLineAsync();
                    if (pbszResp == null)
                    {
                        Log($"[Conn {connectionId}] FAIL: PBSZ response was null (connection dropped)");
                        return false;
                    }

                    await writer.WriteLineAsync("PROT P");
                    var protResp = await reader.ReadLineAsync();
                    if (protResp == null)
                    {
                        Log($"[Conn {connectionId}] FAIL: PROT P response was null (connection dropped)");
                        return false;
                    }

                    await writer.WriteLineAsync("SYST");
                    var systResp = await reader.ReadLineAsync();
                    if (systResp == null)
                    {
                        Log($"[Conn {connectionId}] FAIL: SYST response was null (connection dropped)");
                        return false;
                    }

                    await writer.WriteLineAsync("QUIT");
                    var quitResp = await reader.ReadLineAsync();

                    Log($"[Conn {connectionId}] SUCCESS: All commands completed");
                    return true;
                }
                catch (Exception ex)
                {
                    Log($"[Conn {connectionId}] EXCEPTION: {ex.GetType().Name}: {ex.Message}");
                    return false;
                }
            }));
        }

        var results = await Task.WhenAll(tasks);
        var successCount = results.Count(r => r);
        var failCount = results.Count(r => !r);

        Log($"Results: {successCount} success, {failCount} failed");

        Assert.Equal(0, failCount);
    }

    /// <summary>
    /// Test that multiple sequential connections with TLS session resumption don't interfere.
    /// This specifically tests for thread-safety issues in the shared OpenSSL context.
    /// </summary>
    [Fact]
    public async Task SequentialTlsConnections_ShouldNotInterfere()
    {
        Log("Starting sequential TLS connection test - testing session resumption");

        for (int i = 0; i < 10; i++)
        {
            Log($"=== Connection {i + 1}/10 ===");

            using var client = new TcpClient();
            await client.ConnectAsync(ProxyHost, ProxyPort);

            Stream stream = client.GetStream();
            var reader = new StreamReader(stream, Encoding.UTF8);
            var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };

            // Read banner
            var banner = await ReadResponseAsync(reader, "Banner");
            Assert.StartsWith("220", banner);

            // AUTH TLS
            await SendCommandAsync(writer, "AUTH TLS");
            var authResponse = await ReadResponseAsync(reader, "AUTH TLS");
            Assert.StartsWith("234", authResponse);

            // Upgrade to TLS - this should reuse session on subsequent connections
            var sslStream = new SslStream(stream, false, (sender, cert, chain, errors) => true);
            await sslStream.AuthenticateAsClientAsync(ProxyHost);
            Log($"TLS: {sslStream.SslProtocol}");

            reader = new StreamReader(sslStream, Encoding.UTF8);
            writer = new StreamWriter(sslStream, Encoding.UTF8) { AutoFlush = true };

            // Send several commands to verify connection works
            await SendCommandAsync(writer, "PBSZ 0");
            var pbszResp = await ReadResponseAsync(reader, "PBSZ");
            Assert.StartsWith("200", pbszResp);

            await SendCommandAsync(writer, "PROT P");
            var protResp = await ReadResponseAsync(reader, "PROT P");
            Assert.StartsWith("200", protResp);

            await SendCommandAsync(writer, "SYST");
            var systResp = await ReadResponseAsync(reader, "SYST");
            // SYST might return 215 or 530 depending on auth state

            await SendCommandAsync(writer, "QUIT");
            var quitResp = await ReadResponseAsync(reader, "QUIT");
            Assert.StartsWith("221", quitResp);

            Log($"Connection {i + 1} completed successfully");

            // Small delay between connections
            await Task.Delay(50);
        }

        Log("Sequential TLS test passed");
    }

    /// <summary>
    /// Test that rapidly sets up and tears down data channels without transferring data.
    /// This tests the PASV setup/teardown path.
    /// </summary>
    [Theory]
    [InlineData(20)]
    [InlineData(50)]
    public async Task RapidPasvSetupTeardown_ShouldNotDropConnection(int iterations)
    {
        Log($"Starting rapid PASV setup/teardown test: {iterations} iterations");

        using var client = new TcpClient();
        await client.ConnectAsync(ProxyHost, ProxyPort);

        Stream stream = client.GetStream();
        var reader = new StreamReader(stream, Encoding.UTF8);
        var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };

        // Setup TLS connection (abbreviated)
        await ReadResponseAsync(reader, "Banner");
        await SendCommandAsync(writer, "AUTH TLS");
        await ReadResponseAsync(reader, "AUTH TLS");

        var sslStream = new SslStream(stream, false, (sender, cert, chain, errors) => true);
        await sslStream.AuthenticateAsClientAsync(ProxyHost);

        reader = new StreamReader(sslStream, Encoding.UTF8);
        writer = new StreamWriter(sslStream, Encoding.UTF8) { AutoFlush = true };

        await SendCommandAsync(writer, "PBSZ 0");
        await ReadResponseAsync(reader, "PBSZ");
        await SendCommandAsync(writer, "PROT P");
        await ReadResponseAsync(reader, "PROT P");
        await SendCommandAsync(writer, $"USER {Username}");
        var userResp = await ReadResponseAsync(reader, "USER");
        if (userResp.StartsWith("331"))
        {
            await SendCommandAsync(writer, $"PASS {Password}");
            await ReadResponseAsync(reader, "PASS");
        }

        Log("Authenticated, starting rapid PASV test...");

        for (int i = 0; i < iterations; i++)
        {
            Log($"--- PASV iteration {i + 1}/{iterations} ---");

            // Send EPSV
            await SendCommandAsync(writer, "EPSV");
            var pasvResponse = await ReadResponseAsync(reader, "EPSV");

            if (!pasvResponse.StartsWith("229"))
            {
                Log($"FAILURE at iteration {i + 1}: {pasvResponse}");
                Assert.Fail($"EPSV failed at iteration {i + 1}: {pasvResponse}");
            }

            // Parse port but don't connect - just abandon the data channel
            var dataPort = ParseEpsvPort(pasvResponse);
            Log($"Got data port {dataPort}, abandoning...");

            // The proxy should handle abandoned data channels gracefully
        }

        // Verify control connection is still alive
        await SendCommandAsync(writer, "NOOP");
        var noopResponse = await ReadResponseAsync(reader, "NOOP");
        Assert.StartsWith("200", noopResponse);

        Log($"Rapid PASV test completed successfully - {iterations} iterations");

        await SendCommandAsync(writer, "QUIT");
        await ReadResponseAsync(reader, "QUIT");
    }

    private async Task SendCommandAsync(StreamWriter writer, string command)
    {
        var displayCmd = command.StartsWith("PASS") ? "PASS ****" : command;
        Log($">>> {displayCmd}");
        await writer.WriteLineAsync(command);
    }

    private async Task<string> ReadResponseAsync(StreamReader reader, string context)
    {
        var response = await reader.ReadLineAsync();
        if (response == null)
        {
            Log($"<<< NULL (connection closed) [{context}]");
            throw new IOException($"Connection closed while reading {context}");
        }

        // Handle multi-line responses
        if (response.Length >= 4 && response[3] == '-')
        {
            var fullResponse = new StringBuilder(response);
            var expectedCode = response.Substring(0, 3);

            while (true)
            {
                var line = await reader.ReadLineAsync();
                if (line == null) break;
                fullResponse.AppendLine();
                fullResponse.Append(line);
                if (line.StartsWith(expectedCode + " ")) break;
            }
            response = fullResponse.ToString();
        }

        var displayResponse = response.Length > 100 ? response.Substring(0, 100) + "..." : response;
        Log($"<<< {displayResponse} [{context}]");
        return response;
    }

    private static int ParseEpsvPort(string response)
    {
        // EPSV response format: 229 Entering Extended Passive Mode (|||port|)
        var start = response.IndexOf("|||");
        var end = response.IndexOf("|)", start);
        if (start < 0 || end < 0) return 0;
        return int.Parse(response.Substring(start + 3, end - start - 3));
    }

    /// <summary>
    /// Test that reproduces the idle disconnect issue:
    /// 1. Connect and do a successful LIST
    /// 2. Wait 6+ seconds (idle) - this triggers the TLS termination error
    /// 3. Try to do another LIST - this should fail
    /// 4. Try to reconnect - subsequent connections often fail with "Connection closed by server"
    ///
    /// This test is designed to reproduce the pattern:
    /// "If I open a folder, wait for the TLS error, then try to open another, it fails immediately"
    /// </summary>
    [Theory]
    [InlineData(6)]     // 6 seconds idle
    [InlineData(10)]    // 10 seconds idle
    public async Task IdleDisconnect_ShouldNotCorruptState(int idleSeconds)
    {
        Log($"Starting idle disconnect test: {idleSeconds} second idle period");

        // First connection - do a successful LIST
        Log("=== First connection ===");
        var client1 = await ConnectAndAuthenticateAsync();
        var (reader1, writer1, sslStream1) = client1;

        // Do a successful LIST
        await DoSuccessfulListAsync(reader1, writer1, "/");
        Log("First LIST completed successfully");

        // Now wait for the connection to go idle
        Log($"Waiting {idleSeconds} seconds for idle disconnect...");
        await Task.Delay(TimeSpan.FromSeconds(idleSeconds));

        // Try to do another LIST - this might fail due to TLS termination
        Log("Attempting second LIST after idle period...");
        bool secondListSucceeded = false;
        try
        {
            await DoSuccessfulListAsync(reader1, writer1, "/");
            secondListSucceeded = true;
            Log("Second LIST succeeded (no idle disconnect occurred)");
        }
        catch (Exception ex)
        {
            Log($"Second LIST failed (expected): {ex.GetType().Name}: {ex.Message}");
            // This is expected - the connection should have dropped
        }

        // Now try a new connection - this is where the state corruption would show
        Log("=== Second connection (testing state corruption) ===");
        bool reconnectSucceeded = false;
        int reconnectAttempts = 0;
        const int maxReconnectAttempts = 5;

        while (reconnectAttempts < maxReconnectAttempts && !reconnectSucceeded)
        {
            reconnectAttempts++;
            Log($"Reconnect attempt {reconnectAttempts}/{maxReconnectAttempts}");

            try
            {
                var client2 = await ConnectAndAuthenticateAsync();
                var (reader2, writer2, sslStream2) = client2;

                // Try to LIST
                await DoSuccessfulListAsync(reader2, writer2, "/");
                Log($"Reconnect attempt {reconnectAttempts} succeeded!");
                reconnectSucceeded = true;

                // Clean up
                await SendCommandAsync(writer2, "QUIT");
                await ReadResponseAsync(reader2, "QUIT");
            }
            catch (Exception ex)
            {
                Log($"Reconnect attempt {reconnectAttempts} failed: {ex.GetType().Name}: {ex.Message}");
                // Wait a bit before retrying
                if (reconnectAttempts < maxReconnectAttempts)
                {
                    await Task.Delay(500);
                }
            }
        }

        Log($"=== Test Results ===");
        Log($"Second LIST after idle: {(secondListSucceeded ? "SUCCEEDED" : "FAILED (expected)")}");
        Log($"Reconnect succeeded: {reconnectSucceeded} (after {reconnectAttempts} attempts)");

        // The test passes if reconnection eventually works
        // If state corruption is severe, all reconnect attempts would fail
        Assert.True(reconnectSucceeded,
            $"Failed to reconnect after {maxReconnectAttempts} attempts. State may be corrupted.");

        // Ideally, reconnection should work on the first try
        Assert.True(reconnectAttempts <= 2,
            $"Reconnect took {reconnectAttempts} attempts, indicating possible state corruption that recovered.");
    }

    /// <summary>
    /// Test rapid folder navigation followed by idle, followed by more navigation.
    /// This is the exact pattern that causes issues in FileZilla.
    /// </summary>
    [Fact]
    public async Task RapidNavThenIdleThenRapidNav_ShouldWork()
    {
        Log("Starting rapid-idle-rapid navigation test");

        // First connection with rapid navigation
        Log("=== Phase 1: Rapid navigation ===");
        var client = await ConnectAndAuthenticateAsync();
        var (reader, writer, sslStream) = client;

        // Do several rapid LISTs
        var folders = new[] { "/", "/test", "/uploads", "/" };
        foreach (var folder in folders)
        {
            try
            {
                await DoSuccessfulListAsync(reader, writer, folder);
                Log($"LIST {folder} succeeded");
            }
            catch (Exception ex)
            {
                Log($"LIST {folder} failed: {ex.Message}");
            }
        }

        // Wait for idle disconnect
        Log("=== Phase 2: Idle period (6 seconds) ===");
        await Task.Delay(TimeSpan.FromSeconds(6));

        // Try more rapid navigation
        Log("=== Phase 3: More rapid navigation ===");
        bool connectionStillValid = true;
        foreach (var folder in folders)
        {
            try
            {
                await DoSuccessfulListAsync(reader, writer, folder);
                Log($"LIST {folder} succeeded");
            }
            catch (Exception ex)
            {
                Log($"LIST {folder} failed (expected after idle): {ex.Message}");
                connectionStillValid = false;
                break;
            }
        }

        if (!connectionStillValid)
        {
            // Reconnect and continue
            Log("=== Phase 4: Reconnect and continue ===");
            var client2 = await ConnectAndAuthenticateAsync();
            var (reader2, writer2, sslStream2) = client2;

            foreach (var folder in folders)
            {
                await DoSuccessfulListAsync(reader2, writer2, folder);
                Log($"LIST {folder} succeeded after reconnect");
            }

            await SendCommandAsync(writer2, "QUIT");
            await ReadResponseAsync(reader2, "QUIT");
        }
        else
        {
            await SendCommandAsync(writer, "QUIT");
            await ReadResponseAsync(reader, "QUIT");
        }

        Log("Rapid-idle-rapid test completed");
    }

    /// <summary>
    /// Stress test: Run the idle disconnect test multiple times to catch intermittent failures.
    /// </summary>
    [Theory]
    [InlineData(3)]   // 3 cycles
    [InlineData(5)]   // 5 cycles
    public async Task RepeatedIdleDisconnect_ShouldNotAccumulateCorruption(int cycles)
    {
        Log($"Starting repeated idle disconnect test: {cycles} cycles");

        for (int cycle = 0; cycle < cycles; cycle++)
        {
            Log($"=== Cycle {cycle + 1}/{cycles} ===");

            try
            {
                var client = await ConnectAndAuthenticateAsync();
                var (reader, writer, sslStream) = client;

                // Do a LIST
                await DoSuccessfulListAsync(reader, writer, "/");
                Log($"Cycle {cycle + 1}: Initial LIST succeeded");

                // Wait 4 seconds (shorter idle for faster test)
                await Task.Delay(TimeSpan.FromSeconds(4));

                // Try another LIST
                try
                {
                    await DoSuccessfulListAsync(reader, writer, "/");
                    Log($"Cycle {cycle + 1}: Post-idle LIST succeeded");
                }
                catch (Exception ex)
                {
                    Log($"Cycle {cycle + 1}: Post-idle LIST failed (expected): {ex.Message}");
                }

                await SendCommandAsync(writer, "QUIT");
                try { await ReadResponseAsync(reader, "QUIT"); } catch { }
            }
            catch (Exception ex)
            {
                Log($"Cycle {cycle + 1}: FAILED to even connect - state corruption? {ex.Message}");
                Assert.Fail($"Cycle {cycle + 1} failed to connect: {ex.Message}");
            }

            // Small delay between cycles
            await Task.Delay(500);
        }

        Log($"Repeated idle disconnect test completed: {cycles} cycles");
    }

    /// <summary>
    /// Helper: Connect and authenticate, returning the streams.
    /// </summary>
    private async Task<(StreamReader reader, StreamWriter writer, SslStream sslStream)> ConnectAndAuthenticateAsync()
    {
        var client = new TcpClient();
        await client.ConnectAsync(ProxyHost, ProxyPort);
        Log($"Connected to {ProxyHost}:{ProxyPort}");

        Stream stream = client.GetStream();
        var reader = new StreamReader(stream, Encoding.UTF8);
        var writer = new StreamWriter(stream, Encoding.UTF8) { AutoFlush = true };

        // Read welcome banner
        var banner = await ReadResponseAsync(reader, "Banner");
        if (!banner.StartsWith("220"))
        {
            throw new Exception($"Unexpected banner: {banner}");
        }

        // AUTH TLS
        await SendCommandAsync(writer, "AUTH TLS");
        var authResponse = await ReadResponseAsync(reader, "AUTH TLS");
        if (!authResponse.StartsWith("234"))
        {
            throw new Exception($"AUTH TLS failed: {authResponse}");
        }

        // Upgrade to TLS
        var sslStream = new SslStream(stream, false, (sender, cert, chain, errors) => true);
        await sslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = ProxyHost,
            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
        });
        Log($"TLS: {sslStream.SslProtocol}");

        reader = new StreamReader(sslStream, Encoding.UTF8);
        writer = new StreamWriter(sslStream, Encoding.UTF8) { AutoFlush = true };

        // PBSZ 0
        await SendCommandAsync(writer, "PBSZ 0");
        var pbszResponse = await ReadResponseAsync(reader, "PBSZ");

        // PROT P
        await SendCommandAsync(writer, "PROT P");
        var protResponse = await ReadResponseAsync(reader, "PROT P");

        // USER
        await SendCommandAsync(writer, $"USER {Username}");
        var userResponse = await ReadResponseAsync(reader, "USER");

        if (userResponse.StartsWith("331"))
        {
            // PASS
            await SendCommandAsync(writer, $"PASS {Password}");
            var passResponse = await ReadResponseAsync(reader, "PASS");
            if (!passResponse.StartsWith("230"))
            {
                throw new Exception($"Login failed: {passResponse}");
            }
        }

        Log("Authentication complete");
        return (reader, writer, sslStream);
    }

    /// <summary>
    /// Helper: Do a LIST operation and verify it succeeds.
    /// </summary>
    private async Task DoSuccessfulListAsync(StreamReader reader, StreamWriter writer, string folder)
    {
        // CWD if not root
        if (folder != "/")
        {
            await SendCommandAsync(writer, $"CWD {folder}");
            var cwdResponse = await ReadResponseAsync(reader, "CWD");
            // Accept 250 (success) or 550 (not found) - we just want to test the connection
        }

        // EPSV
        await SendCommandAsync(writer, "EPSV");
        var pasvResponse = await ReadResponseAsync(reader, "EPSV");
        if (!pasvResponse.StartsWith("229"))
        {
            throw new Exception($"EPSV failed: {pasvResponse}");
        }

        var dataPort = ParseEpsvPort(pasvResponse);

        // Connect to data channel
        using var dataClient = new TcpClient();
        await dataClient.ConnectAsync(ProxyHost, dataPort);

        // Upgrade data channel to TLS
        var dataSslStream = new SslStream(dataClient.GetStream(), false, (sender, cert, chain, errors) => true);
        await dataSslStream.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = ProxyHost,
            EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13
        });

        // Send LIST command
        await SendCommandAsync(writer, "LIST");
        var listResponse = await ReadResponseAsync(reader, "LIST");
        if (!listResponse.StartsWith("150") && !listResponse.StartsWith("125"))
        {
            throw new Exception($"LIST preliminary failed: {listResponse}");
        }

        // Read directory listing
        var dataReader = new StreamReader(dataSslStream, Encoding.UTF8);
        var listing = new StringBuilder();
        string? line;
        while ((line = await dataReader.ReadLineAsync()) != null)
        {
            listing.AppendLine(line);
        }

        // Close data channel
        dataSslStream.Close();
        dataClient.Close();

        // Read 226 completion
        var completionResponse = await ReadResponseAsync(reader, "226");
        if (!completionResponse.StartsWith("226"))
        {
            throw new Exception($"LIST completion failed: {completionResponse}");
        }
    }
}
