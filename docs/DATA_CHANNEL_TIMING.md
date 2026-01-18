# FTP Data Channel Timing and the Critical Race Condition

This document describes a critical timing issue in FTP data channel handling that caused
transfer failures under concurrent load, and the solution implemented to fix it.

## Background: FTP Dual-Channel Architecture

FTP uses two separate connections:
1. **Control Channel** - Port 21, carries commands (USER, PASS, STOR, RETR, LIST, etc.)
2. **Data Channel** - Dynamic port, carries file data and directory listings

In **passive mode** (PASV/EPSV), the sequence is:
1. Client sends `PASV` command on control channel
2. Server responds with IP/port for data connection
3. Client connects to that IP/port (data channel established)
4. Client sends transfer command (`STOR`, `RETR`, `LIST`, etc.) on control channel
5. Server sends `150` response
6. Data flows on data channel
7. Server sends `226` when complete

**The critical insight**: The data channel is established (step 3) BEFORE the transfer
command is sent (step 4). This means the proxy's data channel relay is ready before
we know whether it's an upload or download.

## The Race Condition Bug

### Symptom
- Uploads would transfer 0 bytes
- Backend would receive empty files
- Problem got worse under concurrent load
- Direct connections to backend worked fine

### Root Cause

In `DataChannelManager.cs`, the flow was:

```
1. PASV received
2. SetupPassiveRelayAsync() creates listener, starts AcceptPassiveConnectionAsync()
3. Client connects to data channel
4. AcceptPassiveConnectionAsync() does TLS handshake
5. RelayBidirectionalAsync() starts immediately
6. RelayBidirectionalAsync reads state.IsUpload (which is FALSE - default!)
7. Relay starts in DOWNLOAD mode (backend -> client)

Meanwhile on control channel:
8. Client sends STOR
9. RelayDataAsync() sets state.IsUpload = TRUE  <-- TOO LATE!
```

The relay was already running in the wrong direction by step 7. For uploads,
we were reading from the backend (which had no data to send) instead of
reading from the client.

### Code Before (Broken)

```csharp
private async Task RelayBidirectionalAsync(...)
{
    // TLS handshake completes...

    // BUG: IsUpload is still false here!
    var isUpload = state.IsUpload;

    if (isUpload)
        relayTask = RelayStreamAsync(clientStream, backendStream, ...); // Upload
    else
        relayTask = RelayStreamAsync(backendStream, clientStream, ...); // Download

    await relayTask;
}
```

## The Solution

### 1. Add a Synchronization Signal

In `DataChannelState.cs`:
```csharp
/// <summary>
/// Signals when the transfer direction (upload/download) has been determined.
/// The relay must wait for this before starting to copy data.
/// </summary>
public TaskCompletionSource DirectionDetermined { get; } = new();
```

### 2. Signal When Direction is Known

In `DataChannelManager.RelayDataAsync()` (called when STOR/RETR/LIST is received):
```csharp
state.IsUsed = true;
state.IsUpload = isUpload;

// CRITICAL: Signal that the transfer direction is now known.
state.DirectionDetermined.TrySetResult();
```

### 3. Wait for Signal Before Starting Relay

In `DataChannelManager.RelayBidirectionalAsync()`:
```csharp
// Wait until we know the transfer direction!
_logger.LogDebug("Data channel ready, waiting for transfer command...");

await state.DirectionDetermined.Task.WaitAsync(TimeSpan.FromSeconds(30), cancellationToken);

var isUpload = state.IsUpload;  // NOW this has the correct value

if (isUpload)
    relayTask = RelayStreamAsync(clientStream, backendStream, ...);
else
    relayTask = RelayStreamAsync(backendStream, clientStream, ...);
```

### Correct Flow After Fix

```
1. PASV received
2. SetupPassiveRelayAsync() creates listener, starts AcceptPassiveConnectionAsync()
3. Client connects to data channel
4. AcceptPassiveConnectionAsync() does TLS handshake
5. RelayBidirectionalAsync() starts
6. RelayBidirectionalAsync WAITS on DirectionDetermined signal  <-- NEW!

Meanwhile on control channel:
7. Client sends STOR
8. RelayDataAsync() sets state.IsUpload = TRUE
9. RelayDataAsync() signals DirectionDetermined  <-- NEW!

Back in data channel:
10. RelayBidirectionalAsync receives signal, reads state.IsUpload (now TRUE)
11. Relay starts in UPLOAD mode (client -> backend)  <-- CORRECT!
```

## Why This Only Affected Concurrent Load

Under light load, the timing often worked out:
- Single connection, slow client = STOR command arrives before TLS handshake completes
- Relay starts after IsUpload is already set

Under heavy load:
- Multiple connections compete for resources
- TLS handshakes complete faster relative to command processing
- Race condition triggers more frequently
- "The more it runs the worse it gets" - as connections accumulated, timing got tighter

## Related Fixes

### 1. TLS close_notify to Backend

FileZilla Server would close the CONTROL channel when receiving TLS close_notify
on the DATA channel. Solution: Skip TLS shutdown to backend, just close the socket.

### 2. 0-Byte File Cleanup

When uploads fail, the backend has already created an empty file (at STOR/150 time).
Solution: Send DELE command to remove the empty file on failure.

### 3. Resource Leaks

Sockets weren't being disposed in error paths (e.g., backend connection fails after
client connects). Solution: Proper try/finally cleanup in AcceptPassiveConnectionAsync.

## Debugging Tips

### Log Messages to Look For

**Good (direction determined correctly):**
```
Data channel ready, waiting for transfer command to determine direction...
Direction determined - isUpload=True, signaled relay to start
Transfer direction determined - UPLOAD (client->backend)
```

**Bad (0 bytes transferred):**
```
Data transfer completed: 0 bytes up, 0 bytes down
```

### Key Files

- `DataChannelManager.cs` - Main data channel logic, relay implementation
- `DataChannelState.cs` - State tracking including DirectionDetermined signal
- `FtpSessionHandler.cs` - Control channel handling, calls RelayDataAsync

## Remaining Known Issue

Occasionally, the 226 response read from the control channel fails with IOException,
even though the transfer succeeded. The response can be "drained" and found, and
retry succeeds. This appears to be a minor TLS timing issue between data channel
closure and control channel read. Low priority since retry handles it.
