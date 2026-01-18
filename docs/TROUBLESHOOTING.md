# FTP Reverse Proxy Troubleshooting Guide

Quick reference for diagnosing common issues.

## Issue: Transfers Show 0 Bytes

**Symptom:**
```
Data transfer completed: 0 bytes up, 0 bytes down
```

**Likely Cause:** Race condition - relay started before direction was known.

**Check:**
1. Look for "Direction determined" in logs
2. Should see: `Direction determined - isUpload=True, signaled relay to start`
3. If missing, the `DirectionDetermined` signal isn't being sent/received

**Fix:** Ensure `RelayDataAsync()` calls `state.DirectionDetermined.TrySetResult()`

---

## Issue: "Connection closed by server" After Successful Transfer

**Symptom:**
```
Backend connection closed unexpectedly. TcpClient.Connected: True
Drained stale backend response after IOException: 226 Successfully transferred
```

**Likely Cause:** TLS close_notify on data channel confusing backend.

**Check:**
1. Ensure `backendSslStream.SkipTlsShutdownOnDispose()` is called before dispose
2. Backend (FileZilla Server) gets confused by TLS close_notify on data channel

**Note:** This is partially mitigated - if drain finds the 226, file transferred OK.

---

## Issue: TLS Session Resumption Not Working

**Symptom:**
```
TLS session resumption was requested but NOT achieved on data channel
SessionResumed: False
```

**Checks:**
1. Control channel session captured? Look for: `Captured TLS session for data channel resumption`
2. Session still valid? Check `sessionValid=True` in data channel setup log
3. Session serialization working? Check for errors in `CreateSessionForResumption()`

**Common Causes:**
- Session expired (default timeout 300s)
- Session cache full on backend
- Wrong hostname used for session lookup

---

## Issue: Resource Exhaustion Over Time

**Symptom:**
- "No available ports in data channel range"
- Performance degrades over time
- Works initially, then fails

**Checks:**
1. Port exhaustion: Check if ports 30000-30100 are all in use
2. Socket leaks: Look for sockets not being disposed in error paths
3. TLS context leaks: Ensure SSL_free is called for all SSL objects

**In Docker:**
```bash
docker exec ftp-reverse-proxy netstat -an | grep 30 | wc -l
```

---

## Issue: File Truncation at 16KB/32KB Boundaries

**Symptom:**
- Files truncated at exactly 16384 or 32768 bytes
- These are TLS record size boundaries

**Likely Cause:** Concurrent SSL_read/SSL_write on same SSL object.

**Check:**
1. Ensure relay is unidirectional (not bidirectional)
2. Only one task should be reading/writing to each SSL stream
3. Look for: `Starting Upload (client->backend) relay` or `Starting Download (backend->client) relay`

---

## Issue: 0-Byte Files Left on Backend

**Symptom:**
- Failed uploads leave empty files on server
- Overwrite prompts appear for files that should be new

**Cause:** FTP creates file at STOR/150 time, before data transfer.

**Check:**
1. Look for: `Deleting failed upload file: <filename>`
2. Should see: `Successfully deleted failed upload file`
3. If delete fails, check backend permissions

---

## Useful Log Grep Commands

```bash
# Check session resumption status
docker logs ftp-reverse-proxy 2>&1 | grep -i "sessionresumed"

# Check for 0-byte transfers
docker logs ftp-reverse-proxy 2>&1 | grep "0 bytes up, 0 bytes down"

# Check direction signaling
docker logs ftp-reverse-proxy 2>&1 | grep "Direction determined"

# Check for connection closures
docker logs ftp-reverse-proxy 2>&1 | grep "closed unexpectedly"

# Trace a specific session
docker logs ftp-reverse-proxy 2>&1 | grep "Session <session-id>"

# Check for errors
docker logs ftp-reverse-proxy 2>&1 | grep -E "(ERR|Error|error|failed|Failed)"
```

## Log Levels

Set in `appsettings.json`:
```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "FtpReverseProxy": "Debug"
    }
  }
}
```

Debug level shows:
- Every command sent/received
- TLS handshake details
- Relay byte counts per read/write
- Timing information

## Architecture Quick Reference

```
Client                    Proxy                      Backend
  |                         |                          |
  |--[Control Channel TLS]--|--[Control Channel TLS]---|
  |    (OpenSslServer)      |    (OpenSslTlsStream)    |
  |                         |                          |
  |--[Data Channel TLS]-----|--[Data Channel TLS]------|
  |    (OpenSslServer)      |    (OpenSslTlsStream)    |
  |                         |    + Session Resumption  |
```

Key timing:
1. PASV -> Data listener starts, AcceptPassiveConnectionAsync fires
2. Client connects -> TLS handshake, RelayBidirectionalAsync waits
3. STOR/RETR/LIST -> RelayDataAsync signals direction
4. Relay reads direction, starts copying correct way
