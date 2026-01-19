using Microsoft.Extensions.Logging;
using Renci.SshNet;
using Renci.SshNet.Sftp;
using System.Collections.Concurrent;
using System.Text;

namespace FtpReverseProxy.Sftp.Protocol;

/// <summary>
/// Proxies SFTP operations between client and backend server.
/// Parses incoming SFTP packets and translates them to SSH.NET operations.
/// </summary>
public class SftpProxy : IDisposable
{
    private readonly SftpClient _backend;
    private readonly ILogger _logger;
    private readonly Action<byte[]> _sendToClient;

    // Handle management - maps client handles to backend handles/streams
    private readonly ConcurrentDictionary<string, SftpFileStream> _fileHandles = new();
    private readonly ConcurrentDictionary<string, DirectoryHandle> _dirHandles = new();
    private int _handleCounter;

    private uint _clientVersion;

    public SftpProxy(SftpClient backend, Action<byte[]> sendToClient, ILogger logger)
    {
        _backend = backend;
        _sendToClient = sendToClient;
        _logger = logger;
    }

    /// <summary>
    /// Process an incoming SFTP packet from the client
    /// </summary>
    public void ProcessPacket(byte[] packetData)
    {
        if (packetData.Length < 5)
        {
            _logger.LogWarning("SFTP packet too short: {Length} bytes", packetData.Length);
            return;
        }

        // Parse packet: 4-byte length + 1-byte type + payload
        var reader = new SftpPacketReader(packetData.AsSpan(4)); // Skip length prefix
        var packetType = reader.ReadByte();

        _logger.LogDebug("Processing SFTP packet: {Type}", SftpPacketType.GetName(packetType));

        try
        {
            switch (packetType)
            {
                case SftpPacketType.Init:
                    HandleInit(ref reader);
                    break;

                case SftpPacketType.Open:
                    HandleOpen(ref reader);
                    break;

                case SftpPacketType.Close:
                    HandleClose(ref reader);
                    break;

                case SftpPacketType.Read:
                    HandleRead(ref reader);
                    break;

                case SftpPacketType.Write:
                    HandleWrite(ref reader);
                    break;

                case SftpPacketType.Lstat:
                    HandleLstat(ref reader);
                    break;

                case SftpPacketType.Fstat:
                    HandleFstat(ref reader);
                    break;

                case SftpPacketType.Setstat:
                    HandleSetstat(ref reader);
                    break;

                case SftpPacketType.Opendir:
                    HandleOpendir(ref reader);
                    break;

                case SftpPacketType.Readdir:
                    HandleReaddir(ref reader);
                    break;

                case SftpPacketType.Remove:
                    HandleRemove(ref reader);
                    break;

                case SftpPacketType.Mkdir:
                    HandleMkdir(ref reader);
                    break;

                case SftpPacketType.Rmdir:
                    HandleRmdir(ref reader);
                    break;

                case SftpPacketType.Realpath:
                    HandleRealpath(ref reader);
                    break;

                case SftpPacketType.Stat:
                    HandleStat(ref reader);
                    break;

                case SftpPacketType.Rename:
                    HandleRename(ref reader);
                    break;

                case SftpPacketType.Readlink:
                    HandleReadlink(ref reader);
                    break;

                case SftpPacketType.Symlink:
                    HandleSymlink(ref reader);
                    break;

                default:
                    _logger.LogWarning("Unsupported SFTP packet type: {Type}", packetType);
                    // We can't send a proper error without a request ID
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing SFTP packet type {Type}", SftpPacketType.GetName(packetType));
        }
    }

    private void HandleInit(ref SftpPacketReader reader)
    {
        _clientVersion = reader.ReadUInt32();
        _logger.LogDebug("Client SFTP version: {Version}", _clientVersion);

        // Respond with VERSION packet (we support SFTP v3)
        var response = SftpPacketBuilder.CreateVersionPacket(3);
        _sendToClient(response);
    }

    private void HandleOpen(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var path = reader.ReadString();
        var pflags = (SftpOpenFlags)reader.ReadUInt32();
        var attrs = reader.ReadAttributes();

        _logger.LogDebug("OPEN: {Path} flags={Flags}", path, pflags);

        try
        {
            // Map SFTP flags to .NET FileMode/FileAccess
            var mode = MapOpenFlags(pflags, out var access);

            var stream = _backend.Open(path, mode, access);
            var handle = GenerateHandle();

            _fileHandles[handle] = stream;

            var response = SftpPacketBuilder.CreateHandlePacket(requestId, Encoding.UTF8.GetBytes(handle));
            _sendToClient(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error opening file: {Path}", path);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleClose(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var handleBytes = reader.ReadBytes();
        var handle = Encoding.UTF8.GetString(handleBytes);

        _logger.LogDebug("CLOSE: handle={Handle}", handle);

        try
        {
            if (_fileHandles.TryRemove(handle, out var stream))
            {
                stream.Close();
                stream.Dispose();
            }
            else if (_dirHandles.TryRemove(handle, out var dirHandle))
            {
                // Directory handles are just markers, nothing to close
            }
            else
            {
                SendStatus(requestId, SftpStatusCode.Failure, "Invalid handle");
                return;
            }

            SendStatus(requestId, SftpStatusCode.Ok, "Success");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error closing handle: {Handle}", handle);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleRead(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var handleBytes = reader.ReadBytes();
        var handle = Encoding.UTF8.GetString(handleBytes);
        var offset = reader.ReadUInt64();
        var length = reader.ReadUInt32();

        _logger.LogDebug("READ: handle={Handle} offset={Offset} length={Length}", handle, offset, length);

        try
        {
            if (!_fileHandles.TryGetValue(handle, out var stream))
            {
                SendStatus(requestId, SftpStatusCode.Failure, "Invalid handle");
                return;
            }

            stream.Position = (long)offset;
            var buffer = new byte[length];
            var bytesRead = stream.Read(buffer, 0, (int)length);

            if (bytesRead == 0)
            {
                SendStatus(requestId, SftpStatusCode.Eof, "End of file");
                return;
            }

            var data = bytesRead == length ? buffer : buffer[..bytesRead];
            var response = SftpPacketBuilder.CreateDataPacket(requestId, data);
            _sendToClient(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error reading from handle: {Handle}", handle);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleWrite(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var handleBytes = reader.ReadBytes();
        var handle = Encoding.UTF8.GetString(handleBytes);
        var offset = reader.ReadUInt64();
        var data = reader.ReadBytes();

        _logger.LogDebug("WRITE: handle={Handle} offset={Offset} length={Length}", handle, offset, data.Length);

        try
        {
            if (!_fileHandles.TryGetValue(handle, out var stream))
            {
                SendStatus(requestId, SftpStatusCode.Failure, "Invalid handle");
                return;
            }

            stream.Position = (long)offset;
            stream.Write(data, 0, data.Length);

            SendStatus(requestId, SftpStatusCode.Ok, "Success");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error writing to handle: {Handle}", handle);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleLstat(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var path = reader.ReadString();

        _logger.LogDebug("LSTAT: {Path}", path);

        try
        {
            var attrs = _backend.GetAttributes(path);
            SendAttrs(requestId, attrs);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting attributes: {Path}", path);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleFstat(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var handleBytes = reader.ReadBytes();
        var handle = Encoding.UTF8.GetString(handleBytes);

        _logger.LogDebug("FSTAT: handle={Handle}", handle);

        try
        {
            if (!_fileHandles.TryGetValue(handle, out var stream))
            {
                SendStatus(requestId, SftpStatusCode.Failure, "Invalid handle");
                return;
            }

            // Get attributes for the file path associated with the stream
            var attrs = _backend.GetAttributes(stream.Name);
            SendAttrs(requestId, attrs);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting file attributes: {Handle}", handle);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleSetstat(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var path = reader.ReadString();
        var attrs = reader.ReadAttributes();

        _logger.LogDebug("SETSTAT: {Path}", path);

        try
        {
            // SSH.NET's SetAttributes is limited, but we can try
            if (attrs.Flags.HasFlag(SftpAttributeFlags.Permissions))
            {
                // Would need to convert permissions to SftpFileAttributes
            }

            // For now, just acknowledge
            SendStatus(requestId, SftpStatusCode.Ok, "Success");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error setting attributes: {Path}", path);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleOpendir(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var path = reader.ReadString();

        _logger.LogDebug("OPENDIR: {Path}", path);

        try
        {
            // Verify directory exists and is readable
            var entries = _backend.ListDirectory(path).ToList();

            var handle = GenerateHandle();
            _dirHandles[handle] = new DirectoryHandle(path, entries);

            var response = SftpPacketBuilder.CreateHandlePacket(requestId, Encoding.UTF8.GetBytes(handle));
            _sendToClient(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error opening directory: {Path}", path);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleReaddir(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var handleBytes = reader.ReadBytes();
        var handle = Encoding.UTF8.GetString(handleBytes);

        _logger.LogDebug("READDIR: handle={Handle}", handle);

        try
        {
            if (!_dirHandles.TryGetValue(handle, out var dirHandle))
            {
                SendStatus(requestId, SftpStatusCode.Failure, "Invalid handle");
                return;
            }

            // Return a batch of entries
            var entries = dirHandle.GetNextBatch(100);

            if (entries.Count == 0)
            {
                SendStatus(requestId, SftpStatusCode.Eof, "End of directory");
                return;
            }

            var nameEntries = entries.Select(e => (
                FileName: e.Name,
                LongName: FormatLongName(e),
                Attrs: ConvertAttributes(e.Attributes)
            ));

            var response = SftpPacketBuilder.CreateNamePacket(requestId, nameEntries);
            _sendToClient(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error reading directory: {Handle}", handle);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleRemove(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var path = reader.ReadString();

        _logger.LogDebug("REMOVE: {Path}", path);

        try
        {
            _backend.Delete(path);
            SendStatus(requestId, SftpStatusCode.Ok, "Success");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing file: {Path}", path);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleMkdir(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var path = reader.ReadString();
        var attrs = reader.ReadAttributes();

        _logger.LogDebug("MKDIR: {Path}", path);

        try
        {
            // Check if directory already exists (race condition with parallel connections)
            if (_backend.Exists(path))
            {
                var existingAttrs = _backend.GetAttributes(path);
                if (existingAttrs.IsDirectory)
                {
                    // Directory already exists - treat as success
                    SendStatus(requestId, SftpStatusCode.Ok, "Success");
                    return;
                }
                // Path exists but is a file
                SendStatus(requestId, SftpStatusCode.Failure, "Path exists and is not a directory");
                return;
            }

            _backend.CreateDirectory(path);
            SendStatus(requestId, SftpStatusCode.Ok, "Success");
        }
        catch (Exception ex)
        {
            // Also handle race condition where directory was created between Exists check and CreateDirectory
            if (ex.Message.Contains("already exists", StringComparison.OrdinalIgnoreCase) ||
                ex.Message.Contains("file exists", StringComparison.OrdinalIgnoreCase))
            {
                SendStatus(requestId, SftpStatusCode.Ok, "Success");
                return;
            }
            _logger.LogError(ex, "Error creating directory: {Path}", path);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleRmdir(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var path = reader.ReadString();

        _logger.LogDebug("RMDIR: {Path}", path);

        try
        {
            _backend.DeleteDirectory(path);
            SendStatus(requestId, SftpStatusCode.Ok, "Success");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error removing directory: {Path}", path);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleRealpath(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var path = reader.ReadString();

        _logger.LogDebug("REALPATH: {Path}", path);

        try
        {
            var realPath = _backend.GetAttributes(path).IsDirectory
                ? path
                : path; // SSH.NET doesn't have a direct realpath, use as-is

            // Normalize path
            if (string.IsNullOrEmpty(path) || path == ".")
            {
                realPath = _backend.WorkingDirectory;
            }

            var attrs = new SftpFileAttributes
            {
                Flags = 0 // No attributes for realpath response
            };

            var response = SftpPacketBuilder.CreateNamePacket(requestId, new[]
            {
                (FileName: realPath, LongName: realPath, Attrs: attrs)
            });
            _sendToClient(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error resolving path: {Path}", path);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleStat(ref SftpPacketReader reader)
    {
        // STAT follows symlinks, LSTAT doesn't
        // SSH.NET's GetAttributes follows symlinks by default
        HandleLstat(ref reader);
    }

    private void HandleRename(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var oldPath = reader.ReadString();
        var newPath = reader.ReadString();

        _logger.LogDebug("RENAME: {OldPath} -> {NewPath}", oldPath, newPath);

        try
        {
            _backend.RenameFile(oldPath, newPath);
            SendStatus(requestId, SftpStatusCode.Ok, "Success");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error renaming: {OldPath} -> {NewPath}", oldPath, newPath);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleReadlink(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var path = reader.ReadString();

        _logger.LogDebug("READLINK: {Path}", path);

        try
        {
            var target = _backend.GetAttributes(path).ToString(); // SSH.NET doesn't have direct symlink reading
            SendStatus(requestId, SftpStatusCode.OpUnsupported, "Operation not supported");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error reading link: {Path}", path);
            SendStatusError(requestId, ex);
        }
    }

    private void HandleSymlink(ref SftpPacketReader reader)
    {
        var requestId = reader.ReadUInt32();
        var linkPath = reader.ReadString();
        var targetPath = reader.ReadString();

        _logger.LogDebug("SYMLINK: {LinkPath} -> {TargetPath}", linkPath, targetPath);

        try
        {
            _backend.SymbolicLink(linkPath, targetPath);
            SendStatus(requestId, SftpStatusCode.Ok, "Success");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating symlink: {LinkPath} -> {TargetPath}", linkPath, targetPath);
            SendStatusError(requestId, ex);
        }
    }

    private void SendStatus(uint requestId, uint statusCode, string message)
    {
        var response = SftpPacketBuilder.CreateStatusPacket(requestId, statusCode, message);
        _sendToClient(response);
    }

    private void SendStatusError(uint requestId, Exception ex)
    {
        var statusCode = ex switch
        {
            Renci.SshNet.Common.SftpPathNotFoundException => SftpStatusCode.NoSuchFile,
            Renci.SshNet.Common.SftpPermissionDeniedException => SftpStatusCode.PermissionDenied,
            _ => SftpStatusCode.Failure
        };

        SendStatus(requestId, statusCode, ex.Message);
    }

    private void SendAttrs(uint requestId, Renci.SshNet.Sftp.SftpFileAttributes backendAttrs)
    {
        var attrs = ConvertAttributes(backendAttrs);
        var response = SftpPacketBuilder.CreateAttrsPacket(requestId, attrs);
        _sendToClient(response);
    }

    private static SftpFileAttributes ConvertAttributes(Renci.SshNet.Sftp.SftpFileAttributes backendAttrs)
    {
        var flags = SftpAttributeFlags.Size | SftpAttributeFlags.UidGid |
                    SftpAttributeFlags.Permissions | SftpAttributeFlags.AccessTime;

        return new SftpFileAttributes
        {
            Flags = flags,
            Size = (ulong)backendAttrs.Size,
            Uid = (uint)backendAttrs.UserId,
            Gid = (uint)backendAttrs.GroupId,
            Permissions = (uint)(backendAttrs.IsDirectory ? 0x4000 : 0x8000) |
                          (uint)(backendAttrs.OwnerCanRead ? 0x0100 : 0) |
                          (uint)(backendAttrs.OwnerCanWrite ? 0x0080 : 0) |
                          (uint)(backendAttrs.OwnerCanExecute ? 0x0040 : 0) |
                          (uint)(backendAttrs.GroupCanRead ? 0x0020 : 0) |
                          (uint)(backendAttrs.GroupCanWrite ? 0x0010 : 0) |
                          (uint)(backendAttrs.GroupCanExecute ? 0x0008 : 0) |
                          (uint)(backendAttrs.OthersCanRead ? 0x0004 : 0) |
                          (uint)(backendAttrs.OthersCanWrite ? 0x0002 : 0) |
                          (uint)(backendAttrs.OthersCanExecute ? 0x0001 : 0),
            AccessTime = (uint)(backendAttrs.LastAccessTime.Subtract(DateTime.UnixEpoch).TotalSeconds),
            ModifyTime = (uint)(backendAttrs.LastWriteTime.Subtract(DateTime.UnixEpoch).TotalSeconds)
        };
    }

    private static string FormatLongName(ISftpFile file)
    {
        var attrs = file.Attributes;
        var typeChar = attrs.IsDirectory ? 'd' : attrs.IsSymbolicLink ? 'l' : '-';

        var perms = $"{typeChar}" +
                    $"{(attrs.OwnerCanRead ? 'r' : '-')}{(attrs.OwnerCanWrite ? 'w' : '-')}{(attrs.OwnerCanExecute ? 'x' : '-')}" +
                    $"{(attrs.GroupCanRead ? 'r' : '-')}{(attrs.GroupCanWrite ? 'w' : '-')}{(attrs.GroupCanExecute ? 'x' : '-')}" +
                    $"{(attrs.OthersCanRead ? 'r' : '-')}{(attrs.OthersCanWrite ? 'w' : '-')}{(attrs.OthersCanExecute ? 'x' : '-')}";

        return $"{perms}   1 {attrs.UserId,5} {attrs.GroupId,5} {attrs.Size,10} {attrs.LastWriteTime:MMM dd HH:mm} {file.Name}";
    }

    private static FileMode MapOpenFlags(SftpOpenFlags flags, out FileAccess access)
    {
        access = FileAccess.Read;
        var mode = FileMode.Open;

        if (flags.HasFlag(SftpOpenFlags.Write))
        {
            access = flags.HasFlag(SftpOpenFlags.Read) ? FileAccess.ReadWrite : FileAccess.Write;
        }

        // Handle Create + Truncate combination (common for uploads)
        // FileMode.Create = create new file or truncate existing
        if (flags.HasFlag(SftpOpenFlags.Create) && flags.HasFlag(SftpOpenFlags.Truncate))
        {
            mode = FileMode.Create;
        }
        else if (flags.HasFlag(SftpOpenFlags.Create))
        {
            mode = flags.HasFlag(SftpOpenFlags.Exclusive) ? FileMode.CreateNew : FileMode.OpenOrCreate;
        }
        else if (flags.HasFlag(SftpOpenFlags.Truncate))
        {
            mode = FileMode.Truncate;
        }

        if (flags.HasFlag(SftpOpenFlags.Append))
        {
            mode = FileMode.Append;
        }

        return mode;
    }

    private string GenerateHandle()
    {
        return $"h{Interlocked.Increment(ref _handleCounter):X8}";
    }

    public void Dispose()
    {
        foreach (var stream in _fileHandles.Values)
        {
            try { stream.Dispose(); } catch { }
        }
        _fileHandles.Clear();
        _dirHandles.Clear();
    }

    private class DirectoryHandle
    {
        private readonly string _path;
        private readonly List<ISftpFile> _entries;
        private int _position;

        public DirectoryHandle(string path, List<ISftpFile> entries)
        {
            _path = path;
            _entries = entries;
            _position = 0;
        }

        public List<ISftpFile> GetNextBatch(int count)
        {
            var batch = _entries.Skip(_position).Take(count).ToList();
            _position += batch.Count;
            return batch;
        }
    }
}
