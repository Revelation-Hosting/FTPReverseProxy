using System.Buffers.Binary;
using System.Text;

namespace FtpReverseProxy.Sftp.Protocol;

/// <summary>
/// Writes SFTP packet data in network byte order (big-endian)
/// </summary>
public class SftpPacketWriter : IDisposable
{
    private readonly MemoryStream _stream;
    private readonly BinaryWriter _writer;

    public SftpPacketWriter(int initialCapacity = 256)
    {
        _stream = new MemoryStream(initialCapacity);
        _writer = new BinaryWriter(_stream);

        // Reserve space for length prefix (will be filled in ToPacket)
        _writer.Write(0);
    }

    public void WriteByte(byte value)
    {
        _writer.Write(value);
    }

    public void WriteUInt32(uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
        _writer.Write(buffer);
    }

    public void WriteUInt64(ulong value)
    {
        Span<byte> buffer = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(buffer, value);
        _writer.Write(buffer);
    }

    public void WriteString(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value);
        WriteUInt32((uint)bytes.Length);
        _writer.Write(bytes);
    }

    public void WriteBytes(byte[] data)
    {
        WriteUInt32((uint)data.Length);
        _writer.Write(data);
    }

    public void WriteBytes(ReadOnlySpan<byte> data)
    {
        WriteUInt32((uint)data.Length);
        _writer.Write(data);
    }

    public void WriteBytesRaw(byte[] data)
    {
        _writer.Write(data);
    }

    public void WriteBytesRaw(ReadOnlySpan<byte> data)
    {
        _writer.Write(data);
    }

    public void WriteAttributes(SftpFileAttributes attrs)
    {
        WriteUInt32((uint)attrs.Flags);

        if (attrs.Flags.HasFlag(SftpAttributeFlags.Size))
        {
            WriteUInt64(attrs.Size);
        }

        if (attrs.Flags.HasFlag(SftpAttributeFlags.UidGid))
        {
            WriteUInt32(attrs.Uid);
            WriteUInt32(attrs.Gid);
        }

        if (attrs.Flags.HasFlag(SftpAttributeFlags.Permissions))
        {
            WriteUInt32(attrs.Permissions);
        }

        if (attrs.Flags.HasFlag(SftpAttributeFlags.AccessTime))
        {
            WriteUInt32(attrs.AccessTime);
            WriteUInt32(attrs.ModifyTime);
        }

        if (attrs.Flags.HasFlag(SftpAttributeFlags.Extended))
        {
            WriteUInt32((uint)attrs.ExtendedAttributes.Count);
            foreach (var (name, value) in attrs.ExtendedAttributes)
            {
                WriteString(name);
                WriteString(value);
            }
        }
    }

    /// <summary>
    /// Gets the complete packet with length prefix
    /// </summary>
    public byte[] ToPacket()
    {
        _writer.Flush();
        var data = _stream.ToArray();

        // Write length prefix (packet length excluding the 4-byte length field itself)
        var length = data.Length - 4;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(0, 4), (uint)length);

        return data;
    }

    public void Dispose()
    {
        _writer.Dispose();
        _stream.Dispose();
    }
}

/// <summary>
/// Helper methods for creating common SFTP response packets
/// </summary>
public static class SftpPacketBuilder
{
    public static byte[] CreateVersionPacket(uint version)
    {
        using var writer = new SftpPacketWriter();
        writer.WriteByte(SftpPacketType.Version);
        writer.WriteUInt32(version);
        return writer.ToPacket();
    }

    public static byte[] CreateStatusPacket(uint requestId, uint statusCode, string message = "", string language = "en")
    {
        using var writer = new SftpPacketWriter();
        writer.WriteByte(SftpPacketType.Status);
        writer.WriteUInt32(requestId);
        writer.WriteUInt32(statusCode);
        writer.WriteString(message);
        writer.WriteString(language);
        return writer.ToPacket();
    }

    public static byte[] CreateHandlePacket(uint requestId, byte[] handle)
    {
        using var writer = new SftpPacketWriter();
        writer.WriteByte(SftpPacketType.Handle);
        writer.WriteUInt32(requestId);
        writer.WriteBytes(handle);
        return writer.ToPacket();
    }

    public static byte[] CreateDataPacket(uint requestId, byte[] data)
    {
        using var writer = new SftpPacketWriter();
        writer.WriteByte(SftpPacketType.Data);
        writer.WriteUInt32(requestId);
        writer.WriteBytes(data);
        return writer.ToPacket();
    }

    public static byte[] CreateNamePacket(uint requestId, IEnumerable<(string FileName, string LongName, SftpFileAttributes Attrs)> entries)
    {
        var entryList = entries.ToList();

        using var writer = new SftpPacketWriter();
        writer.WriteByte(SftpPacketType.Name);
        writer.WriteUInt32(requestId);
        writer.WriteUInt32((uint)entryList.Count);

        foreach (var (fileName, longName, attrs) in entryList)
        {
            writer.WriteString(fileName);
            writer.WriteString(longName);
            writer.WriteAttributes(attrs);
        }

        return writer.ToPacket();
    }

    public static byte[] CreateAttrsPacket(uint requestId, SftpFileAttributes attrs)
    {
        using var writer = new SftpPacketWriter();
        writer.WriteByte(SftpPacketType.Attrs);
        writer.WriteUInt32(requestId);
        writer.WriteAttributes(attrs);
        return writer.ToPacket();
    }
}
