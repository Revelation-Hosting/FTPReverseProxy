using System.Buffers.Binary;
using System.Text;

namespace FtpReverseProxy.Sftp.Protocol;

/// <summary>
/// Reads SFTP packet data in network byte order (big-endian)
/// </summary>
public ref struct SftpPacketReader
{
    private ReadOnlySpan<byte> _data;
    private int _position;

    public SftpPacketReader(ReadOnlySpan<byte> data)
    {
        _data = data;
        _position = 0;
    }

    public int Position => _position;
    public int Remaining => _data.Length - _position;
    public bool HasData => _position < _data.Length;

    public byte ReadByte()
    {
        if (_position >= _data.Length)
            throw new InvalidOperationException("End of packet data");

        return _data[_position++];
    }

    public uint ReadUInt32()
    {
        if (_position + 4 > _data.Length)
            throw new InvalidOperationException("Not enough data for uint32");

        var value = BinaryPrimitives.ReadUInt32BigEndian(_data.Slice(_position, 4));
        _position += 4;
        return value;
    }

    public ulong ReadUInt64()
    {
        if (_position + 8 > _data.Length)
            throw new InvalidOperationException("Not enough data for uint64");

        var value = BinaryPrimitives.ReadUInt64BigEndian(_data.Slice(_position, 8));
        _position += 8;
        return value;
    }

    public string ReadString()
    {
        var length = (int)ReadUInt32();
        if (_position + length > _data.Length)
            throw new InvalidOperationException("Not enough data for string");

        var value = Encoding.UTF8.GetString(_data.Slice(_position, length));
        _position += length;
        return value;
    }

    public byte[] ReadBytes()
    {
        var length = (int)ReadUInt32();
        if (_position + length > _data.Length)
            throw new InvalidOperationException("Not enough data for bytes");

        var value = _data.Slice(_position, length).ToArray();
        _position += length;
        return value;
    }

    public byte[] ReadBytes(int length)
    {
        if (_position + length > _data.Length)
            throw new InvalidOperationException("Not enough data for bytes");

        var value = _data.Slice(_position, length).ToArray();
        _position += length;
        return value;
    }

    public ReadOnlySpan<byte> ReadRemainingBytes()
    {
        var remaining = _data.Slice(_position);
        _position = _data.Length;
        return remaining;
    }

    public SftpFileAttributes ReadAttributes()
    {
        var flags = (SftpAttributeFlags)ReadUInt32();
        var attrs = new SftpFileAttributes { Flags = flags };

        if (flags.HasFlag(SftpAttributeFlags.Size))
        {
            attrs.Size = ReadUInt64();
        }

        if (flags.HasFlag(SftpAttributeFlags.UidGid))
        {
            attrs.Uid = ReadUInt32();
            attrs.Gid = ReadUInt32();
        }

        if (flags.HasFlag(SftpAttributeFlags.Permissions))
        {
            attrs.Permissions = ReadUInt32();
        }

        if (flags.HasFlag(SftpAttributeFlags.AccessTime))
        {
            attrs.AccessTime = ReadUInt32();
            attrs.ModifyTime = ReadUInt32();
        }

        if (flags.HasFlag(SftpAttributeFlags.Extended))
        {
            var extendedCount = ReadUInt32();
            for (var i = 0; i < extendedCount; i++)
            {
                var name = ReadString();
                var value = ReadString();
                attrs.ExtendedAttributes[name] = value;
            }
        }

        return attrs;
    }
}

/// <summary>
/// SFTP file attributes
/// </summary>
public class SftpFileAttributes
{
    public SftpAttributeFlags Flags { get; set; }
    public ulong Size { get; set; }
    public uint Uid { get; set; }
    public uint Gid { get; set; }
    public uint Permissions { get; set; }
    public uint AccessTime { get; set; }
    public uint ModifyTime { get; set; }
    public Dictionary<string, string> ExtendedAttributes { get; } = new();

    public bool IsDirectory => (Permissions & 0x4000) != 0;
    public bool IsRegularFile => (Permissions & 0x8000) != 0;
    public bool IsSymbolicLink => (Permissions & 0xA000) == 0xA000;
}
