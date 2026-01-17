namespace FtpReverseProxy.Sftp.Protocol;

/// <summary>
/// SFTP protocol packet types (SSH_FXP_*)
/// Based on draft-ietf-secsh-filexfer-02 (SFTP v3)
/// </summary>
public static class SftpPacketType
{
    // Request types
    public const byte Init = 1;
    public const byte Open = 3;
    public const byte Close = 4;
    public const byte Read = 5;
    public const byte Write = 6;
    public const byte Lstat = 7;
    public const byte Fstat = 8;
    public const byte Setstat = 9;
    public const byte Fsetstat = 10;
    public const byte Opendir = 11;
    public const byte Readdir = 12;
    public const byte Remove = 13;
    public const byte Mkdir = 14;
    public const byte Rmdir = 15;
    public const byte Realpath = 16;
    public const byte Stat = 17;
    public const byte Rename = 18;
    public const byte Readlink = 19;
    public const byte Symlink = 20;

    // Response types
    public const byte Version = 2;
    public const byte Status = 101;
    public const byte Handle = 102;
    public const byte Data = 103;
    public const byte Name = 104;
    public const byte Attrs = 105;

    // Extended
    public const byte Extended = 200;
    public const byte ExtendedReply = 201;

    public static string GetName(byte type) => type switch
    {
        Init => "SSH_FXP_INIT",
        Version => "SSH_FXP_VERSION",
        Open => "SSH_FXP_OPEN",
        Close => "SSH_FXP_CLOSE",
        Read => "SSH_FXP_READ",
        Write => "SSH_FXP_WRITE",
        Lstat => "SSH_FXP_LSTAT",
        Fstat => "SSH_FXP_FSTAT",
        Setstat => "SSH_FXP_SETSTAT",
        Fsetstat => "SSH_FXP_FSETSTAT",
        Opendir => "SSH_FXP_OPENDIR",
        Readdir => "SSH_FXP_READDIR",
        Remove => "SSH_FXP_REMOVE",
        Mkdir => "SSH_FXP_MKDIR",
        Rmdir => "SSH_FXP_RMDIR",
        Realpath => "SSH_FXP_REALPATH",
        Stat => "SSH_FXP_STAT",
        Rename => "SSH_FXP_RENAME",
        Readlink => "SSH_FXP_READLINK",
        Symlink => "SSH_FXP_SYMLINK",
        Status => "SSH_FXP_STATUS",
        Handle => "SSH_FXP_HANDLE",
        Data => "SSH_FXP_DATA",
        Name => "SSH_FXP_NAME",
        Attrs => "SSH_FXP_ATTRS",
        Extended => "SSH_FXP_EXTENDED",
        ExtendedReply => "SSH_FXP_EXTENDED_REPLY",
        _ => $"UNKNOWN({type})"
    };
}

/// <summary>
/// SFTP status codes (SSH_FX_*)
/// </summary>
public static class SftpStatusCode
{
    public const uint Ok = 0;
    public const uint Eof = 1;
    public const uint NoSuchFile = 2;
    public const uint PermissionDenied = 3;
    public const uint Failure = 4;
    public const uint BadMessage = 5;
    public const uint NoConnection = 6;
    public const uint ConnectionLost = 7;
    public const uint OpUnsupported = 8;
}

/// <summary>
/// SFTP open flags (SSH_FXF_*)
/// </summary>
[Flags]
public enum SftpOpenFlags : uint
{
    Read = 0x00000001,
    Write = 0x00000002,
    Append = 0x00000004,
    Create = 0x00000008,
    Truncate = 0x00000010,
    Exclusive = 0x00000020
}

/// <summary>
/// SFTP attribute flags
/// </summary>
[Flags]
public enum SftpAttributeFlags : uint
{
    Size = 0x00000001,
    UidGid = 0x00000002,
    Permissions = 0x00000004,
    AccessTime = 0x00000008,
    Extended = 0x80000000
}
