using System.Text;

namespace FxSsh.Messages;

/// <summary>
/// SSH_MSG_EXT_INFO message (RFC 8308)
/// Sent by server after SSH_MSG_NEWKEYS to advertise extensions like server-sig-algs.
/// </summary>
[Message("SSH_MSG_EXT_INFO", MessageNumber)]
public class ExtInfoMessage : Message
{
    private const byte MessageNumber = 7;

    public override byte MessageType => MessageNumber;

    /// <summary>
    /// Extensions to include in the message.
    /// Key = extension name, Value = extension value (as string)
    /// </summary>
    public Dictionary<string, string> Extensions { get; set; } = new();

    protected override void OnLoad(SshDataReader reader)
    {
        var count = reader.ReadUInt32();
        Extensions = new Dictionary<string, string>();

        for (uint i = 0; i < count; i++)
        {
            var name = reader.ReadString(Encoding.ASCII);
            var value = reader.ReadString(Encoding.ASCII);
            Extensions[name] = value;
        }
    }

    protected override void OnGetPacket(SshDataWriter writer)
    {
        writer.Write((uint)Extensions.Count);

        foreach (var ext in Extensions)
        {
            writer.Write(ext.Key, Encoding.ASCII);
            writer.Write(ext.Value, Encoding.ASCII);
        }
    }

    /// <summary>
    /// Creates an ExtInfoMessage with server-sig-algs extension.
    /// </summary>
    /// <param name="algorithms">List of supported public key algorithms for user authentication</param>
    public static ExtInfoMessage CreateWithServerSigAlgs(IEnumerable<string> algorithms)
    {
        return new ExtInfoMessage
        {
            Extensions = new Dictionary<string, string>
            {
                ["server-sig-algs"] = string.Join(",", algorithms)
            }
        };
    }
}
