using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace FxSsh.Algorithms;

/// <summary>
/// Ed25519 public key algorithm implementation using Bouncy Castle.
/// Supports SSH wire format for ssh-ed25519 keys.
/// </summary>
public class Ed25519Key : PublicKeyAlgorithm
{
    private const string AlgorithmName = "ssh-ed25519";
    private const int PublicKeySize = 32;
    private const int PrivateKeySize = 32;
    private const int SignatureSize = 64;

    private Ed25519PrivateKeyParameters? _privateKey;
    private Ed25519PublicKeyParameters? _publicKey;

    public Ed25519Key(string? key) : base(key ?? string.Empty)
    {
        // If no key provided, generate a new keypair
        if (string.IsNullOrEmpty(key))
        {
            GenerateKeyPair();
        }
    }

    public override string Name => AlgorithmName;

    private void GenerateKeyPair()
    {
        var generator = new Ed25519KeyPairGenerator();
        generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var keyPair = generator.GenerateKeyPair();
        _privateKey = (Ed25519PrivateKeyParameters)keyPair.Private;
        _publicKey = (Ed25519PublicKeyParameters)keyPair.Public;
    }

    public override void ImportKey(string key)
    {
        using var reader = new StringReader(key);
        var pemReader = new PemReader(reader);
        var keyObject = pemReader.ReadObject();

        switch (keyObject)
        {
            case AsymmetricCipherKeyPair keyPair:
                _privateKey = (Ed25519PrivateKeyParameters)keyPair.Private;
                _publicKey = (Ed25519PublicKeyParameters)keyPair.Public;
                break;
            case Ed25519PrivateKeyParameters privateKey:
                _privateKey = privateKey;
                _publicKey = privateKey.GeneratePublicKey();
                break;
            case Ed25519PublicKeyParameters publicKey:
                _publicKey = publicKey;
                _privateKey = null;
                break;
            default:
                throw new CryptographicException($"Unsupported key type: {keyObject?.GetType().Name ?? "null"}");
        }
    }

    public override string ExportKey()
    {
        if (_privateKey == null)
            throw new CryptographicException("No private key available to export.");

        using var writer = new StringWriter();
        var pemWriter = new PemWriter(writer);
        pemWriter.WriteObject(_privateKey);
        return writer.ToString();
    }

    public override void LoadKeyAndCertificatesData(byte[] data)
    {
        var reader = new SshDataReader(data);
        var algorithmName = reader.ReadString(Encoding.ASCII);

        if (algorithmName != AlgorithmName)
            throw new CryptographicException($"Key algorithm mismatch. Expected {AlgorithmName}, got {algorithmName}");

        var publicKeyBytes = reader.ReadBinary();

        if (publicKeyBytes.Length != PublicKeySize)
            throw new CryptographicException($"Invalid Ed25519 public key size. Expected {PublicKeySize}, got {publicKeyBytes.Length}");

        _publicKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);
    }

    public override byte[] CreateKeyAndCertificatesData()
    {
        if (_publicKey == null)
            throw new CryptographicException("No public key available.");

        var publicKeyBytes = _publicKey.GetEncoded();

        return new SshDataWriter(4 + AlgorithmName.Length + 4 + publicKeyBytes.Length)
            .Write(AlgorithmName, Encoding.ASCII)
            .WriteBinary(publicKeyBytes)
            .ToByteArray();
    }

    public override byte[] SignData(byte[] data)
    {
        if (_privateKey == null)
            throw new CryptographicException("No private key available for signing.");

        var signer = new Ed25519Signer();
        signer.Init(true, _privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    public override byte[] SignHash(byte[] hash)
    {
        // Ed25519 doesn't support signing pre-computed hashes
        // The algorithm internally uses SHA-512
        throw new NotSupportedException("Ed25519 does not support signing pre-computed hashes. Use SignData instead.");
    }

    public override bool VerifyData(byte[] data, byte[] signature)
    {
        if (_publicKey == null)
            throw new CryptographicException("No public key available for verification.");

        if (signature.Length != SignatureSize)
            return false;

        var verifier = new Ed25519Signer();
        verifier.Init(false, _publicKey);
        verifier.BlockUpdate(data, 0, data.Length);
        return verifier.VerifySignature(signature);
    }

    public override bool VerifyHash(byte[] hash, byte[] signature)
    {
        // Ed25519 doesn't support verifying against pre-computed hashes
        throw new NotSupportedException("Ed25519 does not support verifying pre-computed hashes. Use VerifyData instead.");
    }
}
