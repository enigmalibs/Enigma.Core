using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Enigma.Core.Asymmetric.PublicKey;

/// <summary>
/// Provides RSA public-key encryption (PKCS#1 v1.5, OAEP), signing (RSASSA-PKCS1-v1_5) and key-pair
/// generation. Keys cross the API as PEM strings and passphrases as <see cref="char"/> arrays.
/// </summary>
/// <remarks>
/// The correct BouncyCastle cipher/signer is wired internally per call, so no BouncyCastle type appears on
/// the public surface (principle 1). BouncyCastle decryption/authentication failures never escape: they
/// surface as <see cref="CryptographicException"/>.
/// </remarks>
public sealed class PublicKeyService : IPublicKeyService
{
    /// <inheritdoc />
    public (string publicKeyPem, string privateKeyPem) GenerateRsaKeyPair(int keySizeBits = 2048, char[]? password = null)
    {
        if (keySizeBits <= 0)
            throw new ArgumentException("Key size must be greater than zero.", nameof(keySizeBits));

        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), keySizeBits));
        var pair = generator.GenerateKeyPair();

        return (PemUtils.WritePublicKeyPem(pair.Public), PemUtils.WritePrivateKeyPem(pair.Private, password));
    }

    /// <inheritdoc />
    public byte[] EncryptPkcs1(byte[] data, string publicKeyPem)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        var key = PemUtils.ParsePublicKey(publicKeyPem);
        var cipher = new Pkcs1Encoding(new RsaEngine());
        cipher.Init(forEncryption: true, key);
        return Transform(cipher, data, "PKCS#1 encryption");
    }

    /// <inheritdoc />
    public byte[] DecryptPkcs1(byte[] ciphertext, string privateKeyPem, char[]? password = null)
    {
        if (ciphertext is null) throw new ArgumentNullException(nameof(ciphertext));

        var key = PemUtils.ParsePrivateKey(privateKeyPem, password);
        var cipher = new Pkcs1Encoding(new RsaEngine());
        cipher.Init(forEncryption: false, key);
        return Transform(cipher, ciphertext, "PKCS#1 decryption");
    }

    /// <inheritdoc />
    public byte[] EncryptOaep(byte[] data, string publicKeyPem, RsaOaepHash hash = RsaOaepHash.Sha256)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        var digest = CreateOaepDigest(hash);
        var key = PemUtils.ParsePublicKey(publicKeyPem);
        var cipher = new OaepEncoding(new RsaEngine(), digest);
        cipher.Init(forEncryption: true, key);
        return Transform(cipher, data, "OAEP encryption");
    }

    /// <inheritdoc />
    public byte[] DecryptOaep(byte[] ciphertext, string privateKeyPem, RsaOaepHash hash = RsaOaepHash.Sha256, char[]? password = null)
    {
        if (ciphertext is null) throw new ArgumentNullException(nameof(ciphertext));

        var digest = CreateOaepDigest(hash);
        var key = PemUtils.ParsePrivateKey(privateKeyPem, password);
        var cipher = new OaepEncoding(new RsaEngine(), digest);
        cipher.Init(forEncryption: false, key);
        return Transform(cipher, ciphertext, "OAEP decryption");
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] data, string privateKeyPem, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        var signer = SignerUtilities.GetSigner(SignatureAlgorithms.ToJcaName(algorithm));
        var key = PemUtils.ParsePrivateKey(privateKeyPem, password);
        signer.Init(forSigning: true, key);
        signer.BlockUpdate(data, 0, data.Length);
        try
        {
            return signer.GenerateSignature();
        }
        catch (CryptoException ex)
        {
            throw new CryptographicException("RSA signing failed.", ex);
        }
    }

    /// <inheritdoc />
    public bool Verify(byte[] data, byte[] signature, string publicKeyPem, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (signature is null) throw new ArgumentNullException(nameof(signature));

        var signer = SignerUtilities.GetSigner(SignatureAlgorithms.ToJcaName(algorithm));
        var key = PemUtils.ParsePublicKey(publicKeyPem);
        signer.Init(forSigning: false, key);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(signature);
    }

    // Runs the RSA block transform, translating any BouncyCastle failure (bad padding, oversized/short input,
    // corrupt or mismatched-hash ciphertext) into a CryptographicException so no BouncyCastle type escapes.
    private static byte[] Transform(IAsymmetricBlockCipher cipher, byte[] data, string operation)
    {
        try
        {
            return cipher.ProcessBlock(data, 0, data.Length);
        }
        catch (CryptoException ex)
        {
            throw new CryptographicException(
                $"RSA {operation} failed. The data may be too large for the key, corrupt, or encrypted with a " +
                "different key or padding.", ex);
        }
    }

    // Maps the public OAEP-hash enum to the internal BouncyCastle digest (used for both the OAEP hash and MGF1).
    private static IDigest CreateOaepDigest(RsaOaepHash hash) => hash switch
    {
        RsaOaepHash.Sha1 => new Sha1Digest(),
        RsaOaepHash.Sha256 => new Sha256Digest(),
        RsaOaepHash.Sha384 => new Sha384Digest(),
        RsaOaepHash.Sha512 => new Sha512Digest(),
        _ => throw new ArgumentOutOfRangeException(nameof(hash), hash, "Unsupported OAEP hash algorithm."),
    };
}
