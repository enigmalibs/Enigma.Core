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
/// Provides RSA public-key encryption (PKCS#1 v1.5, OAEP), signing (RSASSA-PKCS1-v1_5) and key generation.
/// Keys cross the API as <see cref="RsaKey"/> handles, so a PEM is parsed — and its passphrase supplied —
/// exactly once, no matter how many operations the key is used for.
/// </summary>
/// <remarks>
/// The correct BouncyCastle cipher/signer is wired internally per call, so no BouncyCastle type appears on the
/// public surface (principle 1). BouncyCastle decryption/authentication failures never escape: they surface as
/// <see cref="CryptographicException"/>.
/// </remarks>
public sealed class PublicKeyService : IPublicKeyService
{
    /// <inheritdoc />
    public RsaKey GenerateRsaKey(int keySizeBits = 2048)
    {
        if (keySizeBits <= 0)
            throw new ArgumentException("Key size must be greater than zero.", nameof(keySizeBits));

        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), keySizeBits));
        var pair = generator.GenerateKeyPair();

        // The private half alone is handed over: it is a CRT key, so the public half stays derivable from it and
        // one handle serves both directions.
        return RsaKey.FromBcKey((RsaKeyParameters)pair.Private);
    }

    /// <inheritdoc />
    public byte[] EncryptPkcs1(byte[] data, RsaKey key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));

        var cipher = new Pkcs1Encoding(new RsaEngine());
        cipher.Init(forEncryption: true, key.BcPublicKey);
        return Transform(cipher, data, "PKCS#1 encryption");
    }

    /// <inheritdoc />
    public byte[] DecryptPkcs1(byte[] ciphertext, RsaKey key)
    {
        if (ciphertext is null) throw new ArgumentNullException(nameof(ciphertext));
        if (key is null) throw new ArgumentNullException(nameof(key));

        var cipher = new Pkcs1Encoding(new RsaEngine());
        cipher.Init(forEncryption: false, RequirePrivate(key));
        return Transform(cipher, ciphertext, "PKCS#1 decryption");
    }

    /// <inheritdoc />
    public byte[] EncryptOaep(byte[] data, RsaKey key, RsaOaepHash hash = RsaOaepHash.Sha256)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));

        var digest = CreateOaepDigest(hash);
        var cipher = new OaepEncoding(new RsaEngine(), digest);
        cipher.Init(forEncryption: true, key.BcPublicKey);
        return Transform(cipher, data, "OAEP encryption");
    }

    /// <inheritdoc />
    public byte[] DecryptOaep(byte[] ciphertext, RsaKey key, RsaOaepHash hash = RsaOaepHash.Sha256)
    {
        if (ciphertext is null) throw new ArgumentNullException(nameof(ciphertext));
        if (key is null) throw new ArgumentNullException(nameof(key));

        var privateKey = RequirePrivate(key);
        var digest = CreateOaepDigest(hash);
        var cipher = new OaepEncoding(new RsaEngine(), digest);
        cipher.Init(forEncryption: false, privateKey);
        return Transform(cipher, ciphertext, "OAEP decryption");
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] data, RsaKey key, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));

        var privateKey = RequirePrivate(key);
        var signer = SignerUtilities.GetSigner(SignatureAlgorithms.ToJcaName(algorithm));
        signer.Init(forSigning: true, privateKey);
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
    public bool Verify(byte[] data, byte[] signature, RsaKey key, RsaSignatureAlgorithm algorithm = RsaSignatureAlgorithm.Sha256WithRsa)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (signature is null) throw new ArgumentNullException(nameof(signature));
        if (key is null) throw new ArgumentNullException(nameof(key));

        var signer = SignerUtilities.GetSigner(SignatureAlgorithms.ToJcaName(algorithm));
        signer.Init(forSigning: false, key.BcPublicKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.VerifySignature(signature);
    }

    // The key a private-key operation runs on. A public-only handle is a bad argument to the method rather than a
    // broken handle, so it is reported as ArgumentException naming the parameter the caller passed. (The public
    // operations take RsaKey.BcPublicKey directly: they accept either kind of handle, and BouncyCastle's RSA core
    // picks the private exponentiation from the key type alone, so a private key must never reach one of them.)
    private static RsaKeyParameters RequirePrivate(RsaKey key)
    {
        if (!key.HasPrivateKey)
            throw new ArgumentException(
                "The key holds only a public key; this operation requires a private key.", nameof(key));

        return key.BcKey;
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
