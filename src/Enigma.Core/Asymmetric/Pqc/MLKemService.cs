using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Establishes shared secrets with ML-KEM (FIPS 203) key encapsulation for a single parameter set fixed by the
/// factory.
/// </summary>
/// <remarks>
/// Keys and ciphertexts cross the API as raw <see cref="byte"/> arrays in their FIPS 203 encoding: the public
/// key is the standard encapsulation key; the private key is the <b>expanded</b> decapsulation-key encoding (not
/// the 64-byte seed), so the array returned by <see cref="GenerateKeyPair"/> is directly usable by
/// <see cref="Decapsulate"/>. BouncyCastle backs every operation internally and never appears on the public
/// surface (principle 1). A malformed ciphertext or key surfaces as <see cref="CryptographicException"/>; no
/// BouncyCastle exception escapes. Decapsulating with the wrong (but well-formed) key does not throw — per FIPS
/// 203 implicit rejection it simply yields a different shared secret.
/// </remarks>
public sealed class MLKemService : IMLKemService
{
    private readonly MLKemParameters _parameters;

    // Constructed by MLKemServiceFactory, which maps the public MLKemParameterSet to the BouncyCastle parameter
    // object. Internal so the BouncyCastle parameter type never reaches the public surface.
    internal MLKemService(MLKemParameters parameters) => _parameters = parameters;

    /// <inheritdoc />
    public (byte[] publicKey, byte[] privateKey) GenerateKeyPair()
    {
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(new SecureRandom(), _parameters));
        var pair = generator.GenerateKeyPair();

        var publicKey = ((MLKemPublicKeyParameters)pair.Public).GetEncoded();
        var privateKey = ((MLKemPrivateKeyParameters)pair.Private).GetEncoded();
        return (publicKey, privateKey);
    }

    /// <inheritdoc />
    public (byte[] ciphertext, byte[] sharedSecret) Encapsulate(byte[] publicKey)
    {
        if (publicKey is null) throw new ArgumentNullException(nameof(publicKey));

        try
        {
            var key = MLKemPublicKeyParameters.FromEncoding(_parameters, publicKey);
            var encapsulator = new MLKemEncapsulator(_parameters);
            encapsulator.Init(key);

            var ciphertext = new byte[encapsulator.EncapsulationLength];
            var sharedSecret = new byte[encapsulator.SecretLength];
            encapsulator.Encapsulate(ciphertext, 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);
            return (ciphertext, sharedSecret);
        }
        catch (Exception ex) when (IsCryptoInputFailure(ex))
        {
            throw new CryptographicException(
                "ML-KEM encapsulation failed. The public key may be malformed or for a different parameter set.", ex);
        }
    }

    /// <inheritdoc />
    public byte[] Decapsulate(byte[] ciphertext, byte[] privateKey)
    {
        if (ciphertext is null) throw new ArgumentNullException(nameof(ciphertext));
        if (privateKey is null) throw new ArgumentNullException(nameof(privateKey));

        try
        {
            var key = MLKemPrivateKeyParameters.FromEncoding(_parameters, privateKey);
            var decapsulator = new MLKemDecapsulator(_parameters);
            decapsulator.Init(key);

            var sharedSecret = new byte[decapsulator.SecretLength];
            decapsulator.Decapsulate(ciphertext, 0, ciphertext.Length, sharedSecret, 0, sharedSecret.Length);
            return sharedSecret;
        }
        catch (Exception ex) when (IsCryptoInputFailure(ex))
        {
            throw new CryptographicException(
                "ML-KEM decapsulation failed. The ciphertext or private key may be malformed or for a different " +
                "parameter set.", ex);
        }
    }

    // A malformed key or ciphertext (wrong length / bad encoding) surfaces from BouncyCastle as an
    // ArgumentException, and any internal BouncyCastle CryptoException is caught here too, so callers only ever
    // see CryptographicException. Null-argument guards run before the try block, so they never route through here.
    private static bool IsCryptoInputFailure(Exception ex) => ex is ArgumentException or CryptoException;
}
