using System;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Generates and verifies ML-DSA (FIPS 204) digital signatures for a single parameter set fixed by the factory.
/// </summary>
/// <remarks>
/// Keys and signatures cross the API as raw <see cref="byte"/> arrays in their FIPS 204 encoding: the public key
/// is the standard encoded verification key; the private key is the <b>expanded</b> secret-key encoding (not the
/// 32-byte seed), so the array returned by <see cref="GenerateKeyPair"/> is directly usable by <see cref="Sign"/>
/// with no seed re-derivation. BouncyCastle backs every operation internally and never appears on the public
/// surface (principle 1). A malformed key surfaces as <see cref="CryptographicException"/>; no BouncyCastle
/// exception escapes.
/// </remarks>
public sealed class MLDsaService : IMLDsaService
{
    private readonly MLDsaParameters _parameters;
    private readonly bool _deterministic;

    // Constructed by MLDsaServiceFactory, which maps the public MLDsaParameterSet to the BouncyCastle parameter
    // object. Internal so the BouncyCastle parameter type never reaches the public surface.
    internal MLDsaService(MLDsaParameters parameters, bool deterministic)
    {
        _parameters = parameters;
        _deterministic = deterministic;
    }

    /// <inheritdoc />
    public (byte[] publicKey, byte[] privateKey) GenerateKeyPair()
    {
        var generator = new MLDsaKeyPairGenerator();
        generator.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), _parameters));
        var pair = generator.GenerateKeyPair();

        var publicKey = ((MLDsaPublicKeyParameters)pair.Public).GetEncoded();
        var privateKey = ((MLDsaPrivateKeyParameters)pair.Private).GetEncoded();
        return (publicKey, privateKey);
    }

    /// <inheritdoc />
    public byte[] Sign(byte[] message, byte[] privateKey)
    {
        if (message is null) throw new ArgumentNullException(nameof(message));
        if (privateKey is null) throw new ArgumentNullException(nameof(privateKey));

        try
        {
            var key = MLDsaPrivateKeyParameters.FromEncoding(_parameters, privateKey);
            var signer = new MLDsaSigner(_parameters, _deterministic);
            signer.Init(forSigning: true, key);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.GenerateSignature();
        }
        catch (Exception ex) when (IsCryptoInputFailure(ex))
        {
            throw new CryptographicException(
                "ML-DSA signing failed. The private key may be malformed or for a different parameter set.", ex);
        }
    }

    /// <inheritdoc />
    public bool Verify(byte[] message, byte[] signature, byte[] publicKey)
    {
        if (message is null) throw new ArgumentNullException(nameof(message));
        if (signature is null) throw new ArgumentNullException(nameof(signature));
        if (publicKey is null) throw new ArgumentNullException(nameof(publicKey));

        try
        {
            var key = MLDsaPublicKeyParameters.FromEncoding(_parameters, publicKey);
            var signer = new MLDsaSigner(_parameters, _deterministic);
            signer.Init(forSigning: false, key);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(signature);
        }
        catch (Exception ex) when (IsCryptoInputFailure(ex))
        {
            throw new CryptographicException(
                "ML-DSA verification failed. The public key may be malformed or for a different parameter set.", ex);
        }
    }

    // A malformed key (wrong length / bad encoding) surfaces from BouncyCastle as an ArgumentException, and any
    // internal BouncyCastle CryptoException is caught here too, so callers only ever see CryptographicException.
    // Null-argument guards run before the try block, so they are never routed through here.
    private static bool IsCryptoInputFailure(Exception ex) => ex is ArgumentException or CryptoException;
}
