using System;
using Enigma.Core.Internal;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Default <see cref="IMLDsaPemService"/> implementation, backed by BouncyCastle's PKCS#8 / SubjectPublicKeyInfo
/// encoders and the library's shared PEM envelope.
/// </summary>
/// <remarks>
/// Construct directly with <c>new</c> or through <see cref="MLDsaPemServiceFactory"/>; the service is stateless, so
/// an instance is reusable and the parameter set is passed per call. No BouncyCastle type appears on the public
/// surface (principle 1) and no BouncyCastle exception escapes: a structurally invalid PEM or key surfaces as
/// <see cref="ArgumentException"/>, a wrong or missing passphrase as
/// <see cref="System.Security.Cryptography.CryptographicException"/>.
/// </remarks>
public sealed class MLDsaPemService : IMLDsaPemService
{
    /// <inheritdoc />
    public (string publicKeyPem, string privateKeyPem) GenerateKeyPairPem(
        MLDsaParameterSet parameterSet,
        char[]? password = null,
        MLPrivateKeyPemFormat format = MLPrivateKeyPemFormat.Seed)
    {
        var parameters = MLParameterSets.ToBcParameters(parameterSet);
        var preferredFormat = ToBcFormat(format);

        var generator = new MLDsaKeyPairGenerator();
        generator.Init(new MLDsaKeyGenerationParameters(new SecureRandom(), parameters));
        var pair = generator.GenerateKeyPair();

        // The format has to be pinned on the freshly generated key, while its seed is still available: an
        // expanded key rebuilt from an encoding has no seed and rejects the two seed-bearing formats.
        var privateKey = ((MLDsaPrivateKeyParameters)pair.Private).WithPreferredFormat(preferredFormat);
        var keyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);

        return (PemEnvelope.WritePublicKeyPem(pair.Public), PemEnvelope.WritePrivateKeyPem(keyInfo, password));
    }

    /// <inheritdoc />
    public string ToPublicKeyPem(byte[] publicKey, MLDsaParameterSet parameterSet)
    {
        if (publicKey is null) throw new ArgumentNullException(nameof(publicKey));

        // Mapped before the try: an undefined enum value must stay an ArgumentOutOfRangeException rather than be
        // re-wrapped as a malformed-key ArgumentException (it derives from ArgumentException).
        var parameters = MLParameterSets.ToBcParameters(parameterSet);

        MLDsaPublicKeyParameters key;
        try
        {
            key = MLDsaPublicKeyParameters.FromEncoding(parameters, publicKey);
        }
        catch (Exception ex) when (IsKeyInputFailure(ex))
        {
            throw new ArgumentException(
                $"The bytes are not a valid ML-DSA public key for {parameterSet}.", nameof(publicKey), ex);
        }

        return PemEnvelope.WritePublicKeyPem(key);
    }

    /// <inheritdoc />
    public string ToPrivateKeyPem(byte[] privateKey, MLDsaParameterSet parameterSet, char[]? password = null)
    {
        if (privateKey is null) throw new ArgumentNullException(nameof(privateKey));

        var parameters = MLParameterSets.ToBcParameters(parameterSet);

        MLDsaPrivateKeyParameters key;
        try
        {
            // EncodingOnly is pinned explicitly. A key rebuilt from an encoding already defaults to it, but saying
            // so keeps the intent visible and immune to an upstream default change — and it is the only format a
            // seedless key can produce.
            key = MLDsaPrivateKeyParameters.FromEncoding(parameters, privateKey)
                .WithPreferredFormat(MLDsaPrivateKeyParameters.Format.EncodingOnly);
        }
        catch (Exception ex) when (IsKeyInputFailure(ex))
        {
            throw new ArgumentException(
                $"The bytes are not a valid ML-DSA private key for {parameterSet}.", nameof(privateKey), ex);
        }

        return PemEnvelope.WritePrivateKeyPem(PrivateKeyInfoFactory.CreatePrivateKeyInfo(key), password);
    }

    /// <inheritdoc />
    public (byte[] publicKey, MLDsaParameterSet parameterSet) FromPublicKeyPem(string pem)
    {
        if (pem is null) throw new ArgumentNullException(nameof(pem));

        if (PemEnvelope.ReadPublicKey(pem, nameof(pem)) is not MLDsaPublicKeyParameters key)
            throw new ArgumentException("The PEM does not contain an ML-DSA public key.", nameof(pem));

        return (key.GetEncoded(), MLParameterSets.FromBcParameters(key.Parameters, nameof(pem)));
    }

    /// <inheritdoc />
    public (byte[] privateKey, MLDsaParameterSet parameterSet) FromPrivateKeyPem(string pem, char[]? password = null)
    {
        if (pem is null) throw new ArgumentNullException(nameof(pem));

        if (PemEnvelope.ReadPrivateKey(pem, password, nameof(pem)) is not MLDsaPrivateKeyParameters key)
            throw new ArgumentException("The PEM does not contain an ML-DSA private key.", nameof(pem));

        // GetEncoded returns the expanded FIPS 204 key whatever format the PEM stored: a seed-only key is expanded
        // here, so the caller always receives bytes that IMLDsaService.Sign accepts.
        return (key.GetEncoded(), MLParameterSets.FromBcParameters(key.Parameters, nameof(pem)));
    }

    // Maps the library's PEM format enum onto BouncyCastle's encoding preference.
    private static MLDsaPrivateKeyParameters.Format ToBcFormat(MLPrivateKeyPemFormat format) => format switch
    {
        MLPrivateKeyPemFormat.Seed => MLDsaPrivateKeyParameters.Format.SeedOnly,
        MLPrivateKeyPemFormat.ExpandedKey => MLDsaPrivateKeyParameters.Format.EncodingOnly,
        MLPrivateKeyPemFormat.SeedAndExpandedKey => MLDsaPrivateKeyParameters.Format.SeedAndEncoding,
        _ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported private-key PEM format."),
    };

    // A key of the wrong length or a bad encoding surfaces from BouncyCastle as an ArgumentException, and any
    // internal CryptoException is caught alongside it, so callers only ever see the library's own exceptions.
    // Null guards and enum mapping both run before the try, so they are never routed through here.
    private static bool IsKeyInputFailure(Exception ex) => ex is ArgumentException or CryptoException;
}
