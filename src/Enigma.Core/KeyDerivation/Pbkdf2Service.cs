using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.Core.KeyDerivation;

/// <summary>
/// Derives key material with PBKDF2 (PKCS #5 v2.0 / RFC 8018) by iterating an HMAC over the password
/// and salt. Uses BouncyCastle's <c>Pkcs5S2ParametersGenerator</c> internally; the backing digest is
/// selected by <see cref="Pbkdf2Prf"/> and never surfaces on the public API.
/// </summary>
/// <remarks>
/// The <c>password</c> array is caller-owned: it is fed straight into the derivation and is never
/// re-encoded, mutated, or cleared. The caller is responsible for clearing sensitive material when
/// done. A single instance holds no per-call state and is safe to reuse.
/// </remarks>
public sealed class Pbkdf2Service : IPbkdf2Service
{
    /// <inheritdoc />
    public byte[] DeriveKey(
        byte[] password,
        byte[] salt,
        int iterations,
        int keySizeBytes,
        Pbkdf2Prf prf = Pbkdf2Prf.HmacSha256)
    {
        if (password is null) throw new ArgumentNullException(nameof(password));
        if (salt is null) throw new ArgumentNullException(nameof(salt));
        if (iterations <= 0) throw new ArgumentException("Iterations must be greater than zero.", nameof(iterations));
        if (keySizeBytes <= 0) throw new ArgumentException("Key size must be greater than zero.", nameof(keySizeBytes));

        // Feed the caller's password bytes straight in — no UTF-8 re-encode (the caller owns encoding)
        // and no Array.Clear of the caller's array (the caller owns its lifetime).
        var generator = new Pkcs5S2ParametersGenerator(CreateDigest(prf));
        generator.Init(password, salt, iterations);

        var keyParameter = (KeyParameter)generator.GenerateDerivedParameters("AES", keySizeBytes * 8);
        return keyParameter.GetKey();
    }

    // Maps the BC-free PRF enum to the internal BouncyCastle digest that backs the HMAC. Keeping this
    // switch private is what lets the digest types stay off the public surface (principle 1).
    private static IDigest CreateDigest(Pbkdf2Prf prf) => prf switch
    {
        Pbkdf2Prf.HmacSha1 => new Sha1Digest(),
        Pbkdf2Prf.HmacSha256 => new Sha256Digest(),
        Pbkdf2Prf.HmacSha384 => new Sha384Digest(),
        Pbkdf2Prf.HmacSha512 => new Sha512Digest(),
        _ => throw new ArgumentOutOfRangeException(nameof(prf), prf, "Unsupported PBKDF2 PRF."),
    };
}
