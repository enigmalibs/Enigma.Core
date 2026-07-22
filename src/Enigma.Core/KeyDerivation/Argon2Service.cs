using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.Core.KeyDerivation;

/// <summary>
/// Derives key material with Argon2 (RFC 9106), a memory-hard function whose time, memory and
/// parallelism cost parameters make brute-force attacks expensive on CPUs and GPUs alike. Uses
/// BouncyCastle's <c>Argon2BytesGenerator</c> internally; no BouncyCastle type appears on the public
/// API.
/// </summary>
/// <remarks>
/// The <c>password</c> array is caller-owned: it is passed straight into the generator and is never
/// mutated or cleared. The caller is responsible for clearing sensitive material when done. A single
/// instance holds no per-call state and is safe to reuse.
/// </remarks>
public sealed class Argon2Service : IArgon2Service
{
    /// <inheritdoc />
    public byte[] DeriveKey(
        byte[] password,
        byte[] salt,
        int iterations,
        int memorySizeKb,
        int degreeOfParallelism,
        int keySizeBytes,
        Argon2Variant variant = Argon2Variant.Argon2id,
        Argon2Version version = Argon2Version.Version13)
    {
        if (password is null) throw new ArgumentNullException(nameof(password));
        if (salt is null) throw new ArgumentNullException(nameof(salt));
        if (iterations <= 0) throw new ArgumentException("Iterations must be greater than zero.", nameof(iterations));
        if (memorySizeKb <= 0) throw new ArgumentException("Memory size must be greater than zero.", nameof(memorySizeKb));
        if (degreeOfParallelism <= 0) throw new ArgumentException("Degree of parallelism must be greater than zero.", nameof(degreeOfParallelism));
        if (keySizeBytes <= 0) throw new ArgumentException("Key size must be greater than zero.", nameof(keySizeBytes));

        var parameters = new Argon2Parameters.Builder(MapVariant(variant))
            .WithVersion(MapVersion(version))
            .WithIterations(iterations)
            // Absolute kibibytes — NOT WithMemoryPowOfTwo. The public contract takes memory as an
            // absolute KiB count, so it maps directly onto WithMemoryAsKB.
            .WithMemoryAsKB(memorySizeKb)
            .WithParallelism(degreeOfParallelism)
            .WithSalt(salt)
            .Build();

        var generator = new Argon2BytesGenerator();
        generator.Init(parameters);

        var derivedKey = new byte[keySizeBytes];
        generator.GenerateBytes(password, derivedKey, 0, derivedKey.Length);
        return derivedKey;
    }

    // Explicit enum -> BouncyCastle constant map. The variant ordinals happen to coincide with BC's
    // today, but we map explicitly rather than cast so the two enums can never drift apart silently.
    private static int MapVariant(Argon2Variant variant) => variant switch
    {
        Argon2Variant.Argon2d => Argon2Parameters.Argon2d,
        Argon2Variant.Argon2i => Argon2Parameters.Argon2i,
        Argon2Variant.Argon2id => Argon2Parameters.Argon2id,
        _ => throw new ArgumentOutOfRangeException(nameof(variant), variant, "Unsupported Argon2 variant."),
    };

    // Explicit enum -> BouncyCastle constant map. This one is load-bearing: the enum ordinals (0, 1)
    // do NOT match BC's version constants (0x10, 0x13), so a raw (int) cast would derive under the
    // wrong version and silently produce non-conforming output.
    private static int MapVersion(Argon2Version version) => version switch
    {
        Argon2Version.Version10 => Argon2Parameters.Version10,
        Argon2Version.Version13 => Argon2Parameters.Version13,
        _ => throw new ArgumentOutOfRangeException(nameof(version), version, "Unsupported Argon2 version."),
    };
}
