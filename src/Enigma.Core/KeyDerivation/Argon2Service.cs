using System;

namespace Enigma.Core.KeyDerivation;

/// <summary>
/// Provides Argon2 key-derivation operations.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete derivation logic arrives with the key-derivation implementation feature.
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
        Argon2Version version = Argon2Version.Version13) => throw new NotImplementedException();
}
