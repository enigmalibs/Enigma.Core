using System;

namespace Enigma.Core.KeyDerivation;

/// <summary>
/// Provides PBKDF2 key-derivation operations.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete derivation logic arrives with the key-derivation implementation feature.
/// </remarks>
public sealed class Pbkdf2Service : IPbkdf2Service
{
    /// <inheritdoc />
    public byte[] DeriveKey(
        byte[] password,
        byte[] salt,
        int iterations,
        int keySizeBytes,
        Pbkdf2Prf prf = Pbkdf2Prf.HmacSha256) => throw new NotImplementedException();
}
