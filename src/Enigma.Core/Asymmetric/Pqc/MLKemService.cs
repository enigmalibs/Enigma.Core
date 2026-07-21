using System;

namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Establishes shared secrets with ML-KEM (FIPS 203) key encapsulation.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete ML-KEM logic arrives with the post-quantum implementation feature.
/// </remarks>
public sealed class MLKemService : IMLKemService
{
    /// <inheritdoc />
    public (byte[] publicKey, byte[] privateKey) GenerateKeyPair() => throw new NotImplementedException();

    /// <inheritdoc />
    public (byte[] ciphertext, byte[] sharedSecret) Encapsulate(byte[] publicKey) => throw new NotImplementedException();

    /// <inheritdoc />
    public byte[] Decapsulate(byte[] ciphertext, byte[] privateKey) => throw new NotImplementedException();
}
