using System;

namespace Enigma.Core.Asymmetric.Pqc;

/// <summary>
/// Generates and verifies ML-DSA (FIPS 204) digital signatures.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete ML-DSA logic arrives with the post-quantum implementation feature.
/// </remarks>
public sealed class MLDsaService : IMLDsaService
{
    /// <inheritdoc />
    public (byte[] publicKey, byte[] privateKey) GenerateKeyPair() => throw new NotImplementedException();

    /// <inheritdoc />
    public byte[] Sign(byte[] message, byte[] privateKey) => throw new NotImplementedException();

    /// <inheritdoc />
    public bool Verify(byte[] message, byte[] signature, byte[] publicKey) => throw new NotImplementedException();
}
