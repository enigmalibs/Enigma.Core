using System;

namespace Enigma.Core.Symmetric.StreamCiphers;

/// <summary>
/// A factory for creating stream cipher services.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete factory logic arrives with the symmetric-cipher implementation feature.
/// </remarks>
public sealed class StreamCipherServiceFactory : IStreamCipherServiceFactory
{
    /// <inheritdoc />
    public IStreamCipherService CreateChaCha7539Service(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IStreamCipherService CreateChaCha20Service(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IStreamCipherService CreateSalsa20Service(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();
}
