using System;

namespace Enigma.Core.Hashing.Hash;

/// <summary>
/// A factory for creating hash services, one per supported algorithm.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete factory logic arrives with the hashing implementation feature.
/// </remarks>
public sealed class HashServiceFactory : IHashServiceFactory
{
    /// <inheritdoc />
    public IHashService CreateMd5Service(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IHashService CreateSha1Service(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IHashService CreateSha256Service(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IHashService CreateSha512Service(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IHashService CreateSha3Service(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();
}
