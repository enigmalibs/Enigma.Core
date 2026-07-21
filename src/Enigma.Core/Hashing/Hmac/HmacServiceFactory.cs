using System;

namespace Enigma.Core.Hashing.Hmac;

/// <summary>
/// A factory for creating HMAC services, one per supported algorithm.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete factory logic arrives with the hashing implementation feature.
/// </remarks>
public sealed class HmacServiceFactory : IHmacServiceFactory
{
    /// <inheritdoc />
    public IHmacService CreateHmacSha1Service(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IHmacService CreateHmacSha256Service(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public IHmacService CreateHmacSha512Service(int bufferSize = CryptoDefaults.StreamBufferSize) => throw new NotImplementedException();
}
