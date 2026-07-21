using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Hashing.Hmac;

/// <summary>
/// Provides HMAC (keyed-hash message authentication code) operations.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete HMAC logic arrives with the hashing implementation feature.
/// </remarks>
public sealed class HmacService : IHmacService
{
    /// <inheritdoc />
    public byte[] ComputeHmac(byte[] data, byte[] key) => throw new NotImplementedException();

    /// <inheritdoc />
    public Task<byte[]> ComputeHmacAsync(
        Stream input,
        byte[] key,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default) => throw new NotImplementedException();
}
