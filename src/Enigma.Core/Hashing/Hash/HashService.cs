using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Hashing.Hash;

/// <summary>
/// Provides cryptographic hashing operations.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete hashing logic arrives with the hashing implementation feature.
/// </remarks>
public sealed class HashService : IHashService
{
    /// <inheritdoc />
    public Task<byte[]> ComputeHashAsync(
        Stream input,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default) => throw new NotImplementedException();
}
