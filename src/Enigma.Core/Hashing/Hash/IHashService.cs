using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Hashing.Hash;

/// <summary>
/// Provides cryptographic hashing services. Computes a fixed-size digest over stream data using the
/// algorithm selected by the factory, supporting asynchronous operation with progress reporting and
/// cancellation.
/// </summary>
public interface IHashService
{
    /// <summary>
    /// Computes the hash digest of the data read from the input stream.
    /// </summary>
    /// <param name="input">The input stream containing the data to hash. Read to its end.</param>
    /// <param name="progress">Optional progress reporting mechanism that reports bytes processed.</param>
    /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
    /// <returns>
    /// A task whose result is the computed digest. Its length is determined by the algorithm the
    /// service was created for.
    /// </returns>
    Task<byte[]> ComputeHashAsync(
        Stream input,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);
}
