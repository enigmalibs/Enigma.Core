using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Hashing.Hmac;

/// <summary>
/// Provides keyed-hash message authentication code (HMAC) services. Computes an authentication tag over
/// data with a caller-supplied secret key, using the hash algorithm selected by the factory. Offers a
/// synchronous <c>byte[]</c> variant for in-memory data and an asynchronous streaming variant with
/// progress reporting and cancellation.
/// </summary>
public interface IHmacService
{
    /// <summary>
    /// Computes the HMAC of the specified in-memory data.
    /// </summary>
    /// <param name="data">The data to authenticate.</param>
    /// <param name="key">The secret key.</param>
    /// <returns>
    /// The computed authentication tag. Its length is determined by the algorithm the service was
    /// created for.
    /// </returns>
    byte[] ComputeHmac(byte[] data, byte[] key);

    /// <summary>
    /// Computes the HMAC of the data read from the input stream.
    /// </summary>
    /// <param name="input">The input stream containing the data to authenticate. Read to its end.</param>
    /// <param name="key">The secret key.</param>
    /// <param name="progress">Optional progress reporting mechanism that reports bytes processed.</param>
    /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
    /// <returns>
    /// A task whose result is the computed authentication tag. Its length is determined by the algorithm
    /// the service was created for.
    /// </returns>
    Task<byte[]> ComputeHmacAsync(
        Stream input,
        byte[] key,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);
}
