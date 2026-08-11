using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Checksum;

/// <summary>
/// Computes a cyclic-redundancy-check (CRC) checksum over data, using the variant selected by the
/// factory. The same value is available as bytes (for framing) and as a <see cref="uint"/> (for
/// comparison), synchronously for in-memory buffers and asynchronously for streams.
/// </summary>
/// <remarks>
/// <b>Not a cryptographic primitive.</b> A CRC detects accidental corruption — transmission errors,
/// bit rot, truncated files — and nothing more. It is trivially forgeable: anyone who can alter the
/// data can recompute a matching checksum, and collisions can be constructed by hand. When integrity
/// must hold against an adversary, use <see cref="Enigma.Core.Hashing.Hmac.IHmacService"/> (or a
/// signature); never a checksum.
/// </remarks>
public interface IChecksumService
{
    /// <summary>
    /// Gets the length, in bytes, of the checksum this service produces: 2 for a CRC-16, 4 for a
    /// CRC-32.
    /// </summary>
    int ChecksumSize { get; }

    /// <summary>
    /// Computes the checksum of an in-memory buffer.
    /// </summary>
    /// <param name="data">The data to checksum. May be empty.</param>
    /// <returns>
    /// The checksum as <see cref="ChecksumSize"/> bytes in big-endian order (most-significant byte
    /// first) — network/frame order, and the order digests read in.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="data"/> is <see langword="null"/>.</exception>
    byte[] ComputeChecksum(byte[] data);

    /// <summary>
    /// Computes the checksum of an in-memory buffer as a numeric value.
    /// </summary>
    /// <param name="data">The data to checksum. May be empty.</param>
    /// <returns>
    /// The same value <see cref="ComputeChecksum"/> returns, as a <see cref="uint"/>. For a CRC-16 it
    /// occupies the low 16 bits and the high 16 bits are zero.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="data"/> is <see langword="null"/>.</exception>
    uint ComputeChecksumValue(byte[] data);

    /// <summary>
    /// Computes the checksum of the data read from a stream.
    /// </summary>
    /// <param name="input">The input stream to checksum. Read to its end.</param>
    /// <param name="progress">Optional progress reporting mechanism that reports bytes processed.</param>
    /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
    /// <returns>
    /// A task whose result is the checksum as <see cref="ChecksumSize"/> big-endian bytes — the same
    /// value <see cref="ComputeChecksum"/> returns for the same data.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="input"/> is <see langword="null"/>.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task<byte[]> ComputeChecksumAsync(
        Stream input,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Computes the checksum of the data read from a stream, as a numeric value.
    /// </summary>
    /// <param name="input">The input stream to checksum. Read to its end.</param>
    /// <param name="progress">Optional progress reporting mechanism that reports bytes processed.</param>
    /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
    /// <returns>
    /// A task whose result is the checksum as a <see cref="uint"/> — the same value
    /// <see cref="ComputeChecksumValue"/> returns for the same data.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="input"/> is <see langword="null"/>.</exception>
    /// <exception cref="OperationCanceledException">The operation was cancelled.</exception>
    Task<uint> ComputeChecksumValueAsync(
        Stream input,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);
}
