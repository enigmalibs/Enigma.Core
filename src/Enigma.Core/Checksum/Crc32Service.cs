using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Checksum;

/// <summary>
/// Computes a 32-bit CRC using the variant selected by the factory.
/// </summary>
/// <remarks>
/// <para>
/// Instances are created by <see cref="ChecksumServiceFactory"/> only; the variant is chosen there.
/// The lookup table is immutable and no per-call state is kept on the instance, so a single service
/// may be shared freely across threads.
/// </para>
/// <para>
/// See <see cref="IChecksumService"/>: a CRC detects accidental corruption only and must never be
/// used where integrity has to hold against an adversary.
/// </para>
/// </remarks>
public sealed class Crc32Service : IChecksumService
{
    private readonly CrcTable _table;
    private readonly int _bufferSize;

    // Internal so only the factory (same assembly) can construct a service; the CRC parameter set
    // never becomes part of the public API surface.
    internal Crc32Service(CrcParameters parameters, int bufferSize = CryptoDefaults.StreamBufferSize)
    {
        // A non-positive buffer would make the read loop terminate before consuming the stream, so
        // the service would silently return the checksum of the empty message. Reject it at creation.
        if (bufferSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(bufferSize), bufferSize, "Buffer size must be positive.");

        _table = CrcTable.For(parameters);
        _bufferSize = bufferSize;
    }

    /// <inheritdoc />
    public int ChecksumSize => 4;

    /// <inheritdoc />
    public byte[] ComputeChecksum(byte[] data) => ToBigEndian(ComputeChecksumValue(data));

    /// <inheritdoc />
    public uint ComputeChecksumValue(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));

        return _table.Compute(data);
    }

    /// <inheritdoc />
    public async Task<byte[]> ComputeChecksumAsync(
        Stream input,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
        => ToBigEndian(await ComputeChecksumValueAsync(input, progress, cancellationToken).ConfigureAwait(false));

    /// <inheritdoc />
    public Task<uint> ComputeChecksumValueAsync(
        Stream input,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));

        return _table.ComputeAsync(input, _bufferSize, progress, cancellationToken);
    }

    private static byte[] ToBigEndian(uint value) =>
        [(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value];
}
