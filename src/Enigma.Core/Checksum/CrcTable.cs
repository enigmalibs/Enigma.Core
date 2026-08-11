using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Checksum;

/// <summary>
/// The table-driven CRC engine: a 256-entry lookup table for one parameter set, plus the byte-fold
/// and stream-read loops that run over it. Internal — the public surface is
/// <see cref="IChecksumService"/>.
/// </summary>
/// <remarks>
/// Instances are immutable and cached per distinct (polynomial, reflection, width) key, so the two
/// variants that differ only in <see cref="CrcParameters.Init"/> (ARC and MODBUS) share one table;
/// a differing initial register value does not change the table. Sharing is an optimisation — each
/// parameter set would be correct with its own table.
/// </remarks>
internal sealed class CrcTable
{
    // Keyed on what actually determines the table's contents. GetOrAdd may run the build factory more
    // than once under a race, but the table is a pure function of the key, so every candidate is
    // identical and exactly one is published.
    private static readonly ConcurrentDictionary<(uint Polynomial, bool Reflected, int Width), uint[]> Tables = new();

    private readonly CrcParameters _parameters;
    private readonly uint[] _table;
    private readonly uint _mask;
    private readonly int _topByteShift;

    private CrcTable(CrcParameters parameters)
    {
        _parameters = parameters;
        _mask = MaskFor(parameters.Width);
        _topByteShift = parameters.Width - 8;
        _table = Tables.GetOrAdd(
            (parameters.Polynomial, parameters.Reflected, parameters.Width),
            key => key.Reflected
                ? BuildReflected(key.Polynomial, key.Width)
                : BuildNormal(key.Polynomial, key.Width));
    }

    /// <summary>Gets the engine for the given parameter set.</summary>
    internal static CrcTable For(CrcParameters parameters) => new(parameters);

    /// <summary>
    /// Computes the checksum of an entire in-memory buffer, seeding and finalising the register.
    /// </summary>
    internal uint Compute(byte[] data) => Complete(Append(Seed(), data, 0, data.Length));

    /// <summary>
    /// Computes the checksum of a stream read to its end, seeding and finalising the register.
    /// Mirrors the streaming contract of the hashing services: progress reports the bytes consumed by
    /// each read, and cancellation is checked before the first read and on every iteration.
    /// </summary>
    internal async Task<uint> ComputeAsync(
        Stream input,
        int bufferSize,
        IProgress<int>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var crc = Seed();
        var buffer = ArrayPool<byte>.Shared.Rent(bufferSize);

        try
        {
            int bytesRead;
            while ((bytesRead = await input.ReadAsync(buffer, 0, bufferSize, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                crc = Append(crc, buffer, 0, bytesRead);
                progress?.Report(bytesRead);
            }

            return Complete(crc);
        }
        finally
        {
            // Clear on return: input data may be sensitive and must not linger in a pooled buffer.
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
        }
    }

    /// <summary>Gets the initial register value.</summary>
    /// <remarks>
    /// The register is seeded with <see cref="CrcParameters.Init"/> <b>directly</b>. That is correct
    /// only because every variant shipped here has a reflection-symmetric initial value (0x0000,
    /// 0xFFFF, 0xFFFFFFFF). A future reflected variant whose <c>Init</c> is <i>not</i> symmetric must
    /// have that value bit-reflected before seeding — skipping that step produces a plausible-looking
    /// but wrong checksum with no other symptom, and is the classic trap in table-driven CRC code.
    /// </remarks>
    private uint Seed() => _parameters.Init & _mask;

    /// <summary>Folds a run of bytes into the running register.</summary>
    private uint Append(uint crc, byte[] buffer, int offset, int count)
    {
        var table = _table;

        if (_parameters.Reflected)
        {
            for (var i = 0; i < count; i++)
                crc = (crc >> 8) ^ table[(crc ^ buffer[offset + i]) & 0xFF];
        }
        else
        {
            for (var i = 0; i < count; i++)
                crc = ((crc << 8) & _mask) ^ table[((crc >> _topByteShift) ^ buffer[offset + i]) & 0xFF];
        }

        return crc;
    }

    /// <summary>Applies the final XOR and masks the register to the variant's width.</summary>
    private uint Complete(uint crc) => (crc ^ _parameters.XorOut) & _mask;

    /// <summary>Builds the LSB-first table for a reflected variant, from the reflected polynomial.</summary>
    private static uint[] BuildReflected(uint reflectedPolynomial, int width)
    {
        var mask = MaskFor(width);
        var table = new uint[256];

        for (var i = 0; i < table.Length; i++)
        {
            var crc = (uint)i;
            for (var bit = 0; bit < 8; bit++)
                crc = (crc & 1u) != 0u ? ((crc >> 1) ^ reflectedPolynomial) & mask : (crc >> 1) & mask;
            table[i] = crc;
        }

        return table;
    }

    /// <summary>Builds the MSB-first table for a non-reflected variant, from the normal polynomial.</summary>
    private static uint[] BuildNormal(uint polynomial, int width)
    {
        var mask = MaskFor(width);
        var topBit = 1u << (width - 1);
        var table = new uint[256];

        for (var i = 0; i < table.Length; i++)
        {
            var crc = ((uint)i << (width - 8)) & mask;
            for (var bit = 0; bit < 8; bit++)
                crc = (crc & topBit) != 0u ? ((crc << 1) ^ polynomial) & mask : (crc << 1) & mask;
            table[i] = crc;
        }

        return table;
    }

    // uint.MaxValue is spelled out for width 32: `(1u << 32) - 1` would shift by 32, which C# masks
    // to a shift of 0 and would silently yield a mask of 0.
    private static uint MaskFor(int width) => width == 32 ? uint.MaxValue : (1u << width) - 1u;
}
