using System;

namespace Enigma.Core.Padding;

/// <summary>
/// A padding service that performs no padding — the data is returned unchanged. Corresponds to
/// <see cref="PaddingScheme.None"/>.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete (pass-through) logic arrives with the symmetric-cipher implementation feature.
/// </remarks>
public sealed class NoPaddingService : IPaddingService
{
    /// <inheritdoc />
    public byte[] Pad(byte[] data, int blockSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public byte[] Unpad(byte[] data, int blockSize) => throw new NotImplementedException();
}
