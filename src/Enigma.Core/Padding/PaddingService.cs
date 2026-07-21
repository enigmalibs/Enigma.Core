using System;

namespace Enigma.Core.Padding;

/// <summary>
/// Provides padding and unpadding functionality for block cipher operations, following a configured
/// <see cref="PaddingScheme"/>.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete padding logic arrives with the symmetric-cipher implementation feature.
/// </remarks>
public sealed class PaddingService : IPaddingService
{
    /// <inheritdoc />
    public byte[] Pad(byte[] data, int blockSize) => throw new NotImplementedException();

    /// <inheritdoc />
    public byte[] Unpad(byte[] data, int blockSize) => throw new NotImplementedException();
}
