using System;

namespace Enigma.Core.Padding;

/// <summary>
/// A padding service that performs no padding — the data is returned unchanged. Corresponds to
/// <see cref="PaddingScheme.None"/>.
/// </summary>
/// <remarks>
/// The <c>blockSize</c> argument is accepted for interface symmetry but ignored: the data is returned
/// unchanged, so callers are responsible for supplying block-aligned data.
/// </remarks>
public sealed class NoPaddingService : IPaddingService
{
    /// <inheritdoc />
    public byte[] Pad(byte[] data, int blockSize)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return data;
    }

    /// <inheritdoc />
    public byte[] Unpad(byte[] data, int blockSize)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return data;
    }
}
