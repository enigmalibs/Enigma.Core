using System;
using Org.BouncyCastle.Utilities.Encoders;

namespace Enigma.Core.Encoding;

/// <summary>
/// Encodes and decodes binary data using hexadecimal (base-16) text.
/// </summary>
/// <remarks>
/// <see cref="Encode"/> emits <b>lowercase</b> hexadecimal; <see cref="Decode"/> accepts either case.
/// </remarks>
public sealed class HexService : IEncodingService
{
    /// <inheritdoc />
    public string Encode(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return Hex.ToHexString(data);
    }

    /// <inheritdoc />
    public byte[] Decode(string encoded)
    {
        if (encoded is null) throw new ArgumentNullException(nameof(encoded));
        return Hex.Decode(encoded);
    }
}
