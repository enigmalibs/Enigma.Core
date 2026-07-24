using System;
using Org.BouncyCastle.Utilities.Encoders;

namespace Enigma.Core.Encoding;

/// <summary>
/// Encodes and decodes binary data using Base64 (RFC 4648).
/// </summary>
/// <remarks>
/// <see cref="Encode"/> produces canonical padded Base64; <see cref="Decode"/> is tolerant of
/// embedded whitespace (line breaks, spaces), matching the behavior of the streamed Base64 text
/// commonly found in PEM and MIME payloads.
/// </remarks>
public sealed class Base64Service : IEncodingService
{
    /// <inheritdoc />
    public string Encode(byte[] data)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        return Base64.ToBase64String(data);
    }

    /// <inheritdoc />
    public byte[] Decode(string encoded)
    {
        if (encoded is null) throw new ArgumentNullException(nameof(encoded));
        return Base64.Decode(encoded);
    }
}
