using System;

namespace Enigma.Core.Encoding;

/// <summary>
/// Encodes and decodes binary data using Base32 (RFC 4648).
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete Base32 logic arrives with the encoding implementation feature.
/// </remarks>
public sealed class Base32Service : IEncodingService
{
    /// <inheritdoc />
    public string Encode(byte[] data) => throw new NotImplementedException();

    /// <inheritdoc />
    public byte[] Decode(string encoded) => throw new NotImplementedException();
}
