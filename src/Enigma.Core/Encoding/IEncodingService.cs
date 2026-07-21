namespace Enigma.Core.Encoding;

/// <summary>
/// Converts binary data to and from a textual representation using the scheme selected by the factory
/// (Base64, Base32 or hexadecimal). Encoding and decoding are exact inverses of each other.
/// </summary>
public interface IEncodingService
{
    /// <summary>
    /// Encodes binary data into its textual representation.
    /// </summary>
    /// <param name="data">The bytes to encode.</param>
    /// <returns>The encoded text.</returns>
    string Encode(byte[] data);

    /// <summary>
    /// Decodes text produced by <see cref="Encode"/> back into the original bytes.
    /// </summary>
    /// <param name="encoded">The encoded text to decode.</param>
    /// <returns>The decoded bytes.</returns>
    byte[] Decode(string encoded);
}
