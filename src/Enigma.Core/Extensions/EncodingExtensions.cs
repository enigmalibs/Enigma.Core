using Enigma.Core.Encoding;
using TextEncoding = System.Text.Encoding;

namespace Enigma.Core.Extensions;

/// <summary>
/// Encoding extensions
/// </summary>
public static class EncodingExtensions
{
    private static readonly Base64Service Base64Service = new();
    private static readonly HexService HexService = new();
    private static readonly Base32Service Base32Service = new();

    // UTF-8, not Encoding.Default: Encoding.Default resolves to UTF-8 on modern .NET but to the
    // system ANSI code page on netstandard2.0/.NET Framework, so the same call would otherwise
    // produce different bytes/strings depending on the consuming runtime — a correctness trap in a
    // crypto library. UTF-8 is stable across every target framework.
    // TextEncoding aliases System.Text.Encoding: the type name Encoding otherwise collides with the
    // Enigma.Core.Encoding namespace that hosts the Base64/Hex/Base32 services.
    private static readonly TextEncoding DefaultEncoding = TextEncoding.UTF8;

    /// <summary>
    /// Bytes extensions (byte[])
    /// </summary>
    /// <param name="bytes">Bytes</param>
    extension(byte[] bytes)
    {
        /// <summary>
        /// Encode bytes to base64 string
        /// </summary>
        /// <returns>Base64 string</returns>
        public string ToBase64String()
            => Base64Service.Encode(bytes);

        /// <summary>
        /// Encode bytes to hex string
        /// </summary>
        /// <returns>Hex string</returns>
        public string ToHexString()
            => HexService.Encode(bytes);

        /// <summary>
        /// Encode bytes to base32 string (RFC 4648, padded)
        /// </summary>
        /// <returns>Base32 string</returns>
        public string ToBase32String()
            => Base32Service.Encode(bytes);

        /// <summary>
        /// Decodes all the bytes in the specified byte array into a string
        /// </summary>
        /// <param name="encoding">Encoding. If null, UTF-8 is used (consistent across target frameworks)</param>
        /// <returns>String</returns>
        // ReSharper disable once MemberCanBePrivate.Global
        public string GetString(TextEncoding? encoding = null)
            => (encoding ?? DefaultEncoding).GetString(bytes);

        /// <summary>
        /// Decodes all the bytes in the specified byte array into a string with UTF-8 encoding
        /// </summary>
        /// <returns>String</returns>
        public string GetUtf8String()
            => GetString(bytes, TextEncoding.UTF8);

        /// <summary>
        /// Decodes all the bytes in the specified byte array into a string with ASCII encoding
        /// </summary>
        /// <returns>String</returns>
        public string GetAsciiString()
            => GetString(bytes, TextEncoding.ASCII);
    }

    /// <summary>
    /// String extensions
    /// </summary>
    /// <param name="str">String</param>
    extension(string str)
    {
        /// <summary>
        /// Decode base64 string to bytes
        /// </summary>
        /// <returns>Bytes</returns>
        public byte[] FromBase64String()
            => Base64Service.Decode(str);

        /// <summary>
        /// Decode hex string to bytes
        /// </summary>
        /// <returns>Bytes</returns>
        public byte[] FromHexString()
            => HexService.Decode(str);

        /// <summary>
        /// Decode base32 string to bytes (RFC 4648; tolerant of case, whitespace and missing padding)
        /// </summary>
        /// <returns>Bytes</returns>
        public byte[] FromBase32String()
            => Base32Service.Decode(str);

        /// <summary>
        /// Encodes all the characters in the specified string into a sequence of bytes
        /// </summary>
        /// <param name="encoding">Encoding. If null, UTF-8 is used (consistent across target frameworks)</param>
        /// <returns>Bytes</returns>
        // ReSharper disable once MemberCanBePrivate.Global
        public byte[] GetBytes(TextEncoding? encoding = null)
            => (encoding ?? DefaultEncoding).GetBytes(str);

        /// <summary>
        /// Encodes all the characters in the specified string into a sequence of bytes with UTF-8 encoding
        /// </summary>
        /// <returns>Bytes</returns>
        public byte[] GetUtf8Bytes()
            => GetBytes(str, TextEncoding.UTF8);

        /// <summary>
        /// Encodes all the characters in the specified string into a sequence of bytes with ASCII encoding
        /// </summary>
        /// <returns>Bytes</returns>
        public byte[] GetAsciiBytes()
            => GetBytes(str, TextEncoding.ASCII);
    }
}
