namespace Enigma.Core;

/// <summary>
/// Shared default values used across the library, exposed so callers can reference the same
/// canonical constants instead of duplicating magic numbers.
/// </summary>
public static class CryptoDefaults
{
    /// <summary>
    /// Default buffer size, in bytes, for stream-based processing (block ciphers, stream ciphers,
    /// hashing and HMAC). 4096 bytes (4 KiB).
    /// </summary>
    public const int StreamBufferSize = 4096;
}
