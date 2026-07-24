namespace Enigma.Core.Hashing.Hmac;

/// <summary>
/// Factory for creating <see cref="IHmacService"/> instances, one per supported HMAC algorithm.
/// </summary>
/// <remarks>
/// The factory selects the underlying hash algorithm that backs the HMAC construction; the data and
/// secret key are supplied per call on the returned service.
/// </remarks>
public interface IHmacServiceFactory
{
    /// <summary>Creates an HMAC service backed by SHA-1 (HMAC-SHA1).</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured HMAC service.</returns>
    /// <remarks>SHA-1 is deprecated for security-sensitive use; provided for legacy interoperability.</remarks>
    IHmacService CreateHmacSha1Service(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates an HMAC service backed by SHA-256 (HMAC-SHA256).</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured HMAC service.</returns>
    IHmacService CreateHmacSha256Service(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates an HMAC service backed by SHA-512 (HMAC-SHA512).</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured HMAC service.</returns>
    IHmacService CreateHmacSha512Service(int bufferSize = CryptoDefaults.StreamBufferSize);
}
