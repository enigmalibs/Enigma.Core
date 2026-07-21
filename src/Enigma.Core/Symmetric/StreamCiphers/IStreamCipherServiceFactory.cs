namespace Enigma.Core.Symmetric.StreamCiphers;

/// <summary>
/// Factory for creating <see cref="IStreamCipherService"/> instances, one per supported stream cipher.
/// </summary>
public interface IStreamCipherServiceFactory
{
    /// <summary>
    /// Creates a ChaCha20-RFC7539 stream cipher service.
    /// </summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured ChaCha20-RFC7539 cipher service.</returns>
    /// <remarks>
    /// This implementation follows the RFC 7539 standard, which specifies a 96-bit nonce and 32-bit
    /// counter, offering improved security and interoperability compared to the original ChaCha20.
    /// </remarks>
    IStreamCipherService CreateChaCha7539Service(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>
    /// Creates a ChaCha20 stream cipher service (original version).
    /// </summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured ChaCha20 cipher service.</returns>
    /// <remarks>
    /// The original ChaCha20 uses a 64-bit nonce and 64-bit counter. Consider the RFC 7539 version for
    /// newer applications requiring standards compliance.
    /// </remarks>
    IStreamCipherService CreateChaCha20Service(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>
    /// Creates a Salsa20 stream cipher service.
    /// </summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured Salsa20 cipher service.</returns>
    /// <remarks>
    /// Salsa20 is the predecessor to ChaCha20, using a similar design but with different internal
    /// operations.
    /// </remarks>
    IStreamCipherService CreateSalsa20Service(int bufferSize = CryptoDefaults.StreamBufferSize);
}
