namespace Enigma.Core.Hashing.Hash;

/// <summary>
/// Factory for creating <see cref="IHashService"/> instances, one per supported hash algorithm.
/// </summary>
/// <remarks>
/// A hash service produces a fixed-size digest of arbitrary input. The factory selects only the
/// underlying algorithm; the data to hash is supplied per call on the returned service.
/// </remarks>
public interface IHashServiceFactory
{
    /// <summary>Creates a hash service for the MD5 algorithm (128-bit digest).</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured hash service.</returns>
    /// <remarks>MD5 is cryptographically broken; provided for legacy interoperability only.</remarks>
    IHashService CreateMd5Service(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a hash service for the SHA-1 algorithm (160-bit digest).</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured hash service.</returns>
    /// <remarks>SHA-1 is deprecated for security-sensitive use; provided for legacy interoperability.</remarks>
    IHashService CreateSha1Service(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a hash service for the SHA-256 algorithm (256-bit digest).</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured hash service.</returns>
    IHashService CreateSha256Service(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a hash service for the SHA-512 algorithm (512-bit digest).</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured hash service.</returns>
    IHashService CreateSha512Service(int bufferSize = CryptoDefaults.StreamBufferSize);

    /// <summary>Creates a hash service for the SHA-3 (256-bit) algorithm.</summary>
    /// <param name="bufferSize">Size of the internal processing buffer, in bytes. Defaults to 4096.</param>
    /// <returns>A configured hash service.</returns>
    IHashService CreateSha3Service(int bufferSize = CryptoDefaults.StreamBufferSize);
}
