using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;

namespace Enigma.Core.Symmetric.StreamCiphers;

/// <summary>
/// Default <see cref="IStreamCipherServiceFactory"/> implementation. Selects the underlying stream
/// cipher by binding the matching BouncyCastle engine (wrapped in a <see cref="BufferedStreamCipher"/>)
/// into a <see cref="StreamCipherService"/>; the key and nonce are supplied per call on the returned
/// service.
/// </summary>
public sealed class StreamCipherServiceFactory : IStreamCipherServiceFactory
{
    /// <inheritdoc />
    public IStreamCipherService CreateChaCha7539Service(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new StreamCipherService(() => new BufferedStreamCipher(new ChaCha7539Engine()), bufferSize);

    /// <inheritdoc />
    public IStreamCipherService CreateChaCha20Service(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new StreamCipherService(() => new BufferedStreamCipher(new ChaChaEngine()), bufferSize);

    /// <inheritdoc />
    public IStreamCipherService CreateSalsa20Service(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new StreamCipherService(() => new BufferedStreamCipher(new Salsa20Engine()), bufferSize);
}
