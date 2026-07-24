using Org.BouncyCastle.Crypto.Digests;

namespace Enigma.Core.Hashing.Hmac;

/// <summary>
/// Default <see cref="IHmacServiceFactory"/> implementation. Selects the underlying digest that backs
/// the HMAC construction and hands a configured <see cref="HmacService"/> back as an
/// <see cref="IHmacService"/>. The secret key is supplied per call on the returned service.
/// </summary>
public sealed class HmacServiceFactory : IHmacServiceFactory
{
    /// <inheritdoc />
    public IHmacService CreateHmacSha1Service(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new HmacService(() => new Sha1Digest(), bufferSize);

    /// <inheritdoc />
    public IHmacService CreateHmacSha256Service(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new HmacService(() => new Sha256Digest(), bufferSize);

    /// <inheritdoc />
    public IHmacService CreateHmacSha512Service(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new HmacService(() => new Sha512Digest(), bufferSize);
}
