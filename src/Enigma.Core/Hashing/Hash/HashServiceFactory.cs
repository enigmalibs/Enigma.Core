using System;
using Org.BouncyCastle.Crypto.Digests;

namespace Enigma.Core.Hashing.Hash;

/// <summary>
/// Default <see cref="IHashServiceFactory"/> implementation. Selects the underlying digest algorithm
/// and hands a configured <see cref="HashService"/> back as an <see cref="IHashService"/>.
/// </summary>
public sealed class HashServiceFactory : IHashServiceFactory
{
    /// <inheritdoc />
    public IHashService CreateMd5Service(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new HashService(() => new MD5Digest(), bufferSize);

    /// <inheritdoc />
    public IHashService CreateSha1Service(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new HashService(() => new Sha1Digest(), bufferSize);

    /// <inheritdoc />
    public IHashService CreateSha256Service(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new HashService(() => new Sha256Digest(), bufferSize);

    /// <inheritdoc />
    public IHashService CreateSha512Service(int bufferSize = CryptoDefaults.StreamBufferSize)
        => new HashService(() => new Sha512Digest(), bufferSize);

    /// <inheritdoc />
    public IHashService CreateSha3Service(int bitLength = 256, int bufferSize = CryptoDefaults.StreamBufferSize)
    {
        // FIPS 202 defines SHA-3 only for these four output sizes. Validate here (not inside the read
        // loop) so the error surfaces at creation with a clear parameter name.
        if (bitLength is not (224 or 256 or 384 or 512))
            throw new ArgumentException(
                "SHA-3 output size must be one of 224, 256, 384 or 512 bits.", nameof(bitLength));

        return new HashService(() => new Sha3Digest(bitLength), bufferSize);
    }
}
