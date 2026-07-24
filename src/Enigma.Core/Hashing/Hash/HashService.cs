using System;
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;

namespace Enigma.Core.Hashing.Hash;

/// <summary>
/// Computes a cryptographic hash digest over stream data using the algorithm selected by the factory.
/// </summary>
/// <remarks>
/// Instances are created by <see cref="HashServiceFactory"/> only; the algorithm is chosen there. The
/// digest algorithm is wired internally, so no BouncyCastle type appears on the public surface.
/// </remarks>
public sealed class HashService : IHashService
{
    private readonly Func<IDigest> _digestFactory;
    private readonly int _bufferSize;
    private readonly ArrayPool<byte> _arrayPool;

    // Internal so only the factory (same assembly) can construct a service; the Func<IDigest> digest
    // selector never becomes part of the public API surface (principle 1 — BouncyCastle stays hidden).
    internal HashService(Func<IDigest> digestFactory, int bufferSize = CryptoDefaults.StreamBufferSize)
    {
        _digestFactory = digestFactory ?? throw new ArgumentNullException(nameof(digestFactory));
        // A non-positive buffer would make the read loop terminate before consuming the stream, so the
        // service would silently return the empty-message digest. Reject it at creation instead.
        if (bufferSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(bufferSize), bufferSize, "Buffer size must be positive.");
        _bufferSize = bufferSize;
        _arrayPool = ArrayPool<byte>.Shared;
    }

    /// <inheritdoc />
    public async Task<byte[]> ComputeHashAsync(
        Stream input,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));

        cancellationToken.ThrowIfCancellationRequested();

        var digest = _digestFactory();
        var buffer = _arrayPool.Rent(_bufferSize);

        try
        {
            int bytesRead;
            while ((bytesRead = await input.ReadAsync(buffer, 0, _bufferSize, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                digest.BlockUpdate(buffer, 0, bytesRead);
                progress?.Report(bytesRead);
            }

            var hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);
            return hash;
        }
        finally
        {
            // Clear on return: input plaintext may be sensitive and must not linger in a pooled buffer.
            _arrayPool.Return(buffer, clearArray: true);
        }
    }
}
