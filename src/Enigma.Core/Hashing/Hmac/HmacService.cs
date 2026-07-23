using System;
using System.Buffers;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.Core.Hashing.Hmac;

/// <summary>
/// Computes an HMAC (RFC 2104) over in-memory data or a stream, using the digest selected by the
/// factory and a per-call secret key.
/// </summary>
/// <remarks>
/// The key is a per-call argument, caller-owned: the service uses the supplied array as-is and never
/// clears it. The caller is responsible for clearing sensitive key material when done. A fresh MAC is
/// created and initialized on every call, so a single instance is safe to reuse across calls and across
/// keys. Instances are created by <see cref="HmacServiceFactory"/> only; the digest algorithm is wired
/// internally so no BouncyCastle type appears on the public surface.
/// </remarks>
public sealed class HmacService : IHmacService
{
    private readonly Func<IDigest> _digestFactory;
    private readonly int _bufferSize;
    private readonly ArrayPool<byte> _arrayPool;

    // Internal: only the factory constructs the service; the Func<IDigest> selector stays off the
    // public surface (principle 1). The key is no longer captured here — it is passed per call.
    internal HmacService(Func<IDigest> digestFactory, int bufferSize = CryptoDefaults.StreamBufferSize)
    {
        _digestFactory = digestFactory ?? throw new ArgumentNullException(nameof(digestFactory));
        // A non-positive buffer would make the streaming read loop terminate before consuming the input,
        // so ComputeHmacAsync would silently authenticate zero bytes. Reject it at creation instead.
        if (bufferSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(bufferSize), bufferSize, "Buffer size must be positive.");
        _bufferSize = bufferSize;
        _arrayPool = ArrayPool<byte>.Shared;
    }

    /// <inheritdoc />
    public byte[] ComputeHmac(byte[] data, byte[] key)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        if (key is null) throw new ArgumentNullException(nameof(key));

        var mac = CreateMac(key);
        mac.BlockUpdate(data, 0, data.Length);

        var output = new byte[mac.GetMacSize()];
        mac.DoFinal(output, 0);
        return output;
    }

    /// <inheritdoc />
    public async Task<byte[]> ComputeHmacAsync(
        Stream input,
        byte[] key,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (key is null) throw new ArgumentNullException(nameof(key));

        cancellationToken.ThrowIfCancellationRequested();

        var mac = CreateMac(key);
        var buffer = _arrayPool.Rent(_bufferSize);

        try
        {
            int bytesRead;
            while ((bytesRead = await input.ReadAsync(buffer, 0, _bufferSize, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                mac.BlockUpdate(buffer, 0, bytesRead);
                progress?.Report(bytesRead);
            }

            var output = new byte[mac.GetMacSize()];
            mac.DoFinal(output, 0);
            return output;
        }
        finally
        {
            // Clear on return: buffered plaintext may be sensitive and must not linger in the pool.
            _arrayPool.Return(buffer, clearArray: true);
        }
    }

    private HMac CreateMac(byte[] key)
    {
        var mac = new HMac(_digestFactory());
        mac.Init(new KeyParameter(key));
        return mac;
    }
}
