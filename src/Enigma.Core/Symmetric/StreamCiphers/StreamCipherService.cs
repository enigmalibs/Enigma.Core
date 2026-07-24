using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Symmetric.BlockCiphers;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;

namespace Enigma.Core.Symmetric.StreamCiphers;

/// <summary>
/// Provides streaming encryption and decryption for a single stream cipher algorithm. The key and nonce
/// are supplied per call.
/// </summary>
/// <remarks>
/// Instances are created by <see cref="StreamCipherServiceFactory"/> only; the algorithm is chosen there
/// via the buffered-cipher constructor. Every BouncyCastle type is wired internally, so none appears on
/// the public surface (principle 1). The service never disposes the caller's streams and never lets a
/// BouncyCastle exception escape (they surface as <see cref="CryptographicException"/>).
/// </remarks>
public sealed class StreamCipherService : IStreamCipherService
{
    private readonly Func<IBufferedCipher> _cipherFactory;
    private readonly int _bufferSize;
    private readonly ArrayPool<byte> _arrayPool;

    // Internal so only the factory (same assembly) can construct a service; the Func<IBufferedCipher>
    // selector never becomes part of the public API surface (principle 1 — BouncyCastle stays hidden).
    internal StreamCipherService(Func<IBufferedCipher> cipherFactory, int bufferSize = CryptoDefaults.StreamBufferSize)
    {
        _cipherFactory = cipherFactory ?? throw new ArgumentNullException(nameof(cipherFactory));
        if (bufferSize <= 0)
            throw new ArgumentOutOfRangeException(nameof(bufferSize), bufferSize, "Buffer size must be positive.");
        _bufferSize = bufferSize;
        _arrayPool = ArrayPool<byte>.Shared;
    }

    /// <inheritdoc />
    public async Task EncryptAsync(
        Stream input,
        Stream output,
        byte[] key,
        byte[] nonce,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (nonce is null) throw new ArgumentNullException(nameof(nonce));

        cancellationToken.ThrowIfCancellationRequested();

        var cipher = CreateInitializedCipher(forEncryption: true, key, nonce);

        var buffer = _arrayPool.Rent(_bufferSize);
        try
        {
            // NonDisposingStreamWrapper keeps CipherStream from closing the caller's output stream.
            using var cipherStream = new CipherStream(new NonDisposingStreamWrapper(output), readCipher: null, writeCipher: cipher);

            int bytesRead;
            while ((bytesRead = await input.ReadAsync(buffer, 0, _bufferSize, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await cipherStream.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
                progress?.Report(bytesRead);
            }

            await cipherStream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (CryptoException ex)
        {
            throw new CryptographicException("Stream encryption failed.", ex);
        }
        finally
        {
            // Clear on return: input plaintext may be sensitive and must not linger in a pooled buffer.
            _arrayPool.Return(buffer, clearArray: true);
        }
    }

    /// <inheritdoc />
    public async Task DecryptAsync(
        Stream input,
        Stream output,
        byte[] key,
        byte[] nonce,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));
        if (key is null) throw new ArgumentNullException(nameof(key));
        if (nonce is null) throw new ArgumentNullException(nameof(nonce));

        cancellationToken.ThrowIfCancellationRequested();

        var cipher = CreateInitializedCipher(forEncryption: false, key, nonce);

        var buffer = _arrayPool.Rent(_bufferSize);
        try
        {
            // NonDisposingStreamWrapper keeps CipherStream from closing the caller's input stream.
            using var cipherStream = new CipherStream(new NonDisposingStreamWrapper(input), readCipher: cipher, writeCipher: null);

            int bytesRead;
            while ((bytesRead = await cipherStream.ReadAsync(buffer, 0, _bufferSize, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await output.WriteAsync(buffer, 0, bytesRead, cancellationToken).ConfigureAwait(false);
                progress?.Report(bytesRead);
            }

            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (CryptoException ex)
        {
            throw new CryptographicException("Stream decryption failed.", ex);
        }
        finally
        {
            _arrayPool.Return(buffer, clearArray: true);
        }
    }

    private IBufferedCipher CreateInitializedCipher(bool forEncryption, byte[] key, byte[] nonce)
    {
        var cipher = _cipherFactory();
        var parameters = new ParametersWithIV(new KeyParameter(key), nonce);
        cipher.Init(forEncryption, parameters);
        return cipher;
    }
}
