using System;
using System.Buffers;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;

namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// Provides streaming encryption and decryption for a single block cipher algorithm. The mode of
/// operation, key, IV/nonce, padding, GCM tag size and optional associated data are supplied per call.
/// </summary>
/// <remarks>
/// Instances are created by <see cref="BlockCipherServiceFactory"/> only; the algorithm is chosen there
/// via the engine constructor. The mode/padding/parameter wiring and every BouncyCastle type are
/// internal, so no BouncyCastle type appears on the public surface (principle 1). GCM authentication
/// failures surface as <see cref="CryptographicException"/>, never the underlying BouncyCastle type.
/// </remarks>
public sealed class BlockCipherService : IBlockCipherService
{
    private static readonly IBlockCipherPaddingFactory PaddingFactory = new BlockCipherPaddingFactory();
    private static readonly IBlockCipherParametersFactory ParametersFactory = new BlockCipherParametersFactory();

    private readonly Func<IBlockCipher> _engineFactory;
    private readonly int _bufferSize;
    private readonly ArrayPool<byte> _arrayPool;

    // Internal so only the factory (same assembly) can construct a service; the Func<IBlockCipher>
    // engine selector never becomes part of the public API surface (principle 1 — BouncyCastle stays
    // hidden).
    internal BlockCipherService(Func<IBlockCipher> engineFactory, int bufferSize = CryptoDefaults.StreamBufferSize)
    {
        _engineFactory = engineFactory ?? throw new ArgumentNullException(nameof(engineFactory));
        // A non-positive buffer would make the read loop terminate before consuming the stream.
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
        byte[]? iv,
        BlockCipherMode mode,
        PaddingScheme padding = PaddingScheme.Pkcs7,
        int gcmMacSizeBits = GcmMacSize.MaxBits,
        byte[]? associatedData = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));

        cancellationToken.ThrowIfCancellationRequested();

        var cipher = CreateInitializedCipher(forEncryption: true, key, iv, mode, padding, gcmMacSizeBits, associatedData);

        var buffer = _arrayPool.Rent(_bufferSize);
        try
        {
            // NonDisposingStreamWrapper keeps CipherStream from closing the caller's output stream.
            // Disposing the cipher stream writes the final block (padding for ECB/CBC, tag for GCM) to
            // the output; keep the disposal inside the try so the buffer is only returned afterwards.
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
            // e.g. PaddingScheme.None with input that is not a whole number of blocks. Never leak the
            // BouncyCastle exception type to callers.
            throw new CryptographicException(
                "Encryption failed. When no padding is used the input length must be a whole number of " +
                "cipher blocks.", ex);
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
        byte[]? iv,
        BlockCipherMode mode,
        PaddingScheme padding = PaddingScheme.Pkcs7,
        int gcmMacSizeBits = GcmMacSize.MaxBits,
        byte[]? associatedData = null,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default)
    {
        if (input is null) throw new ArgumentNullException(nameof(input));
        if (output is null) throw new ArgumentNullException(nameof(output));

        cancellationToken.ThrowIfCancellationRequested();

        var cipher = CreateInitializedCipher(forEncryption: false, key, iv, mode, padding, gcmMacSizeBits, associatedData);

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
            // GCM tag mismatch (InvalidCipherTextException), corrupt/truncated ciphertext or bad padding
            // (DataLengthException / OutputLengthException) — all derive from the BouncyCastle
            // CryptoException base. Catch the base so no BouncyCastle exception type ever escapes.
            throw new CryptographicException(
                "Decryption failed: the data could not be authenticated or its length/padding was invalid. " +
                "It may have been tampered with or truncated, or the key, IV/nonce, associated data or tag " +
                "size may be wrong.", ex);
        }
        finally
        {
            _arrayPool.Return(buffer, clearArray: true);
        }
    }

    private IBufferedCipher CreateInitializedCipher(
        bool forEncryption,
        byte[] key,
        byte[]? iv,
        BlockCipherMode mode,
        PaddingScheme padding,
        int gcmMacSizeBits,
        byte[]? associatedData)
    {
        if (key is null) throw new ArgumentNullException(nameof(key));

        var engine = _engineFactory();
        var blockSize = engine.GetBlockSize();

        ValidateArguments(engine, blockSize, iv, mode, gcmMacSizeBits, associatedData);

        var parameters = ParametersFactory.Create(mode, key, iv, gcmMacSizeBits, associatedData);
        var cipher = BuildCipher(mode, padding, engine);
        cipher.Init(forEncryption, parameters);
        return cipher;
    }

    // Guards the arguments that depend on the mode and the engine's block size, producing clear messages
    // before BouncyCastle's own (less specific) Init validation would fire.
    private static void ValidateArguments(
        IBlockCipher engine,
        int blockSize,
        byte[]? iv,
        BlockCipherMode mode,
        int gcmMacSizeBits,
        byte[]? associatedData)
    {
        if (associatedData is { Length: > 0 } && mode != BlockCipherMode.Gcm)
            throw new ArgumentException("Associated data is only supported in GCM mode.", nameof(associatedData));

        switch (mode)
        {
            case BlockCipherMode.Ecb:
                // ECB uses no IV; any supplied value is ignored.
                break;

            case BlockCipherMode.Cbc:
                RequireIv(iv, mode);
                if (iv!.Length != blockSize)
                    throw new ArgumentException(
                        $"CBC mode requires an IV of exactly {blockSize} bytes for '{engine.AlgorithmName}'; got {iv.Length}.",
                        nameof(iv));
                break;

            case BlockCipherMode.Ctr:
                RequireIv(iv, mode);
                // CTR/SIC accepts an IV/nonce no longer than the block size; a 16-byte IV on a 64-bit
                // block cipher is the common "IV-incompatible" misuse and is rejected here clearly.
                if (iv!.Length > blockSize)
                    throw new ArgumentException(
                        $"CTR mode requires an IV/nonce no longer than the {blockSize}-byte block for '{engine.AlgorithmName}'; got {iv.Length}.",
                        nameof(iv));
                break;

            case BlockCipherMode.Gcm:
                if (blockSize != 16)
                    throw new ArgumentException(
                        $"GCM requires a 128-bit block cipher; '{engine.AlgorithmName}' uses a {blockSize * 8}-bit block.",
                        nameof(mode));
                RequireIv(iv, mode);
                if (iv!.Length == 0)
                    throw new ArgumentException("GCM mode requires a non-empty nonce.", nameof(iv));
                if (!GcmMacSize.IsValid(gcmMacSizeBits))
                    throw new ArgumentException(GcmMacSize.RangeDescription, nameof(gcmMacSizeBits));
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown block cipher mode.");
        }
    }

    private static void RequireIv(byte[]? iv, BlockCipherMode mode)
    {
        if (iv is null)
            throw new ArgumentException($"An IV/nonce is required for {mode} mode.", nameof(iv));
    }

    // Assembles the buffered cipher for the requested mode. Padding is applied only for the block-aligned
    // modes (ECB/CBC) and only when a scheme other than None is requested; CTR and GCM never pad.
    private static IBufferedCipher BuildCipher(BlockCipherMode mode, PaddingScheme padding, IBlockCipher engine)
    {
        switch (mode)
        {
            case BlockCipherMode.Ecb:
                var ecb = new EcbBlockCipher(engine);
                return padding == PaddingScheme.None
                    ? new BufferedBlockCipher(ecb)
                    : new PaddedBufferedBlockCipher(ecb, PaddingFactory.Create(padding));

            case BlockCipherMode.Cbc:
                var cbc = new CbcBlockCipher(engine);
                return padding == PaddingScheme.None
                    ? new BufferedBlockCipher(cbc)
                    : new PaddedBufferedBlockCipher(cbc, PaddingFactory.Create(padding));

            case BlockCipherMode.Ctr:
                return new BufferedBlockCipher(new SicBlockCipher(engine));

            case BlockCipherMode.Gcm:
                return new BufferedAeadBlockCipher(new GcmBlockCipher(engine));

            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unknown block cipher mode.");
        }
    }
}
