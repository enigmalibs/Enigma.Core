using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Padding;

namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// Provides cryptographic services for block cipher operations. Encrypts and decrypts stream data with
/// a caller-supplied key, IV/nonce, mode of operation, and padding scheme, supporting asynchronous
/// operation with progress reporting and cancellation.
/// </summary>
public interface IBlockCipherService
{
    /// <summary>
    /// Encrypts data from the input stream to the output stream.
    /// </summary>
    /// <param name="input">The input stream containing the plaintext data.</param>
    /// <param name="output">The output stream where encrypted data will be written.</param>
    /// <param name="key">The secret key.</param>
    /// <param name="iv">
    /// The initialization vector / nonce. Required for <see cref="BlockCipherMode.Cbc"/>,
    /// <see cref="BlockCipherMode.Ctr"/> and <see cref="BlockCipherMode.Gcm"/>; pass <c>null</c> for
    /// <see cref="BlockCipherMode.Ecb"/>.
    /// </param>
    /// <param name="mode">The block cipher mode of operation.</param>
    /// <param name="padding">
    /// The padding scheme, applied only for block-aligned modes (<see cref="BlockCipherMode.Ecb"/> /
    /// <see cref="BlockCipherMode.Cbc"/>); ignored for stream-like modes (CTR/GCM). Defaults to
    /// <see cref="PaddingScheme.Pkcs7"/>.
    /// </param>
    /// <param name="gcmMacSizeBits">
    /// The authentication tag size in bits, used only when <paramref name="mode"/> is
    /// <see cref="BlockCipherMode.Gcm"/>; must satisfy <see cref="GcmMacSize.IsValid"/>. Defaults to
    /// <see cref="GcmMacSize.MaxBits"/>.
    /// </param>
    /// <param name="progress">Optional progress reporting mechanism that reports bytes processed.</param>
    /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous encryption operation.</returns>
    Task EncryptAsync(
        Stream input,
        Stream output,
        byte[] key,
        byte[]? iv,
        BlockCipherMode mode,
        PaddingScheme padding = PaddingScheme.Pkcs7,
        int gcmMacSizeBits = GcmMacSize.MaxBits,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Decrypts data from the input stream to the output stream.
    /// </summary>
    /// <param name="input">The input stream containing the encrypted data.</param>
    /// <param name="output">The output stream where decrypted data will be written.</param>
    /// <param name="key">The secret key.</param>
    /// <param name="iv">
    /// The initialization vector / nonce that was used for encryption. Required for
    /// <see cref="BlockCipherMode.Cbc"/>, <see cref="BlockCipherMode.Ctr"/> and
    /// <see cref="BlockCipherMode.Gcm"/>; pass <c>null</c> for <see cref="BlockCipherMode.Ecb"/>.
    /// </param>
    /// <param name="mode">The block cipher mode of operation.</param>
    /// <param name="padding">
    /// The padding scheme that was used, applied only for block-aligned modes
    /// (<see cref="BlockCipherMode.Ecb"/> / <see cref="BlockCipherMode.Cbc"/>); ignored for stream-like
    /// modes (CTR/GCM). Defaults to <see cref="PaddingScheme.Pkcs7"/>.
    /// </param>
    /// <param name="gcmMacSizeBits">
    /// The authentication tag size in bits, used only when <paramref name="mode"/> is
    /// <see cref="BlockCipherMode.Gcm"/>; must satisfy <see cref="GcmMacSize.IsValid"/>. Defaults to
    /// <see cref="GcmMacSize.MaxBits"/>.
    /// </param>
    /// <param name="progress">Optional progress reporting mechanism that reports bytes processed.</param>
    /// <param name="cancellationToken">Optional cancellation token to cancel the operation.</param>
    /// <returns>A task representing the asynchronous decryption operation.</returns>
    Task DecryptAsync(
        Stream input,
        Stream output,
        byte[] key,
        byte[]? iv,
        BlockCipherMode mode,
        PaddingScheme padding = PaddingScheme.Pkcs7,
        int gcmMacSizeBits = GcmMacSize.MaxBits,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default);
}
