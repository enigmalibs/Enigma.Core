using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Padding;

namespace Enigma.Core.Symmetric.BlockCiphers;

/// <summary>
/// Provides cryptographic operations for block ciphers.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete cipher logic arrives with the symmetric-cipher implementation feature.
/// </remarks>
public sealed class BlockCipherService : IBlockCipherService
{
    /// <inheritdoc />
    public Task EncryptAsync(
        Stream input,
        Stream output,
        byte[] key,
        byte[]? iv,
        BlockCipherMode mode,
        PaddingScheme padding = PaddingScheme.Pkcs7,
        int gcmMacSizeBits = GcmMacSize.MaxBits,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default) => throw new NotImplementedException();

    /// <inheritdoc />
    public Task DecryptAsync(
        Stream input,
        Stream output,
        byte[] key,
        byte[]? iv,
        BlockCipherMode mode,
        PaddingScheme padding = PaddingScheme.Pkcs7,
        int gcmMacSizeBits = GcmMacSize.MaxBits,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default) => throw new NotImplementedException();
}
