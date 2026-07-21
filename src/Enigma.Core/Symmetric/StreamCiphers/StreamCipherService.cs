using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Symmetric.StreamCiphers;

/// <summary>
/// Provides cryptographic operations for stream ciphers.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete cipher logic arrives with the symmetric-cipher implementation feature.
/// </remarks>
public sealed class StreamCipherService : IStreamCipherService
{
    /// <inheritdoc />
    public Task EncryptAsync(
        Stream input,
        Stream output,
        byte[] key,
        byte[] nonce,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default) => throw new NotImplementedException();

    /// <inheritdoc />
    public Task DecryptAsync(
        Stream input,
        Stream output,
        byte[] key,
        byte[] nonce,
        IProgress<int>? progress = null,
        CancellationToken cancellationToken = default) => throw new NotImplementedException();
}
