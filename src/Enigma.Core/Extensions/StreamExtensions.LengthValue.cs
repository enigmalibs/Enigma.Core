using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Extensions;

/// <summary>
/// Length-Value stream extensions
/// </summary>
public static class StreamExtensionsLengthValue
{
    private const int DefaultMaxLength = 10 * 1024 * 1024; // 10 MB

    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write value length and value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteLengthValue(byte[] value)
        {
            stream.WriteInt(value.Length);
            stream.WriteBytes(value);
        }

        /// <summary>
        /// Asynchronously write value length and value
        /// </summary>
        /// <param name="value">Value</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task WriteLengthValueAsync(byte[] value, CancellationToken cancellationToken = default)
        {
            await stream.WriteIntAsync(value.Length, cancellationToken).ConfigureAwait(false);
            await stream.WriteBytesAsync(value, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Read value length and value
        /// </summary>
        /// <param name="maxLength">Maximum allowed length in bytes (default 10 MB)</param>
        /// <returns>Value</returns>
        /// <exception cref="InvalidOperationException">Thrown when length is negative or exceeds maxLength</exception>
        public byte[] ReadLengthValue(int maxLength = DefaultMaxLength)
        {
            var length = stream.ReadInt();
            if (length < 0 || length > maxLength)
                throw new InvalidOperationException($"Length value {length} is out of allowed range [0, {maxLength}].");
            return stream.ReadBytes(length);
        }

        /// <summary>
        /// Asynchronously read value length and value
        /// </summary>
        /// <param name="maxLength">Maximum allowed length in bytes (default 10 MB)</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Value</returns>
        /// <exception cref="InvalidOperationException">Thrown when length is negative or exceeds maxLength</exception>
        public async Task<byte[]> ReadLengthValueAsync(int maxLength = DefaultMaxLength, CancellationToken cancellationToken = default)
        {
            var length = await stream.ReadIntAsync(cancellationToken).ConfigureAwait(false);
            if (length < 0 || length > maxLength)
                throw new InvalidOperationException($"Length value {length} is out of allowed range [0, {maxLength}].");
            return await stream.ReadBytesAsync(length, cancellationToken).ConfigureAwait(false);
        }
    }
}
