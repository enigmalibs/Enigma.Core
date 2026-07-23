using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Extensions;

/// <summary>
/// Bytes stream extensions
/// </summary>
public static class StreamExtensionsBytes
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        // Note: sync WriteByte(byte)/ReadByte() are intentionally NOT provided here — System.IO.Stream
        // already exposes instance methods with those names, which win overload resolution and shadow
        // any extension of the same shape. The async variants below have no such built-in counterpart.

        /// <summary>
        /// Asynchronously write byte value
        /// </summary>
        /// <param name="value">Byte value</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task WriteByteAsync(byte value, CancellationToken cancellationToken = default)
            => await stream.WriteAsync([value], 0, 1, cancellationToken).ConfigureAwait(false);

        /// <summary>
        /// Asynchronously read byte value
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Byte value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<byte> ReadByteAsync(CancellationToken cancellationToken = default)
        {
            var buffer = new byte[sizeof(byte)];
            await StreamReadHelpers.ReadExactAsync(stream, buffer, 0, sizeof(byte), cancellationToken).ConfigureAwait(false);
            return buffer[0];
        }

        /// <summary>
        /// Write bytes
        /// </summary>
        /// <param name="bytes">Bytes</param>
        public void WriteBytes(byte[] bytes)
            => stream.Write(bytes, 0, bytes.Length);

        /// <summary>
        /// Asynchronously write bytes
        /// </summary>
        /// <param name="bytes">Bytes</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task WriteBytesAsync(byte[] bytes, CancellationToken cancellationToken = default)
            => await stream.WriteAsync(bytes, 0, bytes.Length, cancellationToken).ConfigureAwait(false);

        /// <summary>
        /// Read bytes
        /// </summary>
        /// <param name="count">Number of bytes to read</param>
        /// <returns>Bytes</returns>
        /// <exception cref="IOException"></exception>
        public byte[] ReadBytes(int count)
        {
            var buffer = new byte[count];
            StreamReadHelpers.ReadExact(stream, buffer, 0, count);
            return buffer;
        }

        /// <summary>
        /// Asynchronously read bytes
        /// </summary>
        /// <param name="count">Number of bytes to read</param>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Bytes</returns>
        /// <exception cref="IOException"></exception>
        public async Task<byte[]> ReadBytesAsync(int count, CancellationToken cancellationToken = default)
        {
            var buffer = new byte[count];
            await StreamReadHelpers.ReadExactAsync(stream, buffer, 0, count, cancellationToken).ConfigureAwait(false);
            return buffer;
        }
    }
}
