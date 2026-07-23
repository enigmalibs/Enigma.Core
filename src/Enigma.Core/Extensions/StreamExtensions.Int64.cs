using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Extensions;

/// <summary>
/// Int64 stream extensions
/// </summary>
public static class StreamExtensionsInt64
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write Int64 value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteLong(long value)
        {
            var data = new byte[8];
            data[0] = (byte)value;
            data[1] = (byte)(value >> 8);
            data[2] = (byte)(value >> 16);
            data[3] = (byte)(value >> 24);
            data[4] = (byte)(value >> 32);
            data[5] = (byte)(value >> 40);
            data[6] = (byte)(value >> 48);
            data[7] = (byte)(value >> 56);
            stream.Write(data, 0, 8);
        }

        /// <summary>
        /// Asynchronously write Int64 value
        /// </summary>
        /// <param name="value">Value</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task WriteLongAsync(long value, CancellationToken cancellationToken = default)
        {
            var data = new byte[8];
            data[0] = (byte)value;
            data[1] = (byte)(value >> 8);
            data[2] = (byte)(value >> 16);
            data[3] = (byte)(value >> 24);
            data[4] = (byte)(value >> 32);
            data[5] = (byte)(value >> 40);
            data[6] = (byte)(value >> 48);
            data[7] = (byte)(value >> 56);
            await stream.WriteAsync(data, 0, 8, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Read Int64 value
        /// </summary>
        /// <returns>Int64 value</returns>
        /// <exception cref="IOException"></exception>
        public long ReadLong()
        {
            var buffer = new byte[8];
            StreamReadHelpers.ReadExact(stream, buffer, 0, 8);
            return (long)buffer[0]
                 | ((long)buffer[1] << 8)
                 | ((long)buffer[2] << 16)
                 | ((long)buffer[3] << 24)
                 | ((long)buffer[4] << 32)
                 | ((long)buffer[5] << 40)
                 | ((long)buffer[6] << 48)
                 | ((long)buffer[7] << 56);
        }

        /// <summary>
        /// Asynchronously read Int64 value
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Int64 value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<long> ReadLongAsync(CancellationToken cancellationToken = default)
        {
            var buffer = new byte[8];
            await StreamReadHelpers.ReadExactAsync(stream, buffer, 0, 8, cancellationToken).ConfigureAwait(false);
            return (long)buffer[0]
                 | ((long)buffer[1] << 8)
                 | ((long)buffer[2] << 16)
                 | ((long)buffer[3] << 24)
                 | ((long)buffer[4] << 32)
                 | ((long)buffer[5] << 40)
                 | ((long)buffer[6] << 48)
                 | ((long)buffer[7] << 56);
        }

        /// <summary>
        /// Write unsigned Int64 value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteULong(ulong value)
        {
            var data = new byte[8];
            data[0] = (byte)value;
            data[1] = (byte)(value >> 8);
            data[2] = (byte)(value >> 16);
            data[3] = (byte)(value >> 24);
            data[4] = (byte)(value >> 32);
            data[5] = (byte)(value >> 40);
            data[6] = (byte)(value >> 48);
            data[7] = (byte)(value >> 56);
            stream.Write(data, 0, 8);
        }

        /// <summary>
        /// Asynchronously write unsigned Int64 value
        /// </summary>
        /// <param name="value">Value</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task WriteULongAsync(ulong value, CancellationToken cancellationToken = default)
        {
            var data = new byte[8];
            data[0] = (byte)value;
            data[1] = (byte)(value >> 8);
            data[2] = (byte)(value >> 16);
            data[3] = (byte)(value >> 24);
            data[4] = (byte)(value >> 32);
            data[5] = (byte)(value >> 40);
            data[6] = (byte)(value >> 48);
            data[7] = (byte)(value >> 56);
            await stream.WriteAsync(data, 0, 8, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Read unsigned Int64 value
        /// </summary>
        /// <returns>Unsigned Int64 value</returns>
        /// <exception cref="IOException"></exception>
        public ulong ReadULong()
        {
            var buffer = new byte[8];
            StreamReadHelpers.ReadExact(stream, buffer, 0, 8);
            return (ulong)buffer[0]
                 | ((ulong)buffer[1] << 8)
                 | ((ulong)buffer[2] << 16)
                 | ((ulong)buffer[3] << 24)
                 | ((ulong)buffer[4] << 32)
                 | ((ulong)buffer[5] << 40)
                 | ((ulong)buffer[6] << 48)
                 | ((ulong)buffer[7] << 56);
        }

        /// <summary>
        /// Asynchronously read unsigned Int64 value
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Unsigned Int64 value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<ulong> ReadULongAsync(CancellationToken cancellationToken = default)
        {
            var buffer = new byte[8];
            await StreamReadHelpers.ReadExactAsync(stream, buffer, 0, 8, cancellationToken).ConfigureAwait(false);
            return (ulong)buffer[0]
                 | ((ulong)buffer[1] << 8)
                 | ((ulong)buffer[2] << 16)
                 | ((ulong)buffer[3] << 24)
                 | ((ulong)buffer[4] << 32)
                 | ((ulong)buffer[5] << 40)
                 | ((ulong)buffer[6] << 48)
                 | ((ulong)buffer[7] << 56);
        }
    }
}
