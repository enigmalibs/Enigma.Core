using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Extensions;

/// <summary>
/// Int32 stream extensions
/// </summary>
public static class StreamExtensionsInt32
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write Int32 value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteInt(int value)
        {
            var data = new byte[4];
            data[0] = (byte)value;
            data[1] = (byte)(value >> 8);
            data[2] = (byte)(value >> 16);
            data[3] = (byte)(value >> 24);
            stream.Write(data, 0, 4);
        }

        /// <summary>
        /// Asynchronously write Int32 value
        /// </summary>
        /// <param name="value">Value</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task WriteIntAsync(int value, CancellationToken cancellationToken = default)
        {
            var data = new byte[4];
            data[0] = (byte)value;
            data[1] = (byte)(value >> 8);
            data[2] = (byte)(value >> 16);
            data[3] = (byte)(value >> 24);
            await stream.WriteAsync(data, 0, 4, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Read Int32 value
        /// </summary>
        /// <returns>Int32 value</returns>
        /// <exception cref="IOException"></exception>
        public int ReadInt()
        {
            var buffer = new byte[4];
            StreamReadHelpers.ReadExact(stream, buffer, 0, 4);
            return buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24);
        }

        /// <summary>
        /// Asynchronously read Int32 value
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Int32 value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<int> ReadIntAsync(CancellationToken cancellationToken = default)
        {
            var buffer = new byte[4];
            await StreamReadHelpers.ReadExactAsync(stream, buffer, 0, 4, cancellationToken).ConfigureAwait(false);
            return buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24);
        }

        /// <summary>
        /// Write unsigned Int32 value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteUInt(uint value)
        {
            var data = new byte[4];
            data[0] = (byte)value;
            data[1] = (byte)(value >> 8);
            data[2] = (byte)(value >> 16);
            data[3] = (byte)(value >> 24);
            stream.Write(data, 0, 4);
        }

        /// <summary>
        /// Asynchronously write unsigned Int32 value
        /// </summary>
        /// <param name="value">Value</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task WriteUIntAsync(uint value, CancellationToken cancellationToken = default)
        {
            var data = new byte[4];
            data[0] = (byte)value;
            data[1] = (byte)(value >> 8);
            data[2] = (byte)(value >> 16);
            data[3] = (byte)(value >> 24);
            await stream.WriteAsync(data, 0, 4, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Read unsigned Int32 value
        /// </summary>
        /// <returns>Unsigned Int32 value</returns>
        /// <exception cref="IOException"></exception>
        public uint ReadUInt()
        {
            var buffer = new byte[4];
            StreamReadHelpers.ReadExact(stream, buffer, 0, 4);
            return (uint)(buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24));
        }

        /// <summary>
        /// Asynchronously read unsigned Int32 value
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Unsigned Int32 value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<uint> ReadUIntAsync(CancellationToken cancellationToken = default)
        {
            var buffer = new byte[4];
            await StreamReadHelpers.ReadExactAsync(stream, buffer, 0, 4, cancellationToken).ConfigureAwait(false);
            return (uint)(buffer[0] | (buffer[1] << 8) | (buffer[2] << 16) | (buffer[3] << 24));
        }
    }
}
