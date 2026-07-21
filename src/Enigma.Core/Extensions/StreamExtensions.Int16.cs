using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Extensions;

/// <summary>
/// Int16 stream extensions
/// </summary>
public static class StreamExtensionsInt16
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write Int16 value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteShort(short value)
        {
            var data = new byte[2];
            data[0] = (byte)value;
            data[1] = (byte)(value >> 8);
            stream.Write(data, 0, 2);
        }

        /// <summary>
        /// Asynchronously write Int16 value
        /// </summary>
        /// <param name="value">Value</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task WriteShortAsync(short value, CancellationToken cancellationToken = default)
        {
            var data = new byte[2];
            data[0] = (byte)value;
            data[1] = (byte)(value >> 8);
            await stream.WriteAsync(data, 0, 2, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Read Int16 value
        /// </summary>
        /// <returns>Int16 value</returns>
        /// <exception cref="IOException"></exception>
        public short ReadShort()
        {
            var buffer = new byte[2];
            StreamReadHelpers.ReadExact(stream, buffer, 0, 2);
            return (short)(buffer[0] | (buffer[1] << 8));
        }

        /// <summary>
        /// Asynchronously read Int16 value
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Int16 value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<short> ReadShortAsync(CancellationToken cancellationToken = default)
        {
            var buffer = new byte[2];
            await StreamReadHelpers.ReadExactAsync(stream, buffer, 0, 2, cancellationToken).ConfigureAwait(false);
            return (short)(buffer[0] | (buffer[1] << 8));
        }

        /// <summary>
        /// Write unsigned Int16 value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteUShort(ushort value)
        {
            var data = new byte[2];
            data[0] = (byte)value;
            data[1] = (byte)(value >> 8);
            stream.Write(data, 0, 2);
        }

        /// <summary>
        /// Asynchronously write unsigned Int16 value
        /// </summary>
        /// <param name="value">Value</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task WriteUShortAsync(ushort value, CancellationToken cancellationToken = default)
        {
            var data = new byte[2];
            data[0] = (byte)value;
            data[1] = (byte)(value >> 8);
            await stream.WriteAsync(data, 0, 2, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Read unsigned Int16 value
        /// </summary>
        /// <returns>Unsigned Int16 value</returns>
        /// <exception cref="IOException"></exception>
        public ushort ReadUShort()
        {
            var buffer = new byte[2];
            StreamReadHelpers.ReadExact(stream, buffer, 0, 2);
            return (ushort)(buffer[0] | (buffer[1] << 8));
        }

        /// <summary>
        /// Asynchronously read unsigned Int16 value
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Unsigned Int16 value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<ushort> ReadUShortAsync(CancellationToken cancellationToken = default)
        {
            var buffer = new byte[2];
            await StreamReadHelpers.ReadExactAsync(stream, buffer, 0, 2, cancellationToken).ConfigureAwait(false);
            return (ushort)(buffer[0] | (buffer[1] << 8));
        }
    }
}
