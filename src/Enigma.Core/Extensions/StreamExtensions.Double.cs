using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Extensions;

/// <summary>
/// Double stream extensions
/// </summary>
public static class StreamExtensionsDouble
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write double
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteDouble(double value)
        {
            var data = BitConverter.GetBytes(value);
            if (!BitConverter.IsLittleEndian) Array.Reverse(data);
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Asynchronously write double
        /// </summary>
        /// <param name="value">Value</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task WriteDoubleAsync(double value, CancellationToken cancellationToken = default)
        {
            var data = BitConverter.GetBytes(value);
            if (!BitConverter.IsLittleEndian) Array.Reverse(data);
            await stream.WriteAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Read double value
        /// </summary>
        /// <returns>Double value</returns>
        /// <exception cref="IOException"></exception>
        public double ReadDouble()
        {
            var buffer = new byte[sizeof(double)];
            StreamReadHelpers.ReadExact(stream, buffer, 0, sizeof(double));
            if (!BitConverter.IsLittleEndian) Array.Reverse(buffer);
            return BitConverter.ToDouble(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read double value
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Double value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<double> ReadDoubleAsync(CancellationToken cancellationToken = default)
        {
            var buffer = new byte[sizeof(double)];
            await StreamReadHelpers.ReadExactAsync(stream, buffer, 0, sizeof(double), cancellationToken).ConfigureAwait(false);
            if (!BitConverter.IsLittleEndian) Array.Reverse(buffer);
            return BitConverter.ToDouble(buffer, 0);
        }
    }
}
