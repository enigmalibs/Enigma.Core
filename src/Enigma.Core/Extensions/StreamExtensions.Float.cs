using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Extensions;

/// <summary>
/// Float stream extensions
/// </summary>
public static class StreamExtensionsFloat
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write float value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteFloat(float value)
        {
            var data = BitConverter.GetBytes(value);
            if (!BitConverter.IsLittleEndian) Array.Reverse(data);
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Asynchronously write float value
        /// </summary>
        /// <param name="value">Value</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task WriteFloatAsync(float value, CancellationToken cancellationToken = default)
        {
            var data = BitConverter.GetBytes(value);
            if (!BitConverter.IsLittleEndian) Array.Reverse(data);
            await stream.WriteAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Read float value
        /// </summary>
        /// <returns>Float value</returns>
        /// <exception cref="IOException"></exception>
        public float ReadFloat()
        {
            var buffer = new byte[sizeof(float)];
            StreamReadHelpers.ReadExact(stream, buffer, 0, sizeof(float));
            if (!BitConverter.IsLittleEndian) Array.Reverse(buffer);
            return BitConverter.ToSingle(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read float value
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Float value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<float> ReadFloatAsync(CancellationToken cancellationToken = default)
        {
            var buffer = new byte[sizeof(float)];
            await StreamReadHelpers.ReadExactAsync(stream, buffer, 0, sizeof(float), cancellationToken).ConfigureAwait(false);
            if (!BitConverter.IsLittleEndian) Array.Reverse(buffer);
            return BitConverter.ToSingle(buffer, 0);
        }
    }
}
