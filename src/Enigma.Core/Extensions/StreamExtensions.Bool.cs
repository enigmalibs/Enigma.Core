using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Extensions;

/// <summary>
/// Bool stream extensions
/// </summary>
public static class StreamExtensionsBool
{
    /// <summary>
    /// Stream extensions
    /// </summary>
    /// <param name="stream">Stream</param>
    extension(Stream stream)
    {
        /// <summary>
        /// Write bool value
        /// </summary>
        /// <param name="value">Value</param>
        public void WriteBool(bool value)
        {
            var data = BitConverter.GetBytes(value);
            if (!BitConverter.IsLittleEndian) Array.Reverse(data);
            stream.Write(data, 0, data.Length);
        }

        /// <summary>
        /// Asynchronously write bool value
        /// </summary>
        /// <param name="value">Value</param>
        /// <param name="cancellationToken">Cancellation token</param>
        public async Task WriteBoolAsync(bool value, CancellationToken cancellationToken = default)
        {
            var data = BitConverter.GetBytes(value);
            if (!BitConverter.IsLittleEndian) Array.Reverse(data);
            await stream.WriteAsync(data, 0, data.Length, cancellationToken).ConfigureAwait(false);
        }

        /// <summary>
        /// Read bool value
        /// </summary>
        /// <returns>Bool value</returns>
        /// <exception cref="IOException"></exception>
        public bool ReadBool()
        {
            var buffer = new byte[sizeof(bool)];
            StreamReadHelpers.ReadExact(stream, buffer, 0, sizeof(bool));
            if (!BitConverter.IsLittleEndian) Array.Reverse(buffer);
            return BitConverter.ToBoolean(buffer, 0);
        }

        /// <summary>
        /// Asynchronously read bool value
        /// </summary>
        /// <param name="cancellationToken">Cancellation token</param>
        /// <returns>Bool value</returns>
        /// <exception cref="IOException"></exception>
        public async Task<bool> ReadBoolAsync(CancellationToken cancellationToken = default)
        {
            var buffer = new byte[sizeof(bool)];
            await StreamReadHelpers.ReadExactAsync(stream, buffer, 0, sizeof(bool), cancellationToken).ConfigureAwait(false);
            if (!BitConverter.IsLittleEndian) Array.Reverse(buffer);
            return BitConverter.ToBoolean(buffer, 0);
        }
    }
}
