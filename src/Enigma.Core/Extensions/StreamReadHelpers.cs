using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace Enigma.Core.Extensions;

/// <summary>
/// Internal helpers for reading exact byte counts from streams using a read loop.
/// </summary>
internal static class StreamReadHelpers
{
    /// <summary>
    /// Read exactly <paramref name="count"/> bytes starting at <paramref name="offset"/> into <paramref name="buffer"/>.
    /// </summary>
    internal static void ReadExact(Stream stream, byte[] buffer, int offset, int count)
    {
        var totalRead = 0;
        while (totalRead < count)
        {
            var bytesRead = stream.Read(buffer, offset + totalRead, count - totalRead);
            if (bytesRead == 0)
                throw new IOException("Incorrect number of bytes read");
            totalRead += bytesRead;
        }
    }

    /// <summary>
    /// Asynchronously read exactly <paramref name="count"/> bytes starting at <paramref name="offset"/> into <paramref name="buffer"/>.
    /// </summary>
    internal static async Task ReadExactAsync(Stream stream, byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
    {
        var totalRead = 0;
        while (totalRead < count)
        {
            var bytesRead = await stream.ReadAsync(buffer, offset + totalRead, count - totalRead, cancellationToken).ConfigureAwait(false);
            if (bytesRead == 0)
                throw new IOException("Incorrect number of bytes read");
            totalRead += bytesRead;
        }
    }
}
