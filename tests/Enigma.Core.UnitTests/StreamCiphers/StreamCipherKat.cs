using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Symmetric.StreamCiphers;
using Enigma.Core.UnitTests.Infrastructure;
using Xunit;

namespace Enigma.Core.UnitTests.StreamCiphers;

/// <summary>Shared helpers for the stream-cipher known-answer tests (<c>key,iv,data,enc</c> vectors).</summary>
internal static class StreamCipherKat
{
    public static IEnumerable<object[]> Vectors(string csv)
        => CsvData.Rows("StreamCiphers", csv)
            .Select(v => new object[]
            {
                CsvData.Hex(v[0]), // key
                CsvData.Hex(v[1]), // nonce
                CsvData.Hex(v[2]), // data
                CsvData.Hex(v[3]), // enc
            });

    public static async Task AssertEncrypt(
        IStreamCipherService service, byte[] key, byte[] nonce, byte[] data, byte[] expected, CancellationToken ct)
    {
        using var input = new MemoryStream(data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, key, nonce, cancellationToken: ct);
        Assert.Equal(expected, output.ToArray());
    }

    public static async Task AssertDecrypt(
        IStreamCipherService service, byte[] key, byte[] nonce, byte[] data, byte[] enc, CancellationToken ct)
    {
        using var input = new MemoryStream(enc);
        using var output = new MemoryStream();
        await service.DecryptAsync(input, output, key, nonce, cancellationToken: ct);
        Assert.Equal(data, output.ToArray());
    }
}
