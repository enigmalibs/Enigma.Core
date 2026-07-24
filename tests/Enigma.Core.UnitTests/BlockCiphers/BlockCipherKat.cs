using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.Core.UnitTests.Infrastructure;
using Xunit;

namespace Enigma.Core.UnitTests.BlockCiphers;

/// <summary>
/// Shared helpers for the block-cipher known-answer tests. The KAT vectors are block-aligned and expect
/// raw cipher output, so every KAT call uses <see cref="PaddingScheme.None"/> (a non-default padding
/// would append an extra block for ECB/CBC and break the vector).
/// </summary>
internal static class BlockCipherKat
{
    /// <summary>Loads a <c>key,iv,data,enc</c> vector file (CBC / CTR).</summary>
    public static IEnumerable<object[]> IvVectors(string csv)
        => CsvData.Rows("BlockCiphers", csv)
            .Select(v => new object[]
            {
                CsvData.Hex(v[0]), // key
                CsvData.Hex(v[1]), // iv
                CsvData.Hex(v[2]), // data
                CsvData.Hex(v[3]), // enc
            });

    /// <summary>Loads a <c>key,data,enc</c> vector file (ECB).</summary>
    public static IEnumerable<object[]> EcbVectors(string csv)
        => CsvData.Rows("BlockCiphers", csv)
            .Select(v => new object[]
            {
                CsvData.Hex(v[0]), // key
                CsvData.Hex(v[1]), // data
                CsvData.Hex(v[2]), // enc
            });

    public static async Task AssertEncrypt(
        IBlockCipherService service, byte[] key, byte[]? iv, BlockCipherMode mode,
        byte[] data, byte[] expected, CancellationToken ct)
    {
        using var input = new MemoryStream(data);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, key, iv, mode, PaddingScheme.None, cancellationToken: ct);
        Assert.Equal(expected, output.ToArray());
    }

    public static async Task AssertDecrypt(
        IBlockCipherService service, byte[] key, byte[]? iv, BlockCipherMode mode,
        byte[] data, byte[] enc, CancellationToken ct)
    {
        using var input = new MemoryStream(enc);
        using var output = new MemoryStream();
        await service.DecryptAsync(input, output, key, iv, mode, PaddingScheme.None, cancellationToken: ct);
        Assert.Equal(data, output.ToArray());
    }
}
