using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Enigma.Core.Symmetric.BlockCiphers;
using Xunit;

namespace Enigma.Core.UnitTests.BlockCiphers;

/// <summary>
/// Padding behaviour on the block-cipher path: PKCS#7 lets ECB/CBC round-trip non-block-aligned data,
/// and padding has no effect on CTR/GCM (a non-default scheme produces byte-identical output).
/// </summary>
public class BlockCipherPaddingBehaviorTests
{
    private static IBlockCipherService Service() => new BlockCipherServiceFactory().CreateAesService();

    // 20 bytes: not a multiple of the 16-byte AES block, so padding is required.
    private static readonly byte[] NonAligned = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

    [Theory]
    [InlineData(BlockCipherMode.Ecb)]
    [InlineData(BlockCipherMode.Cbc)]
    public async Task Pkcs7_NonBlockAligned_RoundTrips(BlockCipherMode mode)
    {
        var service = Service();
        var key = new byte[16];
        var iv = mode == BlockCipherMode.Ecb ? null : new byte[16];
        var ct = TestContext.Current.CancellationToken;

        byte[] encrypted;
        using (var input = new MemoryStream(NonAligned))
        using (var output = new MemoryStream())
        {
            await service.EncryptAsync(input, output, key, iv, mode, PaddingScheme.Pkcs7, cancellationToken: ct);
            encrypted = output.ToArray();
        }

        // PKCS#7 rounds the 20-byte input up to the next block boundary (32 bytes).
        Assert.Equal(32, encrypted.Length);

        using var encInput = new MemoryStream(encrypted);
        using var decrypted = new MemoryStream();
        await service.DecryptAsync(encInput, decrypted, key, iv, mode, PaddingScheme.Pkcs7, cancellationToken: ct);

        Assert.Equal(NonAligned, decrypted.ToArray());
    }

    [Theory]
    [InlineData(BlockCipherMode.Ctr)]
    [InlineData(BlockCipherMode.Gcm)]
    public async Task PaddingIgnored_ForStreamModes(BlockCipherMode mode)
    {
        var service = Service();
        var key = new byte[16];
        var iv = new byte[12];
        var ct = TestContext.Current.CancellationToken;

        var withNone = await Encrypt(service, key, iv, mode, PaddingScheme.None, ct);
        var withPkcs7 = await Encrypt(service, key, iv, mode, PaddingScheme.Pkcs7, ct);

        // CTR/GCM never pad, so the requested scheme has no effect on the output.
        Assert.Equal(withNone, withPkcs7);
    }

    private static async Task<byte[]> Encrypt(
        IBlockCipherService service, byte[] key, byte[] iv, BlockCipherMode mode,
        PaddingScheme padding, CancellationToken ct)
    {
        using var input = new MemoryStream(NonAligned);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, key, iv, mode, padding, cancellationToken: ct);
        return output.ToArray();
    }
}
