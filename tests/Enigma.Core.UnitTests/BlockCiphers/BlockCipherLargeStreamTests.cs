using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.Core.Utils;
using Xunit;

namespace Enigma.Core.UnitTests.BlockCiphers;

/// <summary>
/// Encrypt/decrypt correctness for input larger than the 4096-byte streaming buffer, so the read loop
/// runs multiple iterations and the final block/tag flush across buffer boundaries is validated for data
/// integrity (the KAT vectors are all single-buffer, so they cannot prove this path).
/// </summary>
public class BlockCipherLargeStreamTests
{
    // Spans several 4096-byte buffers and is deliberately not a block multiple.
    private const int LargeSize = 4096 * 3 + 7;

    private static IBlockCipherService Service() => new BlockCipherServiceFactory().CreateAesService();

    [Theory]
    [InlineData(BlockCipherMode.Cbc)]
    [InlineData(BlockCipherMode.Ctr)]
    [InlineData(BlockCipherMode.Gcm)]
    public async Task Encrypt_Decrypt_MultiBuffer_RoundTrips(BlockCipherMode mode)
    {
        var service = Service();
        var key = new byte[32];
        var iv = mode == BlockCipherMode.Gcm ? new byte[12] : new byte[16];
        var plaintext = RandomUtils.GenerateRandomBytes(LargeSize);
        var ct = TestContext.Current.CancellationToken;

        var encrypted = await Run(service.EncryptAsync, key, iv, mode, plaintext, ct);
        Assert.True(encrypted.Length > 4096, "ciphertext should span more than one buffer");

        var decrypted = await Run(service.DecryptAsync, key, iv, mode, encrypted, ct);
        Assert.Equal(plaintext, decrypted);
    }

    private delegate Task CipherOp(
        Stream input, Stream output, byte[] key, byte[]? iv, BlockCipherMode mode,
        PaddingScheme padding, int gcmMacSizeBits, byte[]? associatedData,
        System.IProgress<int>? progress, CancellationToken cancellationToken);

    private static async Task<byte[]> Run(
        CipherOp op, byte[] key, byte[] iv, BlockCipherMode mode, byte[] data, CancellationToken ct)
    {
        using var input = new MemoryStream(data);
        using var output = new MemoryStream();
        await op(input, output, key, iv, mode, PaddingScheme.Pkcs7, GcmMacSize.MaxBits, null, null, ct);
        return output.ToArray();
    }
}
