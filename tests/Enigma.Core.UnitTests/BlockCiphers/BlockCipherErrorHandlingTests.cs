using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Enigma.Core.Symmetric.BlockCiphers;
using Xunit;

namespace Enigma.Core.UnitTests.BlockCiphers;

/// <summary>
/// No BouncyCastle exception may cross the public boundary: every cipher failure — GCM tag mismatch,
/// corrupt CBC/ECB padding, and non-block-aligned data for the no-padding path (on both encrypt and
/// decrypt) — must surface as <see cref="CryptographicException"/>, never a raw
/// <c>Org.BouncyCastle.Crypto.*</c> type such as <c>DataLengthException</c>.
/// </summary>
public class BlockCipherErrorHandlingTests
{
    private static IBlockCipherService Service() => new BlockCipherServiceFactory().CreateAesService();

    [Theory]
    [InlineData(BlockCipherMode.Cbc)]
    [InlineData(BlockCipherMode.Ecb)]
    public async Task Decrypt_CorruptPadding_ThrowsCryptographicException(BlockCipherMode mode)
    {
        var service = Service();
        var key = new byte[16];
        var iv = mode == BlockCipherMode.Ecb ? null : new byte[16];
        var ct = TestContext.Current.CancellationToken;

        // Encrypt block-aligned data with PKCS#7 (yields a padded, block-aligned ciphertext).
        byte[] encrypted;
        using (var input = new MemoryStream(new byte[16]))
        using (var output = new MemoryStream())
        {
            await service.EncryptAsync(input, output, key, iv, mode, PaddingScheme.Pkcs7, cancellationToken: ct);
            encrypted = output.ToArray();
        }

        // Corrupt the final block so the padding check fails on decrypt.
        encrypted[^1] ^= 0xFF;

        using var badInput = new MemoryStream(encrypted);
        using var discard = new MemoryStream();
        await Assert.ThrowsAsync<CryptographicException>(() =>
            service.DecryptAsync(badInput, discard, key, iv, mode, PaddingScheme.Pkcs7, cancellationToken: ct));
    }

    [Theory]
    [InlineData(PaddingScheme.None)]
    [InlineData(PaddingScheme.Pkcs7)]
    public async Task Decrypt_NonBlockAlignedCiphertext_ThrowsCryptographicException(PaddingScheme padding)
    {
        var service = Service();
        // 20 bytes is not a whole number of 16-byte blocks.
        using var input = new MemoryStream(new byte[20]);
        using var output = new MemoryStream();

        await Assert.ThrowsAsync<CryptographicException>(() =>
            service.DecryptAsync(input, output, new byte[16], new byte[16], BlockCipherMode.Cbc, padding,
                cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(BlockCipherMode.Cbc)]
    [InlineData(BlockCipherMode.Ecb)]
    public async Task Encrypt_NonBlockAlignedWithNoPadding_ThrowsCryptographicException(BlockCipherMode mode)
    {
        var service = Service();
        var iv = mode == BlockCipherMode.Ecb ? null : new byte[16];
        using var input = new MemoryStream(new byte[20]); // not block-aligned, no padding to fix it
        using var output = new MemoryStream();

        await Assert.ThrowsAsync<CryptographicException>(() =>
            service.EncryptAsync(input, output, new byte[16], iv, mode, PaddingScheme.None,
                cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Encrypt_EmptyGcmNonce_ThrowsArgumentException()
    {
        var service = Service();
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();

        await Assert.ThrowsAsync<System.ArgumentException>(() =>
            service.EncryptAsync(input, output, new byte[16], System.Array.Empty<byte>(), BlockCipherMode.Gcm,
                cancellationToken: TestContext.Current.CancellationToken));
    }
}
