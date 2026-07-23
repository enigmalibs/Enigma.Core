using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Enigma.Core.Symmetric.BlockCiphers;
using Xunit;

namespace Enigma.Core.UnitTests.BlockCiphers;

/// <summary>
/// The service must not take ownership of caller-supplied streams: BouncyCastle's CipherStream disposes
/// the stream it wraps, so without the non-disposing wrapper the service would silently close the
/// caller's output (encrypt) or input (decrypt) stream. A closed <see cref="MemoryStream"/> reports
/// <c>CanWrite</c>/<c>CanRead</c> == false, which these tests use to detect the regression.
/// </summary>
public class BlockCipherStreamLifetimeTests
{
    private static IBlockCipherService Service() => new BlockCipherServiceFactory().CreateAesService();

    [Fact]
    public async Task Encrypt_LeavesOutputStreamOpen()
    {
        var service = Service();
        var ct = TestContext.Current.CancellationToken;
        var output = new MemoryStream();

        using (var input = new MemoryStream(new byte[16]))
        {
            await service.EncryptAsync(input, output, new byte[16], new byte[16], BlockCipherMode.Cbc,
                cancellationToken: ct);
        }

        Assert.True(output.CanWrite, "the caller's output stream must remain open after encryption");
        // And it is genuinely usable — a trailer can be appended.
        output.WriteByte(0x2A);
        output.Dispose();
    }

    [Fact]
    public async Task Decrypt_LeavesInputStreamOpen()
    {
        var service = Service();
        var ct = TestContext.Current.CancellationToken;
        var key = new byte[16];
        var iv = new byte[16];

        byte[] encrypted;
        using (var input = new MemoryStream(new byte[16]))
        using (var enc = new MemoryStream())
        {
            await service.EncryptAsync(input, enc, key, iv, BlockCipherMode.Cbc, cancellationToken: ct);
            encrypted = enc.ToArray();
        }

        var cipherInput = new MemoryStream(encrypted);
        using (var plain = new MemoryStream())
        {
            await service.DecryptAsync(cipherInput, plain, key, iv, BlockCipherMode.Cbc, cancellationToken: ct);
        }

        Assert.True(cipherInput.CanRead, "the caller's input stream must remain open after decryption");
        cipherInput.Dispose();
    }
}
