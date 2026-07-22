using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Enigma.Core.Symmetric.BlockCiphers;
using Xunit;

namespace Enigma.Core.UnitTests.BlockCiphers;

/// <summary>
/// Argument-validation guards: null key/stream, missing or wrong-length IV for the modes that require
/// one, and associated data supplied outside GCM.
/// </summary>
public class BlockCipherValidationTests
{
    private static IBlockCipherService Service() => new BlockCipherServiceFactory().CreateAesService();

    [Fact]
    public async Task Encrypt_NullInput_Throws()
    {
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            Service().EncryptAsync(null!, output, new byte[16], new byte[16], BlockCipherMode.Cbc,
                cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Encrypt_NullKey_Throws()
    {
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            Service().EncryptAsync(input, output, null!, new byte[16], BlockCipherMode.Cbc,
                cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(BlockCipherMode.Cbc)]
    [InlineData(BlockCipherMode.Ctr)]
    [InlineData(BlockCipherMode.Gcm)]
    public async Task Encrypt_NullIv_Throws(BlockCipherMode mode)
    {
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            Service().EncryptAsync(input, output, new byte[16], null, mode, PaddingScheme.None,
                cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Encrypt_ShortIvForCbc_Throws()
    {
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();
        // AES has a 16-byte block; an 8-byte IV is too short for CBC.
        await Assert.ThrowsAsync<ArgumentException>(() =>
            Service().EncryptAsync(input, output, new byte[16], new byte[8], BlockCipherMode.Cbc,
                cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Encrypt_AssociatedDataOutsideGcm_Throws()
    {
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            Service().EncryptAsync(input, output, new byte[16], new byte[16], BlockCipherMode.Cbc,
                associatedData: new byte[] { 1, 2, 3 }, cancellationToken: TestContext.Current.CancellationToken));
    }
}
