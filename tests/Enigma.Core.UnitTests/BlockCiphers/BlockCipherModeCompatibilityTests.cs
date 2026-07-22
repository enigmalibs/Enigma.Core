using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Enigma.Core.Symmetric.BlockCiphers;
using Xunit;

namespace Enigma.Core.UnitTests.BlockCiphers;

/// <summary>
/// Algorithm/mode compatibility matrix: GCM requires a 128-bit block cipher, so requesting it on a
/// 64-bit-block algorithm (DES, 3DES, Blowfish, CAST-128, IDEA) is rejected; a block-width-incompatible
/// CTR IV is likewise rejected; and an invalid GCM tag size is rejected.
/// </summary>
public class BlockCipherModeCompatibilityTests
{
    private static readonly IBlockCipherServiceFactory Factory = new BlockCipherServiceFactory();

    private static IBlockCipherService Create(string algorithm) => algorithm switch
    {
        "des" => Factory.CreateDesService(),
        "tripledes" => Factory.CreateTripleDesService(),
        "blowfish" => Factory.CreateBlowfishService(),
        "cast128" => Factory.CreateCast128Service(),
        "idea" => Factory.CreateIdeaService(),
        _ => Factory.CreateAesService(),
    };

    [Theory]
    [InlineData("des")]
    [InlineData("tripledes")]
    [InlineData("blowfish")]
    [InlineData("cast128")]
    [InlineData("idea")]
    public async Task Gcm_On64BitBlockAlgorithm_Throws(string algorithm)
    {
        var service = Create(algorithm);
        var key = new byte[24];
        var iv = new byte[12];
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.EncryptAsync(input, output, key, iv, BlockCipherMode.Gcm,
                cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Ctr_With16ByteIvOn64BitBlockAlgorithm_Throws()
    {
        var service = Factory.CreateDesService();
        var key = new byte[8];
        var iv = new byte[16]; // too long for a 64-bit block
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.EncryptAsync(input, output, key, iv, BlockCipherMode.Ctr, PaddingScheme.None,
                cancellationToken: TestContext.Current.CancellationToken));
    }

    [Theory]
    [InlineData(16)]  // below the 32-bit minimum
    [InlineData(100)] // not a multiple of 8
    [InlineData(256)] // above the 128-bit maximum
    public async Task Gcm_InvalidTagSize_Throws(int gcmMacSizeBits)
    {
        var service = Factory.CreateAesService();
        var key = new byte[16];
        var iv = new byte[12];
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();

        await Assert.ThrowsAsync<ArgumentException>(() =>
            service.EncryptAsync(input, output, key, iv, BlockCipherMode.Gcm,
                gcmMacSizeBits: gcmMacSizeBits, cancellationToken: TestContext.Current.CancellationToken));
    }
}
