using System;
using System.Collections.Generic;
using Enigma.Core.Symmetric.BlockCiphers;
using Xunit;

namespace Enigma.Core.UnitTests.BlockCiphers;

public class BlockCipherServiceFactoryTests
{
    private readonly IBlockCipherServiceFactory _factory = new BlockCipherServiceFactory();

    public static IEnumerable<object[]> AllServices()
    {
        var f = new BlockCipherServiceFactory();
        yield return new object[] { "AES", (Func<IBlockCipherService>)(() => f.CreateAesService()) };
        yield return new object[] { "DES", (Func<IBlockCipherService>)(() => f.CreateDesService()) };
        yield return new object[] { "3DES", (Func<IBlockCipherService>)(() => f.CreateTripleDesService()) };
        yield return new object[] { "Blowfish", (Func<IBlockCipherService>)(() => f.CreateBlowfishService()) };
        yield return new object[] { "Twofish", (Func<IBlockCipherService>)(() => f.CreateTwofishService()) };
        yield return new object[] { "Serpent", (Func<IBlockCipherService>)(() => f.CreateSerpentService()) };
        yield return new object[] { "Camellia", (Func<IBlockCipherService>)(() => f.CreateCamelliaService()) };
        yield return new object[] { "CAST-128", (Func<IBlockCipherService>)(() => f.CreateCast128Service()) };
        yield return new object[] { "IDEA", (Func<IBlockCipherService>)(() => f.CreateIdeaService()) };
        yield return new object[] { "SEED", (Func<IBlockCipherService>)(() => f.CreateSeedService()) };
        yield return new object[] { "ARIA", (Func<IBlockCipherService>)(() => f.CreateAriaService()) };
        yield return new object[] { "SM4", (Func<IBlockCipherService>)(() => f.CreateSm4Service()) };
    }

    [Theory]
    [MemberData(nameof(AllServices))]
    public void Create_ReturnsBlockCipherService(string _, Func<IBlockCipherService> create)
    {
        var service = create();
        Assert.IsType<BlockCipherService>(service);
    }

    [Fact]
    public void Create_ReturnsFreshInstancePerCall()
    {
        Assert.NotSame(_factory.CreateAesService(), _factory.CreateAesService());
        Assert.NotSame(_factory.CreateSm4Service(), _factory.CreateSm4Service());
    }

    [Fact]
    public void Create_WithNonPositiveBufferSize_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _factory.CreateAesService(0));
        Assert.Throws<ArgumentOutOfRangeException>(() => _factory.CreateAesService(-1));
    }
}
