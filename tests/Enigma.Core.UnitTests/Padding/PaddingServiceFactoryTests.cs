using Enigma.Core.Padding;
using Xunit;

namespace Enigma.Core.UnitTests.Padding;

public class PaddingServiceFactoryTests
{
    private readonly IPaddingServiceFactory _factory = new PaddingServiceFactory();

    [Fact]
    public void CreateNoPaddingService_ReturnsPassThroughService()
    {
        var service = _factory.CreateNoPaddingService();

        Assert.IsType<NoPaddingService>(service);

        // No-padding leaves the data untouched on both Pad and Unpad, regardless of block size.
        var data = new byte[] { 1, 2, 3, 4, 5 };
        Assert.Same(data, service.Pad(data, 16));
        Assert.Same(data, service.Unpad(data, 16));
    }

    [Theory]
    [InlineData(PaddingScheme.Pkcs7)]
    [InlineData(PaddingScheme.Iso7816)]
    [InlineData(PaddingScheme.Iso10126)]
    [InlineData(PaddingScheme.X923)]
    public void CreateSchemeService_RoundTrips(PaddingScheme scheme)
    {
        var service = Create(scheme);
        var data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01 };

        var padded = service.Pad(data, 16);
        var unpadded = service.Unpad(padded, 16);

        Assert.Equal(16, padded.Length);
        Assert.Equal(data, unpadded);
    }

    [Fact]
    public void Create_ReturnsFreshInstancePerCall()
    {
        Assert.NotSame(_factory.CreateNoPaddingService(), _factory.CreateNoPaddingService());
        Assert.NotSame(_factory.CreatePkcs7Service(), _factory.CreatePkcs7Service());
        Assert.NotSame(_factory.CreateIso7816Service(), _factory.CreateIso7816Service());
        Assert.NotSame(_factory.CreateIso10126Service(), _factory.CreateIso10126Service());
        Assert.NotSame(_factory.CreateX923Service(), _factory.CreateX923Service());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(256)]
    public void Pad_InvalidBlockSize_Throws(int blockSize)
    {
        var service = _factory.CreatePkcs7Service();

        Assert.Throws<System.ArgumentException>(() => service.Pad(new byte[] { 1 }, blockSize));
    }

    [Fact]
    public void Unpad_NonBlockAlignedLength_Throws()
    {
        var service = _factory.CreatePkcs7Service();

        // 17 bytes is not a whole number of 16-byte blocks.
        Assert.Throws<System.ArgumentException>(() => service.Unpad(new byte[17], 16));
    }

    private IPaddingService Create(PaddingScheme scheme) => scheme switch
    {
        PaddingScheme.Pkcs7 => _factory.CreatePkcs7Service(),
        PaddingScheme.Iso7816 => _factory.CreateIso7816Service(),
        PaddingScheme.Iso10126 => _factory.CreateIso10126Service(),
        PaddingScheme.X923 => _factory.CreateX923Service(),
        _ => _factory.CreateNoPaddingService(),
    };
}
