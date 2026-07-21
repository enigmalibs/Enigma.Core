using Enigma.Core.Encoding;
using Xunit;

namespace Enigma.Core.UnitTests.Encoding;

public class EncodingServiceFactoryTests
{
    private readonly IEncodingServiceFactory _factory = new EncodingServiceFactory();

    [Fact]
    public void CreateBase64Service_ReturnsWorkingBase64Encoder()
    {
        var service = _factory.CreateBase64Service();
        Assert.IsType<Base64Service>(service);
        Assert.Equal("SGVsbG8sIFdvcmxkIQ==", service.Encode("Hello, World!"u8.ToArray()));
    }

    [Fact]
    public void CreateBase32Service_ReturnsWorkingBase32Encoder()
    {
        var service = _factory.CreateBase32Service();
        Assert.IsType<Base32Service>(service);
        var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        Assert.Equal(data, service.Decode(service.Encode(data)));
    }

    [Fact]
    public void CreateHexService_ReturnsWorkingHexEncoder()
    {
        var service = _factory.CreateHexService();
        Assert.IsType<HexService>(service);
        Assert.Equal("00ff10", service.Encode([0x00, 0xFF, 0x10]));
    }

    // Each Create* call yields a fresh per-scheme instance (no shared/cached singleton).
    [Fact]
    public void Create_ReturnsFreshInstancePerCall()
    {
        Assert.NotSame(_factory.CreateBase64Service(), _factory.CreateBase64Service());
        Assert.NotSame(_factory.CreateBase32Service(), _factory.CreateBase32Service());
        Assert.NotSame(_factory.CreateHexService(), _factory.CreateHexService());
    }
}
