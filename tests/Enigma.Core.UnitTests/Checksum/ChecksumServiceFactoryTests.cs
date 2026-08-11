using Enigma.Core.Checksum;
using Xunit;

namespace Enigma.Core.UnitTests.Checksum;

/// <summary>
/// Every factory method returns the expected concrete service type, a service that produces its
/// variant's published check value, and a fresh instance per call.
/// </summary>
public class ChecksumServiceFactoryTests
{
    private readonly IChecksumServiceFactory _factory = new ChecksumServiceFactory();

    [Fact]
    public void CreateCrc16ArcService_ReturnsWorkingCrc16Service()
    {
        var service = _factory.CreateCrc16ArcService();

        Assert.IsType<Crc16Service>(service);
        Assert.Equal(0xBB3Du, service.ComputeChecksumValue(ChecksumVariants.CheckInput()));
    }

    [Fact]
    public void CreateCrc16CcittFalseService_ReturnsWorkingCrc16Service()
    {
        var service = _factory.CreateCrc16CcittFalseService();

        Assert.IsType<Crc16Service>(service);
        Assert.Equal(0x29B1u, service.ComputeChecksumValue(ChecksumVariants.CheckInput()));
    }

    [Fact]
    public void CreateCrc16XmodemService_ReturnsWorkingCrc16Service()
    {
        var service = _factory.CreateCrc16XmodemService();

        Assert.IsType<Crc16Service>(service);
        Assert.Equal(0x31C3u, service.ComputeChecksumValue(ChecksumVariants.CheckInput()));
    }

    [Fact]
    public void CreateCrc16ModbusService_ReturnsWorkingCrc16Service()
    {
        var service = _factory.CreateCrc16ModbusService();

        Assert.IsType<Crc16Service>(service);
        Assert.Equal(0x4B37u, service.ComputeChecksumValue(ChecksumVariants.CheckInput()));
    }

    [Fact]
    public void CreateCrc16KermitService_ReturnsWorkingCrc16Service()
    {
        var service = _factory.CreateCrc16KermitService();

        Assert.IsType<Crc16Service>(service);
        Assert.Equal(0x2189u, service.ComputeChecksumValue(ChecksumVariants.CheckInput()));
    }

    [Fact]
    public void CreateCrc32IsoHdlcService_ReturnsWorkingCrc32Service()
    {
        var service = _factory.CreateCrc32IsoHdlcService();

        Assert.IsType<Crc32Service>(service);
        Assert.Equal(0xCBF43926u, service.ComputeChecksumValue(ChecksumVariants.CheckInput()));
    }

    [Fact]
    public void CreateCrc32CService_ReturnsWorkingCrc32Service()
    {
        var service = _factory.CreateCrc32CService();

        Assert.IsType<Crc32Service>(service);
        Assert.Equal(0xE3069283u, service.ComputeChecksumValue(ChecksumVariants.CheckInput()));
    }

    // Each Create* call yields a fresh per-variant instance (no shared/cached singleton).
    [Fact]
    public void Create_ReturnsFreshInstancePerCall()
    {
        Assert.NotSame(_factory.CreateCrc16ArcService(), _factory.CreateCrc16ArcService());
        Assert.NotSame(_factory.CreateCrc16CcittFalseService(), _factory.CreateCrc16CcittFalseService());
        Assert.NotSame(_factory.CreateCrc16XmodemService(), _factory.CreateCrc16XmodemService());
        Assert.NotSame(_factory.CreateCrc16ModbusService(), _factory.CreateCrc16ModbusService());
        Assert.NotSame(_factory.CreateCrc16KermitService(), _factory.CreateCrc16KermitService());
        Assert.NotSame(_factory.CreateCrc32IsoHdlcService(), _factory.CreateCrc32IsoHdlcService());
        Assert.NotSame(_factory.CreateCrc32CService(), _factory.CreateCrc32CService());
    }
}
