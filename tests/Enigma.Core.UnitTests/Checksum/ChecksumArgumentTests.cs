using System;
using System.Threading.Tasks;
using Enigma.Core.Checksum;
using Xunit;

namespace Enigma.Core.UnitTests.Checksum;

/// <summary>
/// The checksum module's exception contract: null guards on all four compute members, and the
/// non-positive buffer-size guard on every factory method.
/// </summary>
public class ChecksumArgumentTests
{
    [Theory]
    [InlineData(ChecksumVariants.Crc16Arc)]
    [InlineData(ChecksumVariants.Crc16CcittFalse)]
    [InlineData(ChecksumVariants.Crc16Xmodem)]
    [InlineData(ChecksumVariants.Crc16Modbus)]
    [InlineData(ChecksumVariants.Crc16Kermit)]
    [InlineData(ChecksumVariants.Crc32IsoHdlc)]
    [InlineData(ChecksumVariants.Crc32C)]
    public void ComputeChecksum_NullData_Throws(string variant)
    {
        var service = ChecksumVariants.Create(variant);

        var ex = Assert.Throws<ArgumentNullException>(() => service.ComputeChecksum(null!));
        Assert.Equal("data", ex.ParamName);
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc16Arc)]
    [InlineData(ChecksumVariants.Crc32IsoHdlc)]
    public void ComputeChecksumValue_NullData_Throws(string variant)
    {
        var service = ChecksumVariants.Create(variant);

        var ex = Assert.Throws<ArgumentNullException>(() => service.ComputeChecksumValue(null!));
        Assert.Equal("data", ex.ParamName);
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc16Arc)]
    [InlineData(ChecksumVariants.Crc32IsoHdlc)]
    public async Task ComputeChecksumAsync_NullInput_Throws(string variant)
    {
        var service = ChecksumVariants.Create(variant);

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(
            () => service.ComputeChecksumAsync(null!, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal("input", ex.ParamName);
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc16Arc)]
    [InlineData(ChecksumVariants.Crc32IsoHdlc)]
    public async Task ComputeChecksumValueAsync_NullInput_Throws(string variant)
    {
        var service = ChecksumVariants.Create(variant);

        var ex = await Assert.ThrowsAsync<ArgumentNullException>(
            () => service.ComputeChecksumValueAsync(null!, cancellationToken: TestContext.Current.CancellationToken));
        Assert.Equal("input", ex.ParamName);
    }

    // A non-positive buffer size must fail loudly at creation. Otherwise the streaming read loop
    // terminates before consuming the stream and the service silently returns the checksum of the
    // empty message — a wrong result with no exception to notice.
    [Theory]
    [MemberData(nameof(FactoryMethodsAndNonPositiveBufferSizes))]
    public void CreateService_NonPositiveBufferSize_Throws(string variant, int bufferSize)
    {
        var ex = Assert.Throws<ArgumentOutOfRangeException>(() => ChecksumVariants.Create(variant, bufferSize));
        Assert.Equal("bufferSize", ex.ParamName);
    }

    public static TheoryData<string, int> FactoryMethodsAndNonPositiveBufferSizes()
    {
        var data = new TheoryData<string, int>();
        foreach (var variant in ChecksumVariants.All)
        {
            data.Add(variant, 0);
            data.Add(variant, -1);
        }
        return data;
    }

    // The guard belongs to creation, not to first use: nothing is read from a stream before it fires.
    [Fact]
    public void CreateService_ZeroBufferSize_ThrowsBeforeAnyComputation()
    {
        var factory = new ChecksumServiceFactory();

        Assert.Throws<ArgumentOutOfRangeException>(() => factory.CreateCrc32IsoHdlcService(0));
    }
}
