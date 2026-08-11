using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Enigma.Core.UnitTests.Checksum;

/// <summary>
/// Known-answer and contract tests for the five CRC-16 variants: the published check value, the
/// empty-input and single-byte values, big-endian byte order, and agreement between the byte and
/// value shapes and between the sync and async paths.
/// </summary>
public class Crc16Tests
{
    [Theory]
    [InlineData(ChecksumVariants.Crc16Arc, 0xBB3Du)]
    [InlineData(ChecksumVariants.Crc16CcittFalse, 0x29B1u)]
    [InlineData(ChecksumVariants.Crc16Xmodem, 0x31C3u)]
    [InlineData(ChecksumVariants.Crc16Modbus, 0x4B37u)]
    [InlineData(ChecksumVariants.Crc16Kermit, 0x2189u)]
    public void ComputeChecksumValue_CheckInput_MatchesPublishedCheckValue(string variant, uint expected)
    {
        var service = ChecksumVariants.Create(variant);

        Assert.Equal(expected, service.ComputeChecksumValue(ChecksumVariants.CheckInput()));
    }

    // The CRC of zero bytes is Init ^ XorOut, masked to the width. The concrete value is asserted
    // rather than the formula, so a change to either parameter shows up here.
    [Theory]
    [InlineData(ChecksumVariants.Crc16Arc, 0x0000u)]
    [InlineData(ChecksumVariants.Crc16CcittFalse, 0xFFFFu)]
    [InlineData(ChecksumVariants.Crc16Xmodem, 0x0000u)]
    [InlineData(ChecksumVariants.Crc16Modbus, 0xFFFFu)]
    [InlineData(ChecksumVariants.Crc16Kermit, 0x0000u)]
    public void ComputeChecksumValue_EmptyInput_MatchesInitXorOut(string variant, uint expected)
    {
        var service = ChecksumVariants.Create(variant);

        Assert.Equal(expected, service.ComputeChecksumValue([]));
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc16Arc, 0xE8C1u)]
    [InlineData(ChecksumVariants.Crc16CcittFalse, 0x9D77u)]
    [InlineData(ChecksumVariants.Crc16Xmodem, 0x7C87u)]
    [InlineData(ChecksumVariants.Crc16Modbus, 0xA87Eu)]
    [InlineData(ChecksumVariants.Crc16Kermit, 0x728Fu)]
    public void ComputeChecksumValue_SingleByte_MatchesReference(string variant, uint expected)
    {
        var service = ChecksumVariants.Create(variant);

        Assert.Equal(expected, service.ComputeChecksumValue([0x61]));
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc16Arc)]
    [InlineData(ChecksumVariants.Crc16CcittFalse)]
    [InlineData(ChecksumVariants.Crc16Xmodem)]
    [InlineData(ChecksumVariants.Crc16Modbus)]
    [InlineData(ChecksumVariants.Crc16Kermit)]
    public void ChecksumSize_IsTwoBytes(string variant)
    {
        var service = ChecksumVariants.Create(variant);

        Assert.Equal(2, service.ChecksumSize);
        Assert.Equal(2, service.ComputeChecksum(ChecksumVariants.CheckInput()).Length);
    }

    // The value shape must fit a 16-bit register: nothing may leak into the high half.
    [Theory]
    [InlineData(ChecksumVariants.Crc16Arc)]
    [InlineData(ChecksumVariants.Crc16CcittFalse)]
    [InlineData(ChecksumVariants.Crc16Xmodem)]
    [InlineData(ChecksumVariants.Crc16Modbus)]
    [InlineData(ChecksumVariants.Crc16Kermit)]
    public void ComputeChecksumValue_HighSixteenBitsAreZero(string variant)
    {
        var service = ChecksumVariants.Create(variant);

        Assert.Equal(0u, service.ComputeChecksumValue(ChecksumVariants.CheckInput()) >> 16);
        Assert.Equal(0u, service.ComputeChecksumValue([]) >> 16);
        Assert.Equal(0u, service.ComputeChecksumValue([0x61]) >> 16);
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc16Arc)]
    [InlineData(ChecksumVariants.Crc16CcittFalse)]
    [InlineData(ChecksumVariants.Crc16Xmodem)]
    [InlineData(ChecksumVariants.Crc16Modbus)]
    [InlineData(ChecksumVariants.Crc16Kermit)]
    public void ComputeChecksum_IsBigEndianAndAgreesWithValue(string variant)
    {
        var service = ChecksumVariants.Create(variant);
        var data = ChecksumVariants.CheckInput();

        var value = service.ComputeChecksumValue(data);
        var bytes = service.ComputeChecksum(data);

        Assert.Equal([(byte)(value >> 8), (byte)value], bytes);
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc16Arc)]
    [InlineData(ChecksumVariants.Crc16CcittFalse)]
    [InlineData(ChecksumVariants.Crc16Xmodem)]
    [InlineData(ChecksumVariants.Crc16Modbus)]
    [InlineData(ChecksumVariants.Crc16Kermit)]
    public async Task Async_AgreesWithSync(string variant)
    {
        var service = ChecksumVariants.Create(variant);
        var data = ChecksumVariants.CheckInput();

        using var valueStream = new MemoryStream(data);
        using var byteStream = new MemoryStream(data);

        var asyncValue = await service.ComputeChecksumValueAsync(
            valueStream, cancellationToken: TestContext.Current.CancellationToken);
        var asyncBytes = await service.ComputeChecksumAsync(
            byteStream, cancellationToken: TestContext.Current.CancellationToken);

        Assert.Equal(service.ComputeChecksumValue(data), asyncValue);
        Assert.Equal(service.ComputeChecksum(data), asyncBytes);
    }
}
