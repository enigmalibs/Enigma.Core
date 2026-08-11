using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Enigma.Core.UnitTests.Checksum;

/// <summary>
/// Known-answer and contract tests for the two CRC-32 variants: the published check value, the
/// empty-input and single-byte values, big-endian byte order, and agreement between the byte and
/// value shapes and between the sync and async paths.
/// </summary>
public class Crc32Tests
{
    [Theory]
    [InlineData(ChecksumVariants.Crc32IsoHdlc, 0xCBF43926u)]
    [InlineData(ChecksumVariants.Crc32C, 0xE3069283u)]
    public void ComputeChecksumValue_CheckInput_MatchesPublishedCheckValue(string variant, uint expected)
    {
        var service = ChecksumVariants.Create(variant);

        Assert.Equal(expected, service.ComputeChecksumValue(ChecksumVariants.CheckInput()));
    }

    // Init ^ XorOut is 0xFFFFFFFF ^ 0xFFFFFFFF for both variants, so zero bytes checksum to zero.
    // Asserted as a concrete value so a change to either parameter shows up here.
    [Theory]
    [InlineData(ChecksumVariants.Crc32IsoHdlc, 0x00000000u)]
    [InlineData(ChecksumVariants.Crc32C, 0x00000000u)]
    public void ComputeChecksumValue_EmptyInput_MatchesInitXorOut(string variant, uint expected)
    {
        var service = ChecksumVariants.Create(variant);

        Assert.Equal(expected, service.ComputeChecksumValue([]));
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc32IsoHdlc, 0xE8B7BE43u)]
    [InlineData(ChecksumVariants.Crc32C, 0xC1D04330u)]
    public void ComputeChecksumValue_SingleByte_MatchesReference(string variant, uint expected)
    {
        var service = ChecksumVariants.Create(variant);

        Assert.Equal(expected, service.ComputeChecksumValue([0x61]));
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc32IsoHdlc)]
    [InlineData(ChecksumVariants.Crc32C)]
    public void ChecksumSize_IsFourBytes(string variant)
    {
        var service = ChecksumVariants.Create(variant);

        Assert.Equal(4, service.ChecksumSize);
        Assert.Equal(4, service.ComputeChecksum(ChecksumVariants.CheckInput()).Length);
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc32IsoHdlc)]
    [InlineData(ChecksumVariants.Crc32C)]
    public void ComputeChecksum_IsBigEndianAndAgreesWithValue(string variant)
    {
        var service = ChecksumVariants.Create(variant);
        var data = ChecksumVariants.CheckInput();

        var value = service.ComputeChecksumValue(data);
        var bytes = service.ComputeChecksum(data);

        Assert.Equal([(byte)(value >> 24), (byte)(value >> 16), (byte)(value >> 8), (byte)value], bytes);
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc32IsoHdlc)]
    [InlineData(ChecksumVariants.Crc32C)]
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

    // The two CRC-32 variants share width, init and final XOR and differ only in the polynomial, so
    // a mixed-up parameter set would be invisible to the per-variant tests alone.
    [Fact]
    public void IsoHdlcAndCastagnoli_ProduceDifferentChecksums()
    {
        var data = ChecksumVariants.CheckInput();

        Assert.NotEqual(
            ChecksumVariants.Create(ChecksumVariants.Crc32IsoHdlc).ComputeChecksumValue(data),
            ChecksumVariants.Create(ChecksumVariants.Crc32C).ComputeChecksumValue(data));
    }
}
