using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.UnitTests.Infrastructure;
using Enigma.Core.Utils;
using Xunit;

namespace Enigma.Core.UnitTests.Checksum;

/// <summary>
/// Progress-reporting and cancellation behaviour for the streaming checksum paths, shaped after the
/// equivalent hashing tests.
/// </summary>
public class ChecksumProgressAndCancellationTests
{
    // Larger than the 4096-byte default buffer, so the read loop runs multiple iterations.
    private const int MultiBufferSize = 8192;

    [Theory]
    [InlineData(ChecksumVariants.Crc16Modbus)]
    [InlineData(ChecksumVariants.Crc32IsoHdlc)]
    public async Task ComputeChecksumValueAsync_ReportsProgressForMultiBufferStream(string variant)
    {
        var service = ChecksumVariants.Create(variant);
        var data = RandomUtils.GenerateRandomBytes(MultiBufferSize);
        using var input = new MemoryStream(data);

        var reported = new List<int>();
        var progress = new SyncProgress<int>(reported.Add);

        await service.ComputeChecksumValueAsync(input, progress, TestContext.Current.CancellationToken);

        Assert.True(reported.Count >= 2, "expected more than one progress report for a multi-buffer stream");
        Assert.Equal(data.Length, reported.Sum());
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc16Modbus)]
    [InlineData(ChecksumVariants.Crc32IsoHdlc)]
    public async Task ComputeChecksumAsync_ReportsProgressForMultiBufferStream(string variant)
    {
        var service = ChecksumVariants.Create(variant);
        var data = RandomUtils.GenerateRandomBytes(MultiBufferSize);
        using var input = new MemoryStream(data);

        var reported = new List<int>();
        var progress = new SyncProgress<int>(reported.Add);

        await service.ComputeChecksumAsync(input, progress, TestContext.Current.CancellationToken);

        Assert.True(reported.Count >= 2, "expected more than one progress report for a multi-buffer stream");
        Assert.Equal(data.Length, reported.Sum());
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc16Modbus)]
    [InlineData(ChecksumVariants.Crc32IsoHdlc)]
    public async Task ComputeChecksumValueAsync_PreCancelledToken_Throws(string variant)
    {
        var service = ChecksumVariants.Create(variant);
        using var input = new MemoryStream([1, 2, 3]);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => service.ComputeChecksumValueAsync(input, cancellationToken: cts.Token));
    }

    [Theory]
    [InlineData(ChecksumVariants.Crc16Modbus)]
    [InlineData(ChecksumVariants.Crc32IsoHdlc)]
    public async Task ComputeChecksumAsync_PreCancelledToken_Throws(string variant)
    {
        var service = ChecksumVariants.Create(variant);
        using var input = new MemoryStream([1, 2, 3]);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => service.ComputeChecksumAsync(input, cancellationToken: cts.Token));
    }
}
