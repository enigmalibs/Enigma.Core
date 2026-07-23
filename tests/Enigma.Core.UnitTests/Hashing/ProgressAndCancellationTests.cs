using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Hashing.Hash;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.UnitTests.Infrastructure;
using Enigma.Core.Utils;
using Xunit;

namespace Enigma.Core.UnitTests.Hashing;

/// <summary>
/// Progress-reporting and cancellation behavior for the streaming hash and HMAC paths. Services are
/// obtained through the factories — the old public <c>Func&lt;IDigest&gt;</c> constructor is gone.
/// </summary>
public class ProgressAndCancellationTests
{
    // Larger than the 4096-byte default buffer, so the read loop runs multiple iterations.
    private const int MultiBufferSize = 8192;

    [Fact]
    public async Task Hash_ReportsProgressForMultiBufferStream()
    {
        var service = new HashServiceFactory().CreateSha256Service();
        var data = RandomUtils.GenerateRandomBytes(MultiBufferSize);
        using var input = new MemoryStream(data);

        var reported = new List<int>();
        var progress = new SyncProgress<int>(reported.Add);

        await service.ComputeHashAsync(input, progress, TestContext.Current.CancellationToken);

        Assert.True(reported.Count >= 2, "expected more than one progress report for a multi-buffer stream");
        Assert.Equal(data.Length, reported.Sum());
    }

    [Fact]
    public async Task Hmac_ReportsProgressForMultiBufferStream()
    {
        var service = new HmacServiceFactory().CreateHmacSha256Service();
        var key = RandomUtils.GenerateRandomBytes(32);
        var data = RandomUtils.GenerateRandomBytes(MultiBufferSize);
        using var input = new MemoryStream(data);

        var reported = new List<int>();
        var progress = new SyncProgress<int>(reported.Add);

        await service.ComputeHmacAsync(input, key, progress, TestContext.Current.CancellationToken);

        Assert.True(reported.Count >= 2, "expected more than one progress report for a multi-buffer stream");
        Assert.Equal(data.Length, reported.Sum());
    }

    [Fact]
    public async Task Hash_PreCancelledToken_Throws()
    {
        var service = new HashServiceFactory().CreateSha256Service();
        using var input = new MemoryStream(new byte[] { 1, 2, 3 });

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.Cancel();

        await Assert.ThrowsAsync<System.OperationCanceledException>(
            () => service.ComputeHashAsync(input, cancellationToken: cts.Token));
    }

    [Fact]
    public async Task Hmac_PreCancelledToken_Throws()
    {
        var service = new HmacServiceFactory().CreateHmacSha256Service();
        var key = RandomUtils.GenerateRandomBytes(32);
        using var input = new MemoryStream(new byte[] { 1, 2, 3 });

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.Cancel();

        await Assert.ThrowsAsync<System.OperationCanceledException>(
            () => service.ComputeHmacAsync(input, key, cancellationToken: cts.Token));
    }
}
