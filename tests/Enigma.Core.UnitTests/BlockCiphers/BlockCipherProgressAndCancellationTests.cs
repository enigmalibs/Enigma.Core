using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.Core.UnitTests.Infrastructure;
using Enigma.Core.Utils;
using Xunit;

namespace Enigma.Core.UnitTests.BlockCiphers;

/// <summary>
/// Progress-reporting and cancellation behaviour for the streaming block-cipher path.
/// </summary>
public class BlockCipherProgressAndCancellationTests
{
    // Larger than the 4096-byte default buffer, so the read loop runs multiple iterations.
    private const int MultiBufferSize = 8192;

    private static IBlockCipherService Service() => new BlockCipherServiceFactory().CreateAesService();

    [Fact]
    public async Task Encrypt_ReportsProgressForMultiBufferStream()
    {
        var data = RandomUtils.GenerateRandomBytes(MultiBufferSize);
        using var input = new MemoryStream(data);
        using var output = new MemoryStream();

        var reported = new List<int>();
        var progress = new SyncProgress<int>(reported.Add);

        await Service().EncryptAsync(input, output, new byte[16], new byte[16], BlockCipherMode.Cbc,
            progress: progress, cancellationToken: TestContext.Current.CancellationToken);

        Assert.True(reported.Count >= 2, "expected more than one progress report for a multi-buffer stream");
        Assert.Equal(data.Length, reported.Sum());
    }

    [Fact]
    public async Task Encrypt_PreCancelledToken_Throws()
    {
        using var input = new MemoryStream(new byte[] { 1, 2, 3 });
        using var output = new MemoryStream();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.Cancel();

        await Assert.ThrowsAsync<System.OperationCanceledException>(() =>
            Service().EncryptAsync(input, output, new byte[16], new byte[16], BlockCipherMode.Cbc,
                PaddingScheme.None, cancellationToken: cts.Token));
    }

    [Fact]
    public async Task Decrypt_PreCancelledToken_Throws()
    {
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.Cancel();

        await Assert.ThrowsAsync<System.OperationCanceledException>(() =>
            Service().DecryptAsync(input, output, new byte[16], new byte[16], BlockCipherMode.Cbc,
                PaddingScheme.None, cancellationToken: cts.Token));
    }
}
