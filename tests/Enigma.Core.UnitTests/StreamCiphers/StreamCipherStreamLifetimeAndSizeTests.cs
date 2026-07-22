using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Symmetric.StreamCiphers;
using Enigma.Core.UnitTests.Infrastructure;
using Enigma.Core.Utils;
using Xunit;

namespace Enigma.Core.UnitTests.StreamCiphers;

/// <summary>
/// Stream-ownership, multi-buffer round-trip, and progress/cancellation behaviour for the stream-cipher
/// path — mirroring the guarantees verified for the block-cipher path.
/// </summary>
public class StreamCipherStreamLifetimeAndSizeTests
{
    private const int MultiBufferSize = 8192;                 // > the 4096-byte default buffer
    private const int LargeSize = 4096 * 3 + 7;               // spans several buffers, not aligned

    private static readonly byte[] Key = new byte[32];
    private static readonly byte[] Nonce = new byte[8];

    private static IStreamCipherService Service() => new StreamCipherServiceFactory().CreateChaCha20Service();

    [Fact]
    public async Task Encrypt_LeavesOutputStreamOpen()
    {
        var output = new MemoryStream();
        using (var input = new MemoryStream(new byte[16]))
        {
            await Service().EncryptAsync(input, output, Key, Nonce, cancellationToken: TestContext.Current.CancellationToken);
        }

        Assert.True(output.CanWrite, "the caller's output stream must remain open after encryption");
        output.Dispose();
    }

    [Fact]
    public async Task Decrypt_LeavesInputStreamOpen()
    {
        var ct = TestContext.Current.CancellationToken;
        var input = new MemoryStream(new byte[16]);
        using (var output = new MemoryStream())
        {
            await Service().DecryptAsync(input, output, Key, Nonce, cancellationToken: ct);
        }

        Assert.True(input.CanRead, "the caller's input stream must remain open after decryption");
        input.Dispose();
    }

    [Fact]
    public async Task Encrypt_Decrypt_MultiBuffer_RoundTrips()
    {
        var service = Service();
        var ct = TestContext.Current.CancellationToken;
        var plaintext = RandomUtils.GenerateRandomBytes(LargeSize);

        byte[] encrypted;
        using (var input = new MemoryStream(plaintext))
        using (var output = new MemoryStream())
        {
            await service.EncryptAsync(input, output, Key, Nonce, cancellationToken: ct);
            encrypted = output.ToArray();
        }

        // A stream cipher's ciphertext is the same length as the plaintext.
        Assert.Equal(plaintext.Length, encrypted.Length);

        using var encInput = new MemoryStream(encrypted);
        using var decrypted = new MemoryStream();
        await service.DecryptAsync(encInput, decrypted, Key, Nonce, cancellationToken: ct);

        Assert.Equal(plaintext, decrypted.ToArray());
    }

    [Fact]
    public async Task Encrypt_ReportsProgressForMultiBufferStream()
    {
        var data = RandomUtils.GenerateRandomBytes(MultiBufferSize);
        using var input = new MemoryStream(data);
        using var output = new MemoryStream();

        var reported = new List<int>();
        var progress = new SyncProgress<int>(reported.Add);

        await Service().EncryptAsync(input, output, Key, Nonce, progress, TestContext.Current.CancellationToken);

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
            Service().EncryptAsync(input, output, Key, Nonce, cancellationToken: cts.Token));
    }

    [Fact]
    public async Task Decrypt_PreCancelledToken_Throws()
    {
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
        cts.Cancel();

        await Assert.ThrowsAsync<System.OperationCanceledException>(() =>
            Service().DecryptAsync(input, output, Key, Nonce, cancellationToken: cts.Token));
    }
}
