using System;
using System.IO;
using System.Threading.Tasks;
using Enigma.Core.Symmetric.StreamCiphers;
using Xunit;

namespace Enigma.Core.UnitTests.StreamCiphers;

/// <summary>Null-argument guards for the stream-cipher service.</summary>
public class StreamCipherValidationTests
{
    private static IStreamCipherService Service() => new StreamCipherServiceFactory().CreateChaCha20Service();

    private static readonly byte[] Key = new byte[32];
    private static readonly byte[] Nonce = new byte[8];

    [Fact]
    public async Task Encrypt_NullInput_Throws()
    {
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            Service().EncryptAsync(null!, output, Key, Nonce, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Encrypt_NullOutput_Throws()
    {
        using var input = new MemoryStream(new byte[16]);
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            Service().EncryptAsync(input, null!, Key, Nonce, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Encrypt_NullKey_Throws()
    {
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            Service().EncryptAsync(input, output, null!, Nonce, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Encrypt_NullNonce_Throws()
    {
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            Service().EncryptAsync(input, output, Key, null!, cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task Decrypt_NullNonce_Throws()
    {
        using var input = new MemoryStream(new byte[16]);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<ArgumentNullException>(() =>
            Service().DecryptAsync(input, output, Key, null!, cancellationToken: TestContext.Current.CancellationToken));
    }
}
