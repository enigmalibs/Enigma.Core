using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Enigma.Core.Padding;
using Enigma.Core.Symmetric.BlockCiphers;
using Enigma.Core.UnitTests.Infrastructure;
using Xunit;

namespace Enigma.Core.UnitTests.BlockCiphers;

/// <summary>
/// AES-GCM known-answer tests (ciphertext + 128-bit tag), plus authentication behaviour: tamper
/// detection, and the restored associated-data (AAD) round-trip and mismatch cases. GCM authentication
/// failures must surface as <see cref="CryptographicException"/>, never the BouncyCastle exception type.
/// </summary>
public class AesGcmTests
{
    private static IBlockCipherService Service() => new BlockCipherServiceFactory().CreateAesService();

    [Theory]
    [MemberData(nameof(GcmVectors))]
    public async Task Encrypt_KnownVector_MatchesExpected(byte[] key, byte[] iv, byte[] data, byte[] enc)
    {
        using var input = new MemoryStream(data);
        using var output = new MemoryStream();
        await Service().EncryptAsync(input, output, key, iv, BlockCipherMode.Gcm,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(enc, output.ToArray());
    }

    [Theory]
    [MemberData(nameof(GcmVectors))]
    public async Task Decrypt_KnownVector_MatchesExpected(byte[] key, byte[] iv, byte[] data, byte[] enc)
    {
        using var input = new MemoryStream(enc);
        using var output = new MemoryStream();
        await Service().DecryptAsync(input, output, key, iv, BlockCipherMode.Gcm,
            cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal(data, output.ToArray());
    }

    [Fact]
    public async Task Decrypt_TamperedCiphertext_ThrowsCryptographicException()
    {
        var service = Service();
        var key = new byte[16];
        var iv = new byte[12];
        var plaintext = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        var ct = TestContext.Current.CancellationToken;

        var encrypted = await Encrypt(service, key, iv, plaintext, associatedData: null, ct);
        encrypted[0] ^= 0xFF; // flip a byte

        using var input = new MemoryStream(encrypted);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<CryptographicException>(() =>
            service.DecryptAsync(input, output, key, iv, BlockCipherMode.Gcm, cancellationToken: ct));
    }

    [Fact]
    public async Task Encrypt_Decrypt_WithAssociatedData_RoundTrips()
    {
        var service = Service();
        var key = new byte[32];
        var iv = new byte[12];
        var plaintext = new byte[] { 10, 20, 30, 40, 50 };
        var aad = "header-v1"u8.ToArray();
        var ct = TestContext.Current.CancellationToken;

        var encrypted = await Encrypt(service, key, iv, plaintext, aad, ct);

        using var input = new MemoryStream(encrypted);
        using var output = new MemoryStream();
        await service.DecryptAsync(input, output, key, iv, BlockCipherMode.Gcm,
            associatedData: aad, cancellationToken: ct);

        Assert.Equal(plaintext, output.ToArray());
    }

    [Fact]
    public async Task Decrypt_WithMismatchedAssociatedData_ThrowsCryptographicException()
    {
        var service = Service();
        var key = new byte[32];
        var iv = new byte[12];
        var plaintext = new byte[] { 10, 20, 30, 40, 50 };
        var ct = TestContext.Current.CancellationToken;

        var encrypted = await Encrypt(service, key, iv, plaintext, "header-v1"u8.ToArray(), ct);

        using var input = new MemoryStream(encrypted);
        using var output = new MemoryStream();
        await Assert.ThrowsAsync<CryptographicException>(() =>
            service.DecryptAsync(input, output, key, iv, BlockCipherMode.Gcm,
                associatedData: "header-v2"u8.ToArray(), cancellationToken: ct));
    }

    [Fact]
    public async Task Decrypt_WithMissingAssociatedData_ThrowsCryptographicException()
    {
        var service = Service();
        var key = new byte[32];
        var iv = new byte[12];
        var plaintext = new byte[] { 10, 20, 30, 40, 50 };
        var ct = TestContext.Current.CancellationToken;

        var encrypted = await Encrypt(service, key, iv, plaintext, "header-v1"u8.ToArray(), ct);

        using var input = new MemoryStream(encrypted);
        using var output = new MemoryStream();
        // Encrypted with AAD but decrypting without it must fail authentication.
        await Assert.ThrowsAsync<CryptographicException>(() =>
            service.DecryptAsync(input, output, key, iv, BlockCipherMode.Gcm, cancellationToken: ct));
    }

    private static async Task<byte[]> Encrypt(
        IBlockCipherService service, byte[] key, byte[] iv, byte[] plaintext,
        byte[]? associatedData, System.Threading.CancellationToken ct)
    {
        using var input = new MemoryStream(plaintext);
        using var output = new MemoryStream();
        await service.EncryptAsync(input, output, key, iv, BlockCipherMode.Gcm,
            associatedData: associatedData, cancellationToken: ct);
        return output.ToArray();
    }

    public static IEnumerable<object[]> GcmVectors() => BlockCipherKat.IvVectors("aes-gcm.csv");
}
