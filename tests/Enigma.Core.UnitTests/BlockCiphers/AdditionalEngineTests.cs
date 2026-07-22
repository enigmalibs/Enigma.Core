using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Enigma.Core.Symmetric.BlockCiphers;
using Xunit;

namespace Enigma.Core.UnitTests.BlockCiphers;

/// <summary>
/// Encrypt/decrypt round-trips (CBC, default PKCS#7 padding) for the eight algorithms that have no KAT
/// vector file — Twofish, Serpent, Camellia, CAST-128, IDEA, SEED, ARIA, SM4. Together with the KAT'd
/// AES/DES/3DES/Blowfish this exercises all twelve supported algorithms. Keys and IVs come from
/// <see cref="RandomNumberGenerator"/> (a BCL source, independent of the library's own RandomUtils), and
/// the default PKCS#7 padding also exercises the padded round-trip path.
/// </summary>
public class AdditionalEngineTests
{
    private static async Task RoundTrip(IBlockCipherService service, int keyBytes, int blockBytes, CancellationToken ct)
    {
        var key = RandomNumberGenerator.GetBytes(keyBytes);
        var iv = RandomNumberGenerator.GetBytes(blockBytes);
        var plaintext = RandomNumberGenerator.GetBytes(64);

        byte[] encrypted;
        using (var input = new MemoryStream(plaintext))
        using (var output = new MemoryStream())
        {
            await service.EncryptAsync(input, output, key, iv, BlockCipherMode.Cbc, cancellationToken: ct);
            encrypted = output.ToArray();
        }

        using var encInput = new MemoryStream(encrypted);
        using var decrypted = new MemoryStream();
        await service.DecryptAsync(encInput, decrypted, key, iv, BlockCipherMode.Cbc, cancellationToken: ct);

        Assert.Equal(plaintext, decrypted.ToArray());
    }

    private readonly IBlockCipherServiceFactory _factory = new BlockCipherServiceFactory();

    [Fact]
    public Task Twofish_Cbc_RoundTrip() => RoundTrip(_factory.CreateTwofishService(), 32, 16, TestContext.Current.CancellationToken);

    [Fact]
    public Task Serpent_Cbc_RoundTrip() => RoundTrip(_factory.CreateSerpentService(), 32, 16, TestContext.Current.CancellationToken);

    [Fact]
    public Task Camellia_Cbc_RoundTrip() => RoundTrip(_factory.CreateCamelliaService(), 32, 16, TestContext.Current.CancellationToken);

    [Fact]
    public Task Cast128_Cbc_RoundTrip() => RoundTrip(_factory.CreateCast128Service(), 16, 8, TestContext.Current.CancellationToken);

    [Fact]
    public Task Idea_Cbc_RoundTrip() => RoundTrip(_factory.CreateIdeaService(), 16, 8, TestContext.Current.CancellationToken);

    [Fact]
    public Task Seed_Cbc_RoundTrip() => RoundTrip(_factory.CreateSeedService(), 16, 16, TestContext.Current.CancellationToken);

    [Fact]
    public Task Aria_Cbc_RoundTrip() => RoundTrip(_factory.CreateAriaService(), 32, 16, TestContext.Current.CancellationToken);

    [Fact]
    public Task Sm4_Cbc_RoundTrip() => RoundTrip(_factory.CreateSm4Service(), 16, 16, TestContext.Current.CancellationToken);
}
