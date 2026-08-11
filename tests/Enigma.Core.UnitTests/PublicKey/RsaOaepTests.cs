using System.Security.Cryptography;
using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// RSAES-OAEP round-trips across all supported hashes, the SHA-256 default, and the wrapped-exception
/// policy: a mismatched hash / bad ciphertext surfaces as <see cref="CryptographicException"/> (never the
/// underlying BouncyCastle type).
/// </summary>
[Collection(RsaKeyCollection.Name)]
public class RsaOaepTests(RsaKeyFixture keys)
{
    private static IPublicKeyService Service() => new PublicKeyServiceFactory().CreatePublicKeyService();

    [Theory]
    [InlineData(RsaOaepHash.Sha1)]
    [InlineData(RsaOaepHash.Sha256)]
    [InlineData(RsaOaepHash.Sha384)]
    [InlineData(RsaOaepHash.Sha512)]
    public void EncryptOaep_Decrypt_RoundTrips_ForEveryHash(RsaOaepHash hash)
    {
        var service = Service();
        var plaintext = System.Text.Encoding.UTF8.GetBytes($"OAEP round-trip with {hash}");

        var encrypted = service.EncryptOaep(plaintext, keys.PublicKey, hash);
        var decrypted = service.DecryptOaep(encrypted, keys.PrivateKey, hash);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptOaep_DefaultHash_IsSha256()
    {
        var service = Service();
        var plaintext = System.Text.Encoding.UTF8.GetBytes("pin the default OAEP hash");

        // Encrypt with the default hash; an explicit SHA-256 decrypt must succeed, proving the default is SHA-256.
        var encrypted = service.EncryptOaep(plaintext, keys.PublicKey);
        var decrypted = service.DecryptOaep(encrypted, keys.PrivateKey, RsaOaepHash.Sha256);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void DecryptOaep_MismatchedHash_ThrowsCryptographicException()
    {
        var service = Service();
        var plaintext = System.Text.Encoding.UTF8.GetBytes("mismatched OAEP hash");

        var encrypted = service.EncryptOaep(plaintext, keys.PublicKey, RsaOaepHash.Sha256);

        Assert.Throws<CryptographicException>(
            () => service.DecryptOaep(encrypted, keys.PrivateKey, RsaOaepHash.Sha512));
    }

    [Fact]
    public void DecryptOaep_CorruptCiphertext_ThrowsCryptographicException()
    {
        var service = Service();
        var plaintext = System.Text.Encoding.UTF8.GetBytes("corrupt me");

        var encrypted = service.EncryptOaep(plaintext, keys.PublicKey);
        encrypted[0] ^= 0xFF; // flip a byte

        Assert.Throws<CryptographicException>(
            () => service.DecryptOaep(encrypted, keys.PrivateKey));
    }
}
