using System.IO;
using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// End-to-end tests over the real on-disk PEM fixtures: an AES-encrypted PKCS#8 private key
/// (<c>pk_key1.pem</c>, passphrase <c>test1234</c>) and its matching public key (<c>pub_key1.pem</c>),
/// supplied to the API as PEM strings with a <see cref="char"/>-array passphrase.
/// </summary>
public class RsaServiceTests
{
    private static IPublicKeyService Service() => new PublicKeyServiceFactory().CreatePublicKeyService();

    private static string PublicKeyPem() => File.ReadAllText(Path.Combine("PublicKey", "pub_key1.pem"));
    private static string PrivateKeyPem() => File.ReadAllText(Path.Combine("PublicKey", "pk_key1.pem"));
    private static char[] Passphrase() => "test1234".ToCharArray();

    [Fact]
    public void SignVerify_WithFixtureKeys_ReturnsTrue()
    {
        var service = Service();
        var data = "This message will be signed and verified"u8.ToArray();

        var signature = service.Sign(data, PrivateKeyPem(), password: Passphrase());
        var result = service.Verify(data, signature, PublicKeyPem());

        Assert.True(result);
    }

    [Fact]
    public void Verify_WrongMessage_WithFixtureKeys_ReturnsFalse()
    {
        var service = Service();
        var data = "This message will be signed and verified"u8.ToArray();
        var otherData = "This is not gonna work !"u8.ToArray();

        var signature = service.Sign(data, PrivateKeyPem(), password: Passphrase());

        Assert.False(service.Verify(otherData, signature, PublicKeyPem()));
    }

    [Fact]
    public void EncryptPkcs1_Decrypt_WithFixtureKeys_RoundTrips()
    {
        var service = Service();
        var plaintext = "fixture round-trip"u8.ToArray();

        var encrypted = service.EncryptPkcs1(plaintext, PublicKeyPem());
        var decrypted = service.DecryptPkcs1(encrypted, PrivateKeyPem(), password: Passphrase());

        Assert.Equal(plaintext, decrypted);
    }
}
