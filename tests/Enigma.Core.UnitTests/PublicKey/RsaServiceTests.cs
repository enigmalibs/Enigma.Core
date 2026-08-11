using System.IO;
using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// End-to-end tests over the real on-disk PEM fixtures: a PBES2-encrypted PKCS#8 private key
/// (<c>pk_key1.pem</c>, passphrase <c>test1234</c>) and its matching public key (<c>pub_key1.pem</c>),
/// imported into <see cref="RsaKey"/> handles — the passphrase is supplied there and nowhere else.
/// </summary>
public class RsaServiceTests
{
    private static IPublicKeyService Service() => new PublicKeyServiceFactory().CreatePublicKeyService();

    private static RsaKey PublicKey() =>
        RsaKey.ImportPublicKeyPem(File.ReadAllText(Path.Combine("PublicKey", "pub_key1.pem")));

    private static RsaKey PrivateKey() =>
        RsaKey.ImportPrivateKeyPem(File.ReadAllText(Path.Combine("PublicKey", "pk_key1.pem")), Passphrase());

    private static char[] Passphrase() => "test1234".ToCharArray();

    [Fact]
    public void SignVerify_WithFixtureKeys_ReturnsTrue()
    {
        var service = Service();
        var data = "This message will be signed and verified"u8.ToArray();

        var signature = service.Sign(data, PrivateKey());
        var result = service.Verify(data, signature, PublicKey());

        Assert.True(result);
    }

    [Fact]
    public void Verify_WrongMessage_WithFixtureKeys_ReturnsFalse()
    {
        var service = Service();
        var data = "This message will be signed and verified"u8.ToArray();
        var otherData = "This is not gonna work !"u8.ToArray();

        var signature = service.Sign(data, PrivateKey());

        Assert.False(service.Verify(otherData, signature, PublicKey()));
    }

    [Fact]
    public void EncryptPkcs1_Decrypt_WithFixtureKeys_RoundTrips()
    {
        var service = Service();
        var plaintext = "fixture round-trip"u8.ToArray();

        var encrypted = service.EncryptPkcs1(plaintext, PublicKey());
        var decrypted = service.DecryptPkcs1(encrypted, PrivateKey());

        Assert.Equal(plaintext, decrypted);
    }
}
