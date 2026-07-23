using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// PKCS#1 v1.5 encrypt/decrypt and sign/verify round-trips over PEM-string keys, using both the shared
/// generated key pair and the on-disk fixtures.
/// </summary>
[Collection(RsaKeyCollection.Name)]
public class RsaEncryptDecryptTests(RsaKeyFixture keys)
{
    private static IPublicKeyService Service() => new PublicKeyServiceFactory().CreatePublicKeyService();

    [Fact]
    public void EncryptPkcs1_Decrypt_RoundTrips_WithGeneratedKeys()
    {
        var service = Service();
        var plaintext = System.Text.Encoding.UTF8.GetBytes("Hello, RSA PKCS#1 round-trip!");

        var encrypted = service.EncryptPkcs1(plaintext, keys.PublicKeyPem);
        var decrypted = service.DecryptPkcs1(encrypted, keys.PrivateKeyPem);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptPkcs1_ProducesDifferentCiphertextThanPlaintext()
    {
        var service = Service();
        var plaintext = System.Text.Encoding.UTF8.GetBytes("secret");

        var encrypted = service.EncryptPkcs1(plaintext, keys.PublicKeyPem);

        Assert.NotEqual(plaintext, encrypted);
    }

    [Fact]
    public void SignVerify_RoundTrips_WithGeneratedKeys()
    {
        var service = Service();
        var data = System.Text.Encoding.UTF8.GetBytes("data to sign and verify");

        var signature = service.Sign(data, keys.PrivateKeyPem);
        var isValid = service.Verify(data, signature, keys.PublicKeyPem);

        Assert.True(isValid);
    }

    [Fact]
    public void Verify_TamperedMessage_ReturnsFalse()
    {
        var service = Service();
        var data = System.Text.Encoding.UTF8.GetBytes("the original message");
        var tampered = System.Text.Encoding.UTF8.GetBytes("the tampered message");

        var signature = service.Sign(data, keys.PrivateKeyPem);

        Assert.False(service.Verify(tampered, signature, keys.PublicKeyPem));
    }
}
