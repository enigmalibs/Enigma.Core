using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// PKCS#1 v1.5 encrypt/decrypt and sign/verify round-trips over <see cref="RsaKey"/> handles, the acceptance of
/// a private-holding handle by the public-key operations, and the point of the handle: one key reused across
/// many operations without re-importing it.
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

        var encrypted = service.EncryptPkcs1(plaintext, keys.PublicKey);
        var decrypted = service.DecryptPkcs1(encrypted, keys.PrivateKey);

        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptPkcs1_ProducesDifferentCiphertextThanPlaintext()
    {
        var service = Service();
        var plaintext = System.Text.Encoding.UTF8.GetBytes("secret");

        var encrypted = service.EncryptPkcs1(plaintext, keys.PublicKey);

        Assert.NotEqual(plaintext, encrypted);
    }

    [Fact]
    public void SignVerify_RoundTrips_WithGeneratedKeys()
    {
        var service = Service();
        var data = System.Text.Encoding.UTF8.GetBytes("data to sign and verify");

        var signature = service.Sign(data, keys.PrivateKey);
        var isValid = service.Verify(data, signature, keys.PublicKey);

        Assert.True(isValid);
    }

    [Fact]
    public void Verify_TamperedMessage_ReturnsFalse()
    {
        var service = Service();
        var data = System.Text.Encoding.UTF8.GetBytes("the original message");
        var tampered = System.Text.Encoding.UTF8.GetBytes("the tampered message");

        var signature = service.Sign(data, keys.PrivateKey);

        Assert.False(service.Verify(tampered, signature, keys.PublicKey));
    }

    // ---- a private-holding handle serves the public operations too ----

    [Fact]
    public void PublicOperations_AcceptAPrivateHoldingHandle()
    {
        // GenerateRsaKey hands out a single handle carrying both halves, so the public operations must take it:
        // the service derives the public key from the private components rather than refusing the handle.
        var service = Service();
        var plaintext = System.Text.Encoding.UTF8.GetBytes("one handle, both directions");

        var pkcs1 = service.EncryptPkcs1(plaintext, keys.PrivateKey);
        Assert.Equal(plaintext, service.DecryptPkcs1(pkcs1, keys.PrivateKey));

        var oaep = service.EncryptOaep(plaintext, keys.PrivateKey);
        Assert.Equal(plaintext, service.DecryptOaep(oaep, keys.PrivateKey));

        var signature = service.Sign(plaintext, keys.PrivateKey);
        Assert.True(service.Verify(plaintext, signature, keys.PrivateKey));
    }

    [Fact]
    public void PrivateHoldingHandle_EncryptsInteroperablyWithItsPublicOnlyCounterpart()
    {
        // Proof that the derived public half really is the public key, and not the private key being used for the
        // public operation by mistake: what one handle encrypts, the other's private half decrypts.
        var service = Service();
        var plaintext = System.Text.Encoding.UTF8.GetBytes("derived public half");

        var viaPrivateHandle = service.EncryptOaep(plaintext, keys.PrivateKey);
        var viaPublicHandle = service.EncryptOaep(plaintext, keys.PublicKey);

        Assert.Equal(plaintext, service.DecryptOaep(viaPrivateHandle, keys.PrivateKey));
        Assert.Equal(plaintext, service.DecryptOaep(viaPublicHandle, keys.PrivateKey));

        var signature = service.Sign(plaintext, keys.PrivateKey);
        Assert.True(service.Verify(plaintext, signature, keys.PublicKey));
        Assert.True(service.Verify(plaintext, signature, keys.PrivateKey));
    }

    // ---- the reason this item exists ----

    [Fact]
    public void OneImportedHandle_ServesManyOperations_WithoutReImporting()
    {
        // The regression test for the point of the handle: a key is parsed once — here from an encrypted PEM, whose
        // PBES2 derivation is the expensive part — and then drives many operations with no further import and no
        // further passphrase.
        var service = Service();
        var password = "import-once".ToCharArray();
        var key = RsaKey.ImportPrivateKeyPem(keys.PrivateKey.ExportPrivateKeyPem(password), password);

        for (var i = 0; i < 25; i++)
        {
            var message = System.Text.Encoding.UTF8.GetBytes($"message {i}");

            var signature = service.Sign(message, key);
            Assert.True(service.Verify(message, signature, key));
            Assert.Equal(message, service.DecryptOaep(service.EncryptOaep(message, key), key));
        }
    }
}
