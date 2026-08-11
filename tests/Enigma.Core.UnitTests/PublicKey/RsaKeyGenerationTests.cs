using System;
using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// <see cref="IPublicKeyService.GenerateRsaKey"/>: the single handle it hands out (carrying both halves), the
/// unencrypted vs PBES2-encrypted private-key export formats, round-tripping through the encrypt/sign methods,
/// the passphrase paths, and the non-positive key-size guard.
/// </summary>
public class RsaKeyGenerationTests
{
    private static IPublicKeyService Service() => new PublicKeyServiceFactory().CreatePublicKeyService();

    [Fact]
    public void GenerateRsaKey_ReturnsAHandleCarryingBothHalves()
    {
        var key = Service().GenerateRsaKey(2048);

        Assert.True(key.HasPrivateKey);
        Assert.Equal(2048, key.KeySizeBits);
        Assert.Contains("-----BEGIN PUBLIC KEY-----", key.ExportPublicKeyPem());
    }

    [Fact]
    public void GenerateRsaKey_ExportedWithoutPassword_ProducesUnencryptedPkcs8PrivateKeyPem()
    {
        var key = Service().GenerateRsaKey(2048);

        Assert.Contains("-----BEGIN PUBLIC KEY-----", key.ExportPublicKeyPem());
        Assert.Contains("-----BEGIN PRIVATE KEY-----", key.ExportPrivateKeyPem());
        // Not encrypted and not the traditional RSA envelope.
        Assert.DoesNotContain("ENCRYPTED", key.ExportPrivateKeyPem());
        Assert.DoesNotContain("RSA PRIVATE KEY", key.ExportPrivateKeyPem());
    }

    [Fact]
    public void GenerateRsaKey_ExportedWithPassword_ProducesPbes2EncryptedPrivateKeyPem()
    {
        var privateKeyPem = Service().GenerateRsaKey(2048).ExportPrivateKeyPem("pass-phrase".ToCharArray());

        // The emitted format is PKCS#8 PBES2 (PBKDF2-HMAC-SHA256 + AES-256-CBC), not the traditional OpenSSL
        // envelope this test used to pin: that one derives its key with OpenSSL's legacy EVP_BytesToKey
        // (MD5, a single iteration). Reading still accepts the old form — see RsaKeyTests and the committed
        // pk_key_legacy_encrypted.pem fixture — so existing key files keep working.
        Assert.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----", privateKeyPem);
        Assert.DoesNotContain("RSA PRIVATE KEY", privateKeyPem);
        Assert.DoesNotContain("Proc-Type", privateKeyPem);
        Assert.DoesNotContain("DEK-Info", privateKeyPem);
    }

    [Fact]
    public void GenerateRsaKey_RoundTripsThroughEncryptAndSign_OnTheHandleItself()
    {
        var service = Service();
        var key = service.GenerateRsaKey(2048);
        var plaintext = System.Text.Encoding.UTF8.GetBytes("generated-key round-trip");

        var encrypted = service.EncryptPkcs1(plaintext, key);
        Assert.Equal(plaintext, service.DecryptPkcs1(encrypted, key));

        var signature = service.Sign(plaintext, key);
        Assert.True(service.Verify(plaintext, signature, key));
    }

    [Fact]
    public void GenerateRsaKey_Unencrypted_RoundTripsThroughExportAndReImport()
    {
        var service = Service();
        var key = service.GenerateRsaKey(2048);
        var publicKey = RsaKey.ImportPublicKeyPem(key.ExportPublicKeyPem());
        var privateKey = RsaKey.ImportPrivateKeyPem(key.ExportPrivateKeyPem());
        var plaintext = System.Text.Encoding.UTF8.GetBytes("generated-key round-trip");

        var encrypted = service.EncryptPkcs1(plaintext, publicKey);
        Assert.Equal(plaintext, service.DecryptPkcs1(encrypted, privateKey));

        var signature = service.Sign(plaintext, privateKey);
        Assert.True(service.Verify(plaintext, signature, publicKey));
    }

    [Fact]
    public void GenerateRsaKey_Encrypted_ReImportsWithPassword()
    {
        var service = Service();
        var password = "S3cr3t-passphrase".ToCharArray();
        var key = service.GenerateRsaKey(2048);
        var publicKey = RsaKey.ImportPublicKeyPem(key.ExportPublicKeyPem());
        var encryptedPrivateKeyPem = key.ExportPrivateKeyPem(password);
        var plaintext = System.Text.Encoding.UTF8.GetBytes("encrypted-key round-trip");

        // The encrypted private-key PEM must re-import with its password, once, and then serve both operations.
        var privateKey = RsaKey.ImportPrivateKeyPem(encryptedPrivateKeyPem, "S3cr3t-passphrase".ToCharArray());

        var encrypted = service.EncryptPkcs1(plaintext, publicKey);
        Assert.Equal(plaintext, service.DecryptPkcs1(encrypted, privateKey));

        var signature = service.Sign(plaintext, privateKey);
        Assert.True(service.Verify(plaintext, signature, publicKey));
    }

    [Fact]
    public void ExportPrivateKeyPem_DoesNotClearCallerPassword()
    {
        var password = "keep-me".ToCharArray();
        Service().GenerateRsaKey(1024).ExportPrivateKeyPem(password);

        // The caller owns the passphrase array; writing the PEM must not blank it. (Generation itself no longer
        // takes a password at all — the passphrase belongs to the export and to the matching import.)
        Assert.Equal("keep-me".ToCharArray(), password);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-2048)]
    public void GenerateRsaKey_NonPositiveKeySize_ThrowsArgumentException(int keySizeBits)
        => Assert.Throws<ArgumentException>(() => Service().GenerateRsaKey(keySizeBits));
}
