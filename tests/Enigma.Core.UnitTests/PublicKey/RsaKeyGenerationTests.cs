using System;
using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// The restored <see cref="IPublicKeyService.GenerateRsaKeyPair"/>: PEM-string output, the unencrypted vs
/// AES-256-CBC-encrypted private-key formats, round-tripping through the encrypt/sign methods, the
/// passphrase paths, and the non-positive key-size guard.
/// </summary>
public class RsaKeyGenerationTests
{
    private static IPublicKeyService Service() => new PublicKeyServiceFactory().CreatePublicKeyService();

    [Fact]
    public void GenerateRsaKeyPair_NoPassword_ProducesUnencryptedPkcs8PrivateKeyPem()
    {
        var (publicKeyPem, privateKeyPem) = Service().GenerateRsaKeyPair(2048);

        Assert.Contains("-----BEGIN PUBLIC KEY-----", publicKeyPem);
        Assert.Contains("-----BEGIN PRIVATE KEY-----", privateKeyPem);
        // Not encrypted and not the traditional RSA envelope.
        Assert.DoesNotContain("ENCRYPTED", privateKeyPem);
        Assert.DoesNotContain("RSA PRIVATE KEY", privateKeyPem);
    }

    [Fact]
    public void GenerateRsaKeyPair_WithPassword_ProducesAes256CbcEncryptedPrivateKeyPem()
    {
        var (_, privateKeyPem) = Service().GenerateRsaKeyPair(2048, "pass-phrase".ToCharArray());

        Assert.Contains("-----BEGIN RSA PRIVATE KEY-----", privateKeyPem);
        Assert.Contains("Proc-Type: 4,ENCRYPTED", privateKeyPem);
        Assert.Contains("DEK-Info: AES-256-CBC", privateKeyPem);
    }

    [Fact]
    public void GenerateRsaKeyPair_Unencrypted_RoundTripsThroughEncryptAndSign()
    {
        var service = Service();
        var (publicKeyPem, privateKeyPem) = service.GenerateRsaKeyPair(2048);
        var plaintext = System.Text.Encoding.UTF8.GetBytes("generated-key round-trip");

        var encrypted = service.EncryptPkcs1(plaintext, publicKeyPem);
        Assert.Equal(plaintext, service.DecryptPkcs1(encrypted, privateKeyPem));

        var signature = service.Sign(plaintext, privateKeyPem);
        Assert.True(service.Verify(plaintext, signature, publicKeyPem));
    }

    [Fact]
    public void GenerateRsaKeyPair_Encrypted_ReParsesWithPassword()
    {
        var service = Service();
        var password = "S3cr3t-passphrase".ToCharArray();
        var (publicKeyPem, privateKeyPem) = service.GenerateRsaKeyPair(2048, password);
        var plaintext = System.Text.Encoding.UTF8.GetBytes("encrypted-key round-trip");

        // The encrypted private-key PEM must re-parse with its password on the private-key operations.
        var encrypted = service.EncryptPkcs1(plaintext, publicKeyPem);
        var decrypted = service.DecryptPkcs1(encrypted, privateKeyPem, password: "S3cr3t-passphrase".ToCharArray());
        Assert.Equal(plaintext, decrypted);

        var signature = service.Sign(plaintext, privateKeyPem, password: "S3cr3t-passphrase".ToCharArray());
        Assert.True(service.Verify(plaintext, signature, publicKeyPem));
    }

    [Fact]
    public void GenerateRsaKeyPair_DoesNotClearCallerPassword()
    {
        var password = "keep-me".ToCharArray();
        Service().GenerateRsaKeyPair(1024, password);

        // The caller owns the passphrase array; generation must not blank it.
        Assert.Equal("keep-me".ToCharArray(), password);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-2048)]
    public void GenerateRsaKeyPair_NonPositiveKeySize_ThrowsArgumentException(int keySizeBits)
        => Assert.Throws<ArgumentException>(() => Service().GenerateRsaKeyPair(keySizeBits));
}
