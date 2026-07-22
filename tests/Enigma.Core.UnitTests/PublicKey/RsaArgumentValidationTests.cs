using System;
using System.Security.Cryptography;
using Enigma.Core;
using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// Argument guards and failure-mode mapping for the public-key service: null/empty/malformed PEM strings,
/// null data/signature, wrong-password decryption, and the enum→internal-mapping exhaustiveness guards.
/// </summary>
[Collection(RsaKeyCollection.Name)]
public class RsaArgumentValidationTests(RsaKeyFixture keys)
{
    private static IPublicKeyService Service() => new PublicKeyServiceFactory().CreatePublicKeyService();
    private static readonly byte[] SomeData = { 1, 2, 3, 4 };

    // ---- null data / signature ----

    [Fact]
    public void EncryptPkcs1_NullData_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().EncryptPkcs1(null!, keys.PublicKeyPem));

    [Fact]
    public void DecryptPkcs1_NullCiphertext_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().DecryptPkcs1(null!, keys.PrivateKeyPem));

    [Fact]
    public void EncryptOaep_NullData_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().EncryptOaep(null!, keys.PublicKeyPem));

    [Fact]
    public void Sign_NullData_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().Sign(null!, keys.PrivateKeyPem));

    [Fact]
    public void Verify_NullData_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().Verify(null!, SomeData, keys.PublicKeyPem));

    [Fact]
    public void Verify_NullSignature_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().Verify(SomeData, null!, keys.PublicKeyPem));

    // ---- null / empty / malformed PEM ----

    [Fact]
    public void EncryptPkcs1_NullPublicKeyPem_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().EncryptPkcs1(SomeData, null!));

    [Fact]
    public void EncryptPkcs1_EmptyPublicKeyPem_Throws()
        => Assert.Throws<ArgumentException>(() => Service().EncryptPkcs1(SomeData, "   "));

    [Fact]
    public void EncryptPkcs1_MalformedPublicKeyPem_Throws()
        => Assert.Throws<ArgumentException>(() => Service().EncryptPkcs1(SomeData, "not a pem at all"));

    [Fact]
    public void Sign_NullPrivateKeyPem_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().Sign(SomeData, null!));

    [Fact]
    public void Sign_EmptyPrivateKeyPem_Throws()
        => Assert.Throws<ArgumentException>(() => Service().Sign(SomeData, ""));

    [Fact]
    public void Sign_MalformedPrivateKeyPem_Throws()
        => Assert.Throws<ArgumentException>(() => Service().Sign(SomeData, "garbage"));

    // ---- passphrase paths ----

    [Fact]
    public void PrivateKeyOperation_WrongPassword_ThrowsCryptographicException()
    {
        var service = Service();
        var (_, encryptedPrivatePem) = service.GenerateRsaKeyPair(2048, "correct-password".ToCharArray());

        Assert.Throws<CryptographicException>(
            () => service.Sign(SomeData, encryptedPrivatePem, password: "wrong-password".ToCharArray()));
    }

    [Fact]
    public void PrivateKeyOperation_EncryptedPemWithoutPassword_ThrowsCryptographicException()
    {
        var service = Service();
        var (_, encryptedPrivatePem) = service.GenerateRsaKeyPair(2048, "correct-password".ToCharArray());

        Assert.Throws<CryptographicException>(
            () => service.Sign(SomeData, encryptedPrivatePem, password: null));
    }

    [Fact]
    public void PrivateKeyOperation_UnencryptedPemWithNullPassword_Succeeds()
    {
        // The shared fixture's private key is unencrypted; a null password must be accepted.
        var signature = Service().Sign(SomeData, keys.PrivateKeyPem, password: null);
        Assert.True(Service().Verify(SomeData, signature, keys.PublicKeyPem));
    }

    // ---- enum → internal mapping exhaustiveness (undefined values are rejected) ----

    [Fact]
    public void EncryptOaep_UndefinedHash_ThrowsArgumentOutOfRange()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => Service().EncryptOaep(SomeData, keys.PublicKeyPem, (RsaOaepHash)999));

    [Fact]
    public void Sign_UndefinedAlgorithm_ThrowsArgumentOutOfRange()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => Service().Sign(SomeData, keys.PrivateKeyPem, (RsaSignatureAlgorithm)999));

    [Fact]
    public void Verify_UndefinedAlgorithm_ThrowsArgumentOutOfRange()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => Service().Verify(SomeData, SomeData, keys.PublicKeyPem, (RsaSignatureAlgorithm)999));
}
