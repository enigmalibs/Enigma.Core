using System;
using System.IO;
using System.Security.Cryptography;
using Enigma.Core;
using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// Argument guards and failure-mode mapping for the public-key service: null data/key/signature, the
/// private-key-required guard on the private operations, the passphrase failure modes at the point a PEM is
/// imported, and the enum→internal-mapping exhaustiveness guards.
/// </summary>
/// <remarks>
/// The null/empty/malformed-PEM guards are asserted by <see cref="RsaKeyTests"/> instead: a PEM now enters the
/// library only through <see cref="RsaKey.ImportPublicKeyPem"/> / <see cref="RsaKey.ImportPrivateKeyPem"/>, and
/// those tests pin the same exception types plus the parameter name they carry.
/// </remarks>
[Collection(RsaKeyCollection.Name)]
public class RsaArgumentValidationTests(RsaKeyFixture keys)
{
    private static IPublicKeyService Service() => new PublicKeyServiceFactory().CreatePublicKeyService();
    private static readonly byte[] SomeData = { 1, 2, 3, 4 };

    /// <summary>The passphrase protecting the committed <c>pk_key_legacy_encrypted.pem</c> fixture.</summary>
    private const string LegacyFixturePassphrase = "legacy1234";

    // ---- null data / signature ----

    [Fact]
    public void EncryptPkcs1_NullData_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().EncryptPkcs1(null!, keys.PublicKey));

    [Fact]
    public void DecryptPkcs1_NullCiphertext_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().DecryptPkcs1(null!, keys.PrivateKey));

    [Fact]
    public void EncryptOaep_NullData_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().EncryptOaep(null!, keys.PublicKey));

    [Fact]
    public void DecryptOaep_NullCiphertext_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().DecryptOaep(null!, keys.PrivateKey));

    [Fact]
    public void Sign_NullData_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().Sign(null!, keys.PrivateKey));

    [Fact]
    public void Verify_NullData_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().Verify(null!, SomeData, keys.PublicKey));

    [Fact]
    public void Verify_NullSignature_Throws()
        => Assert.Throws<ArgumentNullException>(() => Service().Verify(SomeData, null!, keys.PublicKey));

    // ---- null key ----

    [Fact]
    public void EncryptPkcs1_NullKey_Throws()
        => Assert.Equal("key",
            Assert.Throws<ArgumentNullException>(() => Service().EncryptPkcs1(SomeData, null!)).ParamName);

    [Fact]
    public void DecryptPkcs1_NullKey_Throws()
        => Assert.Equal("key",
            Assert.Throws<ArgumentNullException>(() => Service().DecryptPkcs1(SomeData, null!)).ParamName);

    [Fact]
    public void EncryptOaep_NullKey_Throws()
        => Assert.Equal("key",
            Assert.Throws<ArgumentNullException>(() => Service().EncryptOaep(SomeData, null!)).ParamName);

    [Fact]
    public void DecryptOaep_NullKey_Throws()
        => Assert.Equal("key",
            Assert.Throws<ArgumentNullException>(() => Service().DecryptOaep(SomeData, null!)).ParamName);

    [Fact]
    public void Sign_NullKey_Throws()
        => Assert.Equal("key",
            Assert.Throws<ArgumentNullException>(() => Service().Sign(SomeData, null!)).ParamName);

    [Fact]
    public void Verify_NullKey_Throws()
        => Assert.Equal("key",
            Assert.Throws<ArgumentNullException>(() => Service().Verify(SomeData, SomeData, null!)).ParamName);

    // ---- a public-only handle cannot drive a private operation ----

    [Fact]
    public void DecryptPkcs1_PublicOnlyHandle_ThrowsArgumentExceptionNamingTheKey()
        => Assert.Equal("key",
            Assert.Throws<ArgumentException>(() => Service().DecryptPkcs1(SomeData, keys.PublicKey)).ParamName);

    [Fact]
    public void DecryptOaep_PublicOnlyHandle_ThrowsArgumentExceptionNamingTheKey()
        => Assert.Equal("key",
            Assert.Throws<ArgumentException>(() => Service().DecryptOaep(SomeData, keys.PublicKey)).ParamName);

    [Fact]
    public void Sign_PublicOnlyHandle_ThrowsArgumentExceptionNamingTheKey()
        => Assert.Equal("key",
            Assert.Throws<ArgumentException>(() => Service().Sign(SomeData, keys.PublicKey)).ParamName);

    // ---- passphrase paths: they live at the import, the only place a passphrase is now supplied ----

    [Fact]
    public void ImportPrivateKeyPem_WrongPassword_ThrowsCryptographicException()
    {
        var encryptedPrivatePem = keys.PrivateKey.ExportPrivateKeyPem("correct-password".ToCharArray());

        Assert.Throws<CryptographicException>(
            () => RsaKey.ImportPrivateKeyPem(encryptedPrivatePem, "wrong-password".ToCharArray()));
    }

    [Fact]
    public void ImportPrivateKeyPem_EncryptedPemWithoutPassword_ThrowsCryptographicException()
    {
        var encryptedPrivatePem = keys.PrivateKey.ExportPrivateKeyPem("correct-password".ToCharArray());

        Assert.Throws<CryptographicException>(() => RsaKey.ImportPrivateKeyPem(encryptedPrivatePem, password: null));
    }

    [Fact]
    public void ImportPrivateKeyPem_UnsupportedDekAlgorithm_ThrowsArgumentException()
    {
        // Characterization, not a design statement: an unrecognised DEK-Info cipher makes BouncyCastle raise
        // EncryptionException, which PemEnvelope does not catch explicitly — it falls through to
        // catch (IOException) and surfaces as ArgumentException("malformed"). That is the intended reading (an
        // unknown cipher header is a structural PEM defect, not a failed decryption), and this test pins it so a
        // future BouncyCastle change to that path shows up red instead of silently altering the exception a
        // caller sees.
        //
        // The input is built from the committed legacy fixture rather than from freshly generated output: the
        // writer now emits PBES2, which carries no DEK-Info header to corrupt. The fixture is the library's only
        // remaining source of the traditional OpenSSL envelope, and this path only exists for reading it.
        var legacyPem = File.ReadAllText(Path.Combine("PublicKey", "pk_key_legacy_encrypted.pem"));
        var bogusDekPem = legacyPem.Replace("DEK-Info: AES-256-CBC", "DEK-Info: NOT-A-REAL-CIPHER");

        Assert.NotEqual(legacyPem, bogusDekPem);
        Assert.Throws<ArgumentException>(
            () => RsaKey.ImportPrivateKeyPem(bogusDekPem, LegacyFixturePassphrase.ToCharArray()));
    }

    [Fact]
    public void ImportPrivateKeyPem_UnencryptedPemWithNullPassword_Succeeds()
    {
        // The shared fixture's private-key PEM is unencrypted; importing it with no password must be accepted, and
        // the resulting handle must be usable.
        var key = RsaKey.ImportPrivateKeyPem(keys.PrivateKeyPem, password: null);

        var signature = Service().Sign(SomeData, key);
        Assert.True(Service().Verify(SomeData, signature, keys.PublicKey));
    }

    // ---- enum → internal mapping exhaustiveness (undefined values are rejected) ----

    [Fact]
    public void EncryptOaep_UndefinedHash_ThrowsArgumentOutOfRange()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => Service().EncryptOaep(SomeData, keys.PublicKey, (RsaOaepHash)999));

    [Fact]
    public void DecryptOaep_UndefinedHash_ThrowsArgumentOutOfRange()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => Service().DecryptOaep(SomeData, keys.PrivateKey, (RsaOaepHash)999));

    [Fact]
    public void Sign_UndefinedAlgorithm_ThrowsArgumentOutOfRange()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => Service().Sign(SomeData, keys.PrivateKey, (RsaSignatureAlgorithm)999));

    [Fact]
    public void Verify_UndefinedAlgorithm_ThrowsArgumentOutOfRange()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => Service().Verify(SomeData, SomeData, keys.PublicKey, (RsaSignatureAlgorithm)999));
}
