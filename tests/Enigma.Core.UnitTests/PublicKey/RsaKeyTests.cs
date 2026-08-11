using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// The <see cref="RsaKey"/> handle: its public surface (six members, sealed, deliberately not
/// <see cref="IDisposable"/>), the three private-key PEM forms it reads, the two it writes, export/re-import
/// equivalence, the public-half derivation, and its argument and passphrase failure modes.
/// </summary>
/// <remarks>
/// Operations still go through the PEM-string service API in this phase — <see cref="IPublicKeyService"/> only
/// starts taking a handle in PHASE02 — so equivalence is asserted by exporting a handle and running the
/// existing service against the result.
/// </remarks>
[Collection(RsaKeyCollection.Name)]
public class RsaKeyTests(RsaKeyFixture keys)
{
    private static IPublicKeyService Service() => new PublicKeyServiceFactory().CreatePublicKeyService();

    /// <summary>The passphrase protecting the committed <c>pk_key_legacy_encrypted.pem</c> fixture.</summary>
    private const string LegacyFixturePassphrase = "legacy1234";

    /// <summary>The passphrase protecting the committed PBES2 <c>pk_key1.pem</c> fixture.</summary>
    private const string Pbes2FixturePassphrase = "test1234";

    private static string LegacyEncryptedPem() =>
        File.ReadAllText(Path.Combine("PublicKey", "pk_key_legacy_encrypted.pem"));

    private static string Pbes2FixturePem() => File.ReadAllText(Path.Combine("PublicKey", "pk_key1.pem"));
    private static string Pbes2FixturePublicPem() => File.ReadAllText(Path.Combine("PublicKey", "pub_key1.pem"));

    private static readonly byte[] Payload = "RsaKey round-trip payload"u8.ToArray();

    // ---- public surface (acceptance criterion 2) ----

    [Fact]
    public void RsaKey_ExposesExactlyTheSixDocumentedPublicMembers()
    {
        const BindingFlags declared = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static |
                                      BindingFlags.DeclaredOnly;

        var members = typeof(RsaKey).GetMembers(declared)
            .Select(m => m.Name)
            // Property accessors are surfaced separately by reflection; the properties themselves are counted.
            .Where(n => !n.StartsWith("get_", StringComparison.Ordinal) &&
                        !n.StartsWith("set_", StringComparison.Ordinal))
            .OrderBy(n => n, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            [
                "ExportPrivateKeyPem", "ExportPublicKeyPem", "HasPrivateKey",
                "ImportPrivateKeyPem", "ImportPublicKeyPem", "KeySizeBits",
            ],
            members);

        // Instances come only from the two static importers (and, from PHASE02, IPublicKeyService.GenerateRsaKey).
        Assert.Empty(typeof(RsaKey).GetConstructors(BindingFlags.Public | BindingFlags.Instance));
    }

    [Fact]
    public void RsaKey_IsSealed_AndNotDisposable()
    {
        Assert.True(typeof(RsaKey).IsSealed);

        // Private key material is held as immutable managed BigIntegers and cannot be wiped, so a Dispose would
        // be security theatre. Its absence is a design decision, pinned here.
        Assert.False(typeof(IDisposable).IsAssignableFrom(typeof(RsaKey)));
    }

    [Fact]
    public void RsaKey_ExposesItsBouncyCastleKeyOnlyAsPlainInternal()
    {
        var getter = typeof(RsaKey)
            .GetProperty("BcKey", BindingFlags.NonPublic | BindingFlags.Instance)?.GetMethod;

        Assert.NotNull(getter);
        Assert.True(getter.IsAssembly);
        // Never protected internal: the isolation guard treats IsFamilyOrAssembly as exposed surface, so that
        // accessibility would leak a BouncyCastle type and fail the build's guard test.
        Assert.False(getter.IsFamilyOrAssembly);
    }

    // ---- the three readable private-key forms (acceptance criteria 1 and 3) ----

    [Fact]
    public void LegacyEncryptedFixture_IsInTheTraditionalOpenSslFormat()
    {
        var pem = LegacyEncryptedPem();

        // Captured with the pre-PBES2 writer and committed, because the library no longer produces this format.
        // It is the only remaining proof that reading it still works.
        Assert.Contains("-----BEGIN RSA PRIVATE KEY-----", pem);
        Assert.Contains("Proc-Type: 4,ENCRYPTED", pem);
        Assert.Contains("DEK-Info: AES-256-CBC", pem);
    }

    [Fact]
    public void ImportPrivateKeyPem_UnencryptedPkcs8_Succeeds()
    {
        var key = RsaKey.ImportPrivateKeyPem(keys.PrivateKeyPem);

        Assert.True(key.HasPrivateKey);
        Assert.Equal(2048, key.KeySizeBits);
        Assert.True(Service().Verify(Payload, Service().Sign(Payload, key.ExportPrivateKeyPem()),
            key.ExportPublicKeyPem()));
    }

    [Fact]
    public void ImportPrivateKeyPem_LegacyTraditionalOpenSsl_Succeeds()
    {
        var key = RsaKey.ImportPrivateKeyPem(LegacyEncryptedPem(), LegacyFixturePassphrase.ToCharArray());

        Assert.True(key.HasPrivateKey);
        Assert.Equal(2048, key.KeySizeBits);
        Assert.True(Service().Verify(Payload, Service().Sign(Payload, key.ExportPrivateKeyPem()),
            key.ExportPublicKeyPem()));
    }

    [Fact]
    public void ImportPrivateKeyPem_Pbes2Fixture_Succeeds()
    {
        var key = RsaKey.ImportPrivateKeyPem(Pbes2FixturePem(), Pbes2FixturePassphrase.ToCharArray());

        Assert.True(key.HasPrivateKey);
        // pk_key1.pem is a 4096-bit key — a second, independent check that KeySizeBits reads the real modulus.
        Assert.Equal(4096, key.KeySizeBits);

        // The handle really holds the fixture's key: its signature verifies under the committed public half.
        var signature = Service().Sign(Payload, key.ExportPrivateKeyPem());
        Assert.True(Service().Verify(Payload, signature, Pbes2FixturePublicPem()));
    }

    [Fact]
    public void ImportPrivateKeyPem_DoesNotClearCallerPassword()
    {
        var password = LegacyFixturePassphrase.ToCharArray();
        RsaKey.ImportPrivateKeyPem(LegacyEncryptedPem(), password);

        Assert.Equal(LegacyFixturePassphrase.ToCharArray(), password);
    }

    // ---- written formats (acceptance criterion 5) ----

    [Fact]
    public void ExportPrivateKeyPem_NoPassword_EmitsUnencryptedPkcs8()
    {
        var pem = RsaKey.ImportPrivateKeyPem(keys.PrivateKeyPem).ExportPrivateKeyPem();

        Assert.Contains("-----BEGIN PRIVATE KEY-----", pem);
        Assert.DoesNotContain("ENCRYPTED", pem);
        Assert.DoesNotContain("RSA PRIVATE KEY", pem);
    }

    [Fact]
    public void ExportPrivateKeyPem_WithPassword_EmitsPbes2()
    {
        var pem = RsaKey.ImportPrivateKeyPem(keys.PrivateKeyPem)
            .ExportPrivateKeyPem("export-passphrase".ToCharArray());

        Assert.Contains("-----BEGIN ENCRYPTED PRIVATE KEY-----", pem);
        Assert.DoesNotContain("RSA PRIVATE KEY", pem);
        Assert.DoesNotContain("Proc-Type", pem);
        Assert.DoesNotContain("DEK-Info", pem);
    }

    [Fact]
    public void ExportPublicKeyPem_EmitsSubjectPublicKeyInfo()
    {
        var pem = RsaKey.ImportPublicKeyPem(keys.PublicKeyPem).ExportPublicKeyPem();

        Assert.Contains("-----BEGIN PUBLIC KEY-----", pem);
        Assert.DoesNotContain("PRIVATE", pem);
    }

    // ---- export → re-import equivalence (acceptance criterion 4) ----

    [Fact]
    public void ExportPrivateKeyPem_Unencrypted_ReImportsToAnEquivalentKey()
    {
        var original = RsaKey.ImportPrivateKeyPem(keys.PrivateKeyPem);

        AssertEquivalent(original, RsaKey.ImportPrivateKeyPem(original.ExportPrivateKeyPem()));
    }

    [Fact]
    public void ExportPrivateKeyPem_Encrypted_ReImportsToAnEquivalentKey()
    {
        var password = "round-trip-passphrase".ToCharArray();
        var original = RsaKey.ImportPrivateKeyPem(keys.PrivateKeyPem);

        var exported = original.ExportPrivateKeyPem(password);
        // The passphrase array survives the write and is reusable for the read — the library never clears it.
        Assert.Equal("round-trip-passphrase".ToCharArray(), password);

        AssertEquivalent(original, RsaKey.ImportPrivateKeyPem(exported, password));
    }

    // Two handles are equivalent when they sign identically (RSASSA-PKCS1-v1_5 is deterministic), when one
    // decrypts what the other's public half encrypted, and when they agree on the public key and its size.
    private static void AssertEquivalent(RsaKey expected, RsaKey actual)
    {
        var service = Service();

        Assert.Equal(
            service.Sign(Payload, expected.ExportPrivateKeyPem()),
            service.Sign(Payload, actual.ExportPrivateKeyPem()));

        var ciphertext = service.EncryptPkcs1(Payload, expected.ExportPublicKeyPem());
        Assert.Equal(Payload, service.DecryptPkcs1(ciphertext, actual.ExportPrivateKeyPem()));

        Assert.Equal(expected.ExportPublicKeyPem(), actual.ExportPublicKeyPem());
        Assert.Equal(expected.KeySizeBits, actual.KeySizeBits);
    }

    // ---- passphrase failure modes, on both encrypted formats (acceptance criterion 6) ----

    [Fact]
    public void ImportPrivateKeyPem_Pbes2_WrongPassword_ThrowsCryptographicException()
        => Assert.Throws<CryptographicException>(
            () => RsaKey.ImportPrivateKeyPem(Pbes2FixturePem(), "wrong-password".ToCharArray()));

    [Fact]
    public void ImportPrivateKeyPem_Pbes2_MissingPassword_ThrowsCryptographicException()
        => Assert.Throws<CryptographicException>(() => RsaKey.ImportPrivateKeyPem(Pbes2FixturePem()));

    [Fact]
    public void ImportPrivateKeyPem_Legacy_WrongPassword_ThrowsCryptographicException()
        => Assert.Throws<CryptographicException>(
            () => RsaKey.ImportPrivateKeyPem(LegacyEncryptedPem(), "wrong-password".ToCharArray()));

    [Fact]
    public void ImportPrivateKeyPem_Legacy_MissingPassword_ThrowsCryptographicException()
        => Assert.Throws<CryptographicException>(() => RsaKey.ImportPrivateKeyPem(LegacyEncryptedPem()));

    // ---- key metadata (acceptance criterion 7) ----

    [Theory]
    [InlineData(2048)]
    [InlineData(3072)]
    public void KeySizeBits_ReportsTheModulusSize(int keySizeBits)
    {
        var (publicKeyPem, privateKeyPem) = Service().GenerateRsaKeyPair(keySizeBits);

        Assert.Equal(keySizeBits, RsaKey.ImportPrivateKeyPem(privateKeyPem).KeySizeBits);
        Assert.Equal(keySizeBits, RsaKey.ImportPublicKeyPem(publicKeyPem).KeySizeBits);
    }

    [Fact]
    public void HasPrivateKey_DistinguishesTheTwoKindsOfHandle()
    {
        Assert.True(RsaKey.ImportPrivateKeyPem(keys.PrivateKeyPem).HasPrivateKey);
        Assert.False(RsaKey.ImportPublicKeyPem(keys.PublicKeyPem).HasPrivateKey);
    }

    // ---- public-only vs private handles (acceptance criterion 8) ----

    [Fact]
    public void ExportPrivateKeyPem_OnPublicOnlyHandle_ThrowsInvalidOperationException()
    {
        var key = RsaKey.ImportPublicKeyPem(keys.PublicKeyPem);

        // The fault is the handle's own state, not a caller argument — hence InvalidOperationException.
        Assert.Throws<InvalidOperationException>(() => key.ExportPrivateKeyPem());
        Assert.Throws<InvalidOperationException>(() => key.ExportPrivateKeyPem("any".ToCharArray()));
    }

    [Fact]
    public void ExportPublicKeyPem_OnPrivateHandle_DerivesTheVerifyingPublicHalf()
    {
        var key = RsaKey.ImportPrivateKeyPem(keys.PrivateKeyPem);

        var derivedPublicPem = key.ExportPublicKeyPem();
        var signature = Service().Sign(Payload, key.ExportPrivateKeyPem());

        Assert.Contains("-----BEGIN PUBLIC KEY-----", derivedPublicPem);
        Assert.True(Service().Verify(Payload, signature, derivedPublicPem));
        // ...and it is the same public key the generator handed out alongside the private one.
        Assert.Equal(keys.PublicKeyPem, derivedPublicPem);
    }

    // ---- argument guards (acceptance criterion 9) ----

    [Fact]
    public void ImportPublicKeyPem_NullPem_ThrowsArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => RsaKey.ImportPublicKeyPem(null!));

    [Fact]
    public void ImportPrivateKeyPem_NullPem_ThrowsArgumentNullException()
        => Assert.Throws<ArgumentNullException>(() => RsaKey.ImportPrivateKeyPem(null!));

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a pem at all")]
    [InlineData("-----BEGIN PUBLIC KEY-----\nnot base64!!\n-----END PUBLIC KEY-----")]
    public void ImportPublicKeyPem_EmptyOrMalformedPem_ThrowsArgumentExceptionNamingThePem(string pem)
        => Assert.Equal("pem", Assert.Throws<ArgumentException>(() => RsaKey.ImportPublicKeyPem(pem)).ParamName);

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a pem at all")]
    [InlineData("-----BEGIN PRIVATE KEY-----\nnot base64!!\n-----END PRIVATE KEY-----")]
    public void ImportPrivateKeyPem_EmptyOrMalformedPem_ThrowsArgumentExceptionNamingThePem(string pem)
        => Assert.Equal("pem", Assert.Throws<ArgumentException>(() => RsaKey.ImportPrivateKeyPem(pem)).ParamName);

    [Fact]
    public void ImportPublicKeyPem_PrivateKeyPem_ThrowsArgumentExceptionNamingThePem()
        => Assert.Equal("pem",
            Assert.Throws<ArgumentException>(() => RsaKey.ImportPublicKeyPem(keys.PrivateKeyPem)).ParamName);

    [Fact]
    public void ImportPrivateKeyPem_PublicKeyPem_ThrowsArgumentExceptionNamingThePem()
        => Assert.Equal("pem",
            Assert.Throws<ArgumentException>(() => RsaKey.ImportPrivateKeyPem(keys.PublicKeyPem)).ParamName);

    [Fact]
    public void ImportPublicKeyPem_NonRsaKeyPem_ThrowsArgumentExceptionNamingThePem()
    {
        // A structurally valid PEM carrying a key of another family: the handle is RSA-only, and rejecting it
        // here is what keeps a non-RSA key from reaching an RSA cipher.
        var (publicKeyPem, _) = new MLDsaPemServiceFactory().CreateMLDsaPemService()
            .GenerateKeyPairPem(MLDsaParameterSet.MLDsa44);

        Assert.Equal("pem",
            Assert.Throws<ArgumentException>(() => RsaKey.ImportPublicKeyPem(publicKeyPem)).ParamName);
    }

    [Fact]
    public void ImportPrivateKeyPem_NonRsaKeyPem_ThrowsArgumentExceptionNamingThePem()
    {
        var (_, privateKeyPem) = new MLDsaPemServiceFactory().CreateMLDsaPemService()
            .GenerateKeyPairPem(MLDsaParameterSet.MLDsa44);

        Assert.Equal("pem",
            Assert.Throws<ArgumentException>(() => RsaKey.ImportPrivateKeyPem(privateKeyPem)).ParamName);
    }
}
