using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// Failure modes of the ML-KEM PEM service: null guards, undefined enum values, PEMs that are structurally broken
/// or carry the wrong kind of key, key bytes of the wrong length, and the two password paths. Also pins that no
/// BouncyCastle exception type ever reaches a caller. Mirrors <see cref="MLDsaPemErrorTests"/>; backs PHASE02
/// acceptance criterion 2 (PHASE01 criteria 11-13 and the error half of criterion 8).
/// </summary>
public class MLKemPemErrorTests
{
    private static readonly IMLKemPemService Pem = new MLKemPemServiceFactory().CreateMLKemPemService();

    private const string Passphrase = "correct horse battery staple";
    private const MLKemParameterSet Set = MLKemParameterSet.MLKem768;

    // Generated once per class: an unencrypted pair, plus an encrypted PEM (600 000 PBKDF2 iterations, ~0.6 s).
    private static readonly Lazy<(string PublicKeyPem, string PrivateKeyPem)> Pair =
        new(() => Pem.GenerateKeyPairPem(Set));

    private static readonly Lazy<string> EncryptedPrivateKeyPem =
        new(() => Pem.GenerateKeyPairPem(Set, Passphrase.ToCharArray()).privateKeyPem);

    // ---- null arguments ----

    [Fact]
    public void ToPublicKeyPem_NullKey_Throws()
        => Assert.Throws<ArgumentNullException>(() => Pem.ToPublicKeyPem(null!, Set));

    [Fact]
    public void ToPrivateKeyPem_NullKey_Throws()
        => Assert.Throws<ArgumentNullException>(() => Pem.ToPrivateKeyPem(null!, Set));

    [Fact]
    public void FromPublicKeyPem_NullPem_Throws()
        => Assert.Throws<ArgumentNullException>(() => Pem.FromPublicKeyPem(null!));

    [Fact]
    public void FromPrivateKeyPem_NullPem_Throws()
        => Assert.Throws<ArgumentNullException>(() => Pem.FromPrivateKeyPem(null!));

    // ---- undefined enum values ----

    [Fact]
    public void GenerateKeyPairPem_UndefinedParameterSet_Throws()
        => Assert.Throws<ArgumentOutOfRangeException>(() => Pem.GenerateKeyPairPem((MLKemParameterSet)999));

    [Fact]
    public void GenerateKeyPairPem_UndefinedFormat_Throws()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => Pem.GenerateKeyPairPem(Set, format: (MLPrivateKeyPemFormat)999));

    [Fact]
    public void ToPublicKeyPem_UndefinedParameterSet_Throws()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => Pem.ToPublicKeyPem(new byte[1184], (MLKemParameterSet)999));

    [Fact]
    public void ToPrivateKeyPem_UndefinedParameterSet_Throws()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => Pem.ToPrivateKeyPem(new byte[2400], (MLKemParameterSet)999));

    // ---- key bytes of the wrong length or parameter set ----

    [Fact]
    public void ToPublicKeyPem_WrongLengthKey_ThrowsArgumentExceptionNamingTheKey()
    {
        var ex = Assert.Throws<ArgumentException>(() => Pem.ToPublicKeyPem(new byte[7], Set));
        Assert.Equal("publicKey", ex.ParamName);
    }

    [Fact]
    public void ToPrivateKeyPem_WrongLengthKey_ThrowsArgumentExceptionNamingTheKey()
    {
        var ex = Assert.Throws<ArgumentException>(() => Pem.ToPrivateKeyPem(new byte[7], Set));
        Assert.Equal("privateKey", ex.ParamName);
    }

    [Fact]
    public void ToPublicKeyPem_KeyForADifferentParameterSet_Throws()
    {
        // An ML-KEM-512 public key is 800 bytes; declaring it as ML-KEM-768 (1184) is a length mismatch.
        var (publicKey, _) = new MLKemServiceFactory()
            .CreateMLKemService(MLKemParameterSet.MLKem512).GenerateKeyPair();

        var ex = Assert.Throws<ArgumentException>(() => Pem.ToPublicKeyPem(publicKey, MLKemParameterSet.MLKem768));
        Assert.Equal("publicKey", ex.ParamName);
    }

    // ---- structurally broken PEMs ----

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a pem at all")]
    [InlineData("-----BEGIN PUBLIC KEY-----\nMIIB\n")]
    [InlineData("-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n")]
    public void FromPublicKeyPem_MalformedPem_ThrowsArgumentExceptionNamingThePem(string pem)
    {
        var ex = Assert.Throws<ArgumentException>(() => Pem.FromPublicKeyPem(pem));
        Assert.Equal("pem", ex.ParamName);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not a pem at all")]
    [InlineData("-----BEGIN PRIVATE KEY-----\nMIIB\n")]
    [InlineData("-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n")]
    public void FromPrivateKeyPem_MalformedPem_ThrowsArgumentExceptionNamingThePem(string pem)
    {
        var ex = Assert.Throws<ArgumentException>(() => Pem.FromPrivateKeyPem(pem));
        Assert.Equal("pem", ex.ParamName);
    }

    [Fact]
    public void FromPrivateKeyPem_EncryptedLabelOverGarbageDer_ThrowsArgumentExceptionNamingThePem()
    {
        // A well-formed envelope whose payload is not an EncryptedPrivateKeyInfo: structurally invalid, so it is a
        // malformed PEM rather than a decryption failure — and it must still name the offending parameter.
        var mislabelled = Pair.Value.PrivateKeyPem
            .Replace("BEGIN PRIVATE KEY", "BEGIN ENCRYPTED PRIVATE KEY")
            .Replace("END PRIVATE KEY", "END ENCRYPTED PRIVATE KEY");

        var ex = Assert.Throws<ArgumentException>(
            () => Pem.FromPrivateKeyPem(mislabelled, Passphrase.ToCharArray()));
        Assert.Equal("pem", ex.ParamName);
    }

    // ---- a valid PEM carrying the wrong kind of key ----

    [Fact]
    public void FromPublicKeyPem_PrivateKeyPem_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => Pem.FromPublicKeyPem(Pair.Value.PrivateKeyPem));
        Assert.Equal("pem", ex.ParamName);
    }

    [Fact]
    public void FromPrivateKeyPem_PublicKeyPem_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => Pem.FromPrivateKeyPem(Pair.Value.PublicKeyPem));
        Assert.Equal("pem", ex.ParamName);
    }

    [Fact]
    public void FromPublicKeyPem_MLDsaPublicKeyPem_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => Pem.FromPublicKeyPem(MLDsaPems().PublicKeyPem));
        Assert.Equal("pem", ex.ParamName);
    }

    [Fact]
    public void FromPrivateKeyPem_MLDsaPrivateKeyPem_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => Pem.FromPrivateKeyPem(MLDsaPems().PrivateKeyPem));
        Assert.Equal("pem", ex.ParamName);
    }

    [Fact]
    public void FromPublicKeyPem_RsaPublicKeyPem_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => Pem.FromPublicKeyPem(RsaPems().PublicKeyPem));
        Assert.Equal("pem", ex.ParamName);
    }

    [Fact]
    public void FromPrivateKeyPem_RsaPrivateKeyPem_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => Pem.FromPrivateKeyPem(RsaPems().PrivateKeyPem));
        Assert.Equal("pem", ex.ParamName);
    }

    // ---- password paths ----

    [Fact]
    public void FromPrivateKeyPem_EncryptedPem_NoPassword_ThrowsCryptographic()
        => Assert.Throws<CryptographicException>(() => Pem.FromPrivateKeyPem(EncryptedPrivateKeyPem.Value));

    [Fact]
    public void FromPrivateKeyPem_EncryptedPem_WrongPassword_ThrowsCryptographic()
        => Assert.Throws<CryptographicException>(
            () => Pem.FromPrivateKeyPem(EncryptedPrivateKeyPem.Value, "wrong password".ToCharArray()));

    [Fact]
    public void FromPrivateKeyPem_UnencryptedPem_WithPassword_Succeeds()
    {
        // A supplied password is simply unused when the PEM is not encrypted; it must not become an error.
        var (privateKey, parameterSet) =
            Pem.FromPrivateKeyPem(Pair.Value.PrivateKeyPem, Passphrase.ToCharArray());

        Assert.Equal(Set, parameterSet);
        Assert.Equal(2400, privateKey.Length);
    }

    // ---- no BouncyCastle exception escapes ----

    [Fact]
    public void NoPublicMethod_LeaksABouncyCastleExceptionType()
    {
        var paths = new Dictionary<string, Action>
        {
            ["wrong password"] = () =>
                Pem.FromPrivateKeyPem(EncryptedPrivateKeyPem.Value, "wrong password".ToCharArray()),
            ["missing password"] = () => Pem.FromPrivateKeyPem(EncryptedPrivateKeyPem.Value),
            ["malformed private-key PEM"] = () => Pem.FromPrivateKeyPem("-----BEGIN PRIVATE KEY-----\nMIIB\n"),
            ["malformed public-key PEM"] = () => Pem.FromPublicKeyPem("not a pem at all"),
            ["invalid base64 body"] = () =>
                Pem.FromPrivateKeyPem("-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n"),
            ["wrong-length public key"] = () => Pem.ToPublicKeyPem(new byte[7], Set),
            ["wrong-length private key"] = () => Pem.ToPrivateKeyPem(new byte[7], Set),
        };

        foreach (var (description, action) in paths)
        {
            var ex = Record.Exception(action);

            Assert.NotNull(ex);
            Assert.False(IsBouncyCastleType(ex!.GetType()),
                $"The '{description}' path surfaced {ex.GetType().FullName}, a BouncyCastle exception type.");

            // The BouncyCastle failure may — and should — survive as the InnerException; it just must not be the
            // exception the caller catches.
            Assert.True(ex is ArgumentException or CryptographicException,
                $"The '{description}' path surfaced an unexpected {ex.GetType().FullName}.");
        }
    }

    private static bool IsBouncyCastleType(Type type) =>
        type.Namespace is { } ns &&
        (ns == "Org.BouncyCastle" || ns.StartsWith("Org.BouncyCastle.", StringComparison.Ordinal));

    // ---- fixtures for the wrong-key-family cases ----

    private static (string PublicKeyPem, string PrivateKeyPem) RsaPems()
    {
        var rsaKey = new PublicKeyServiceFactory().CreatePublicKeyService().GenerateRsaKey(2048);
        return (rsaKey.ExportPublicKeyPem(), rsaKey.ExportPrivateKeyPem());
    }

    // The sibling family's real PEM service, so the fixture is exactly the file a user would hand over — no
    // test-only BouncyCastle needed now that both families ship one.
    private static (string PublicKeyPem, string PrivateKeyPem) MLDsaPems()
        => new MLDsaPemServiceFactory().CreateMLDsaPemService()
            .GenerateKeyPairPem(MLDsaParameterSet.MLDsa65, format: MLPrivateKeyPemFormat.ExpandedKey);
}
