using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Enigma.Core.Asymmetric.Pqc;
using Enigma.Core.Asymmetric.PublicKey;
using Xunit;
// Test-only BouncyCastle use, mirroring the CRL tests: PHASE01 ships no ML-KEM PEM service (that is PHASE02), so
// the "a valid PEM of the wrong key family" fixtures are built directly with BouncyCastle. Bound through aliases
// because Org.BouncyCastle.Crypto.Parameters publishes its own MLKemParameterSet type, whose unqualified name
// would collide with Enigma.Core's public enum of the same name.
using BcMLKemKeyGenerationParameters = Org.BouncyCastle.Crypto.Parameters.MLKemKeyGenerationParameters;
using BcMLKemKeyPairGenerator = Org.BouncyCastle.Crypto.Generators.MLKemKeyPairGenerator;
using BcMLKemParameters = Org.BouncyCastle.Crypto.Parameters.MLKemParameters;
using BcPemObject = Org.BouncyCastle.Utilities.IO.Pem.PemObject;
using BcPemWriter = Org.BouncyCastle.Utilities.IO.Pem.PemWriter;
using BcPrivateKeyInfoFactory = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory;
using BcSecureRandom = Org.BouncyCastle.Security.SecureRandom;
using BcSubjectPublicKeyInfoFactory = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// Failure modes of the ML-DSA PEM service: null guards, undefined enum values, PEMs that are structurally broken
/// or carry the wrong kind of key, key bytes of the wrong length, and the two password paths. Also pins that no
/// BouncyCastle exception type ever reaches a caller. Backs PHASE01 acceptance criteria 11-13 and the error half
/// of criterion 8.
/// </summary>
public class MLDsaPemErrorTests
{
    private static readonly IMLDsaPemService Pem = new MLDsaPemServiceFactory().CreateMLDsaPemService();

    private const string Passphrase = "correct horse battery staple";
    private const MLDsaParameterSet Set = MLDsaParameterSet.MLDsa65;

    // Generated once per class: an unencrypted pair, plus an encrypted PEM (600 000 PBKDF2 iterations, ~0.6 s).
    private static readonly Lazy<(string PublicKeyPem, string PrivateKeyPem)> Pair =
        new(() => Pem.GenerateKeyPairPem(Set));

    private static readonly Lazy<string> EncryptedPrivateKeyPem =
        new(() => Pem.GenerateKeyPairPem(Set, Passphrase.ToCharArray()).privateKeyPem);

    // ---- null arguments (criterion 12) ----

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

    // ---- undefined enum values (criterion 12) ----

    [Fact]
    public void GenerateKeyPairPem_UndefinedParameterSet_Throws()
        => Assert.Throws<ArgumentOutOfRangeException>(() => Pem.GenerateKeyPairPem((MLDsaParameterSet)999));

    [Fact]
    public void GenerateKeyPairPem_UndefinedFormat_Throws()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => Pem.GenerateKeyPairPem(Set, format: (MLPrivateKeyPemFormat)999));

    [Fact]
    public void ToPublicKeyPem_UndefinedParameterSet_Throws()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => Pem.ToPublicKeyPem(new byte[1952], (MLDsaParameterSet)999));

    [Fact]
    public void ToPrivateKeyPem_UndefinedParameterSet_Throws()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => Pem.ToPrivateKeyPem(new byte[4032], (MLDsaParameterSet)999));

    // ---- key bytes of the wrong length or parameter set (criterion 11) ----

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
        // An ML-DSA-44 public key is 1312 bytes; declaring it as ML-DSA-65 (1952) is a length mismatch.
        var (publicKey, _) = new MLDsaServiceFactory()
            .CreateMLDsaService(MLDsaParameterSet.MLDsa44).GenerateKeyPair();

        var ex = Assert.Throws<ArgumentException>(() => Pem.ToPublicKeyPem(publicKey, MLDsaParameterSet.MLDsa65));
        Assert.Equal("publicKey", ex.ParamName);
    }

    // ---- structurally broken PEMs (criterion 11) ----

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

    // ---- a valid PEM carrying the wrong kind of key (criterion 11) ----

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
    public void FromPublicKeyPem_MLKemPublicKeyPem_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => Pem.FromPublicKeyPem(MLKemPems().PublicKeyPem));
        Assert.Equal("pem", ex.ParamName);
    }

    [Fact]
    public void FromPrivateKeyPem_MLKemPrivateKeyPem_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() => Pem.FromPrivateKeyPem(MLKemPems().PrivateKeyPem));
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

    // ---- password paths (criterion 8) ----

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
        Assert.Equal(4032, privateKey.Length);
    }

    // ---- no BouncyCastle exception escapes (criterion 13) ----

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
        var (publicKeyPem, privateKeyPem) =
            new PublicKeyServiceFactory().CreatePublicKeyService().GenerateRsaKeyPair(2048);
        return (publicKeyPem, privateKeyPem);
    }

    private static (string PublicKeyPem, string PrivateKeyPem) MLKemPems()
    {
        var generator = new BcMLKemKeyPairGenerator();
        generator.Init(new BcMLKemKeyGenerationParameters(new BcSecureRandom(), BcMLKemParameters.ml_kem_768));
        var pair = generator.GenerateKeyPair();

        return (WritePem("PUBLIC KEY", BcSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pair.Public).GetDerEncoded()),
                WritePem("PRIVATE KEY", BcPrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetDerEncoded()));
    }

    private static string WritePem(string label, byte[] der)
    {
        using var writer = new StringWriter();
        new BcPemWriter(writer).WriteObject(new BcPemObject(label, der));
        return writer.ToString();
    }
}
