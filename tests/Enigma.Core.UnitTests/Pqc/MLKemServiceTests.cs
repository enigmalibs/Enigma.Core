using System;
using System.Linq;
using System.Security.Cryptography;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// Round-trip, private-key re-injection, wrong-key and failure-mode behaviour of the ML-KEM service across all
/// three parameter sets. Keys, ciphertexts and shared secrets are all raw <see cref="byte"/> arrays.
/// </summary>
public class MLKemServiceTests
{
    private static readonly IMLKemServiceFactory Factory = new MLKemServiceFactory();

    [Theory]
    [InlineData(MLKemParameterSet.MLKem512)]
    [InlineData(MLKemParameterSet.MLKem768)]
    [InlineData(MLKemParameterSet.MLKem1024)]
    public void GenerateEncapsulateDecapsulate_RecoversSharedSecret(MLKemParameterSet parameterSet)
    {
        var service = Factory.CreateMLKemService(parameterSet);
        var (publicKey, privateKey) = service.GenerateKeyPair();

        var (ciphertext, sharedSecret) = service.Encapsulate(publicKey);
        var recovered = service.Decapsulate(ciphertext, privateKey);

        Assert.Equal(sharedSecret, recovered);
    }

    [Fact]
    public void GeneratedPrivateKey_IsAcceptedBackByDecapsulate_EncodeReinjectRoundTrip()
    {
        // Proves the expanded decapsulation-key byte[] produced by GenerateKeyPair round-trips straight into
        // Decapsulate (criterion 7): the key is only ever handled as bytes.
        var service = Factory.CreateMLKemService(MLKemParameterSet.MLKem768);
        var (publicKey, privateKey) = service.GenerateKeyPair();

        var (ciphertext, sharedSecret) = service.Encapsulate(publicKey);
        var recovered = service.Decapsulate(ciphertext, privateKey);

        Assert.Equal(sharedSecret, recovered);
    }

    [Fact]
    public void Decapsulate_WrongPrivateKey_DoesNotRecoverSharedSecret()
    {
        // FIPS 203 implicit rejection: decapsulating with an unrelated (well-formed) key yields a different
        // secret rather than throwing.
        var service = Factory.CreateMLKemService(MLKemParameterSet.MLKem1024);
        var (publicKey, _) = service.GenerateKeyPair();
        var (_, otherPrivateKey) = service.GenerateKeyPair();

        var (ciphertext, sharedSecret) = service.Encapsulate(publicKey);
        var recovered = service.Decapsulate(ciphertext, otherPrivateKey);

        Assert.NotEqual(sharedSecret, recovered);
    }

    [Fact]
    public void Encapsulate_ProducesFreshSecretPerCall()
    {
        var service = Factory.CreateMLKemService(MLKemParameterSet.MLKem768);
        var (publicKey, _) = service.GenerateKeyPair();

        var (_, first) = service.Encapsulate(publicKey);
        var (_, second) = service.Encapsulate(publicKey);

        Assert.False(first.SequenceEqual(second));
    }

    // ---- argument guards ----

    [Fact]
    public void Encapsulate_NullPublicKey_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => Factory.CreateMLKemService().Encapsulate(null!));

    [Fact]
    public void Decapsulate_NullCiphertext_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => Factory.CreateMLKemService().Decapsulate(null!, new byte[] { 1 }));

    [Fact]
    public void Decapsulate_NullPrivateKey_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => Factory.CreateMLKemService().Decapsulate(new byte[] { 1 }, null!));

    // ---- malformed input surfaces as CryptographicException (no BouncyCastle exception escapes) ----

    [Fact]
    public void Encapsulate_MalformedPublicKey_ThrowsCryptographicException()
        => Assert.Throws<CryptographicException>(
            () => Factory.CreateMLKemService().Encapsulate(new byte[] { 1, 2, 3 }));

    [Fact]
    public void Decapsulate_MalformedPrivateKey_ThrowsCryptographicException()
    {
        // A well-formed ciphertext against a malformed private key: the key reconstruction fails and must surface
        // as CryptographicException.
        var service = Factory.CreateMLKemService(MLKemParameterSet.MLKem768);
        var (publicKey, _) = service.GenerateKeyPair();
        var (ciphertext, _) = service.Encapsulate(publicKey);

        Assert.Throws<CryptographicException>(() => service.Decapsulate(ciphertext, new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public void Decapsulate_MalformedCiphertext_ThrowsCryptographicException()
    {
        var service = Factory.CreateMLKemService(MLKemParameterSet.MLKem768);
        var (_, privateKey) = service.GenerateKeyPair();

        Assert.Throws<CryptographicException>(() => service.Decapsulate(new byte[] { 1, 2, 3 }, privateKey));
    }
}
