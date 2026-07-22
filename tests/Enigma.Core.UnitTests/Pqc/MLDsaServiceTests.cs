using System;
using System.Security.Cryptography;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// Round-trip, deterministic-signing, private-key re-injection and failure-mode behaviour of the ML-DSA service
/// across all three parameter sets. Keys, signatures and messages are all raw <see cref="byte"/> arrays.
/// </summary>
public class MLDsaServiceTests
{
    private static readonly IMLDsaServiceFactory Factory = new MLDsaServiceFactory();
    private static byte[] Message(string s) => System.Text.Encoding.UTF8.GetBytes(s);

    [Theory]
    [InlineData(MLDsaParameterSet.MLDsa44)]
    [InlineData(MLDsaParameterSet.MLDsa65)]
    [InlineData(MLDsaParameterSet.MLDsa87)]
    public void GenerateSignVerify_RoundTrips(MLDsaParameterSet parameterSet)
    {
        var service = Factory.CreateMLDsaService(parameterSet);
        var (publicKey, privateKey) = service.GenerateKeyPair();

        var message = Message($"ML-DSA {parameterSet} round-trip message");
        var signature = service.Sign(message, privateKey);

        Assert.True(service.Verify(message, signature, publicKey));
    }

    [Fact]
    public void GeneratedPrivateKey_IsAcceptedBackBySign_EncodeReinjectRoundTrip()
    {
        // Proves the expanded-key byte[] produced by GenerateKeyPair round-trips straight into Sign (criterion 7):
        // the key is only ever handled as bytes between generation and signing.
        var service = Factory.CreateMLDsaService(MLDsaParameterSet.MLDsa65);
        var (publicKey, privateKey) = service.GenerateKeyPair();

        var message = Message("encode/re-inject");
        var signature = service.Sign(message, privateKey);

        Assert.True(service.Verify(message, signature, publicKey));
    }

    [Fact]
    public void Sign_Deterministic_ProducesIdenticalSignatures()
    {
        var service = Factory.CreateMLDsaService(MLDsaParameterSet.MLDsa44, deterministic: true);
        var (publicKey, privateKey) = service.GenerateKeyPair();
        var message = Message("Deterministic signing test");

        var first = service.Sign(message, privateKey);
        var second = service.Sign(message, privateKey);

        Assert.Equal(first, second);
        Assert.True(service.Verify(message, first, publicKey));
    }

    [Fact]
    public void Sign_Hedged_ProducesDifferingSignatures_ThatStillVerify()
    {
        // Default (deterministic: false) is hedged: fresh randomness per call, so signatures differ while both
        // remain valid.
        var service = Factory.CreateMLDsaService(MLDsaParameterSet.MLDsa44);
        var (publicKey, privateKey) = service.GenerateKeyPair();
        var message = Message("Hedged signing test");

        var first = service.Sign(message, privateKey);
        var second = service.Sign(message, privateKey);

        Assert.NotEqual(first, second);
        Assert.True(service.Verify(message, first, publicKey));
        Assert.True(service.Verify(message, second, publicKey));
    }

    [Fact]
    public void Verify_TamperedMessage_ReturnsFalse()
    {
        var service = Factory.CreateMLDsaService(MLDsaParameterSet.MLDsa65);
        var (publicKey, privateKey) = service.GenerateKeyPair();

        var message = Message("original message");
        var signature = service.Sign(message, privateKey);

        Assert.False(service.Verify(Message("tampered message"), signature, publicKey));
    }

    [Fact]
    public void Verify_TamperedSignature_ReturnsFalse()
    {
        var service = Factory.CreateMLDsaService(MLDsaParameterSet.MLDsa65);
        var (publicKey, privateKey) = service.GenerateKeyPair();

        var message = Message("message to sign");
        var signature = service.Sign(message, privateKey);
        signature[0] ^= 0xFF;

        Assert.False(service.Verify(message, signature, publicKey));
    }

    [Fact]
    public void Verify_WrongKey_ReturnsFalse()
    {
        var service = Factory.CreateMLDsaService(MLDsaParameterSet.MLDsa65);
        var (_, privateKey) = service.GenerateKeyPair();
        var (otherPublicKey, _) = service.GenerateKeyPair();

        var message = Message("cross-key message");
        var signature = service.Sign(message, privateKey);

        Assert.False(service.Verify(message, signature, otherPublicKey));
    }

    // ---- argument guards ----

    [Fact]
    public void Sign_NullMessage_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => Factory.CreateMLDsaService().Sign(null!, new byte[] { 1 }));

    [Fact]
    public void Sign_NullPrivateKey_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => Factory.CreateMLDsaService().Sign(new byte[] { 1 }, null!));

    [Fact]
    public void Verify_NullMessage_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => Factory.CreateMLDsaService().Verify(null!, new byte[] { 1 }, new byte[] { 1 }));

    [Fact]
    public void Verify_NullSignature_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => Factory.CreateMLDsaService().Verify(new byte[] { 1 }, null!, new byte[] { 1 }));

    [Fact]
    public void Verify_NullPublicKey_Throws()
        => Assert.Throws<ArgumentNullException>(
            () => Factory.CreateMLDsaService().Verify(new byte[] { 1 }, new byte[] { 1 }, null!));

    // ---- malformed key surfaces as CryptographicException (no BouncyCastle exception escapes) ----

    [Fact]
    public void Sign_MalformedPrivateKey_ThrowsCryptographicException()
        => Assert.Throws<CryptographicException>(
            () => Factory.CreateMLDsaService().Sign(Message("m"), new byte[] { 1, 2, 3 }));

    [Fact]
    public void Verify_MalformedPublicKey_ThrowsCryptographicException()
        => Assert.Throws<CryptographicException>(
            () => Factory.CreateMLDsaService().Verify(Message("m"), new byte[] { 1, 2, 3 }, new byte[] { 4, 5, 6 }));
}
