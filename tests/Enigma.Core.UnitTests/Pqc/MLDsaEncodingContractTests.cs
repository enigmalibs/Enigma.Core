using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// Pins the ML-DSA wire encodings the public service hands out: the exact FIPS 204 key sizes for every parameter
/// set, plus the guarantee that the private key is the <em>expanded</em> signing key and never a seed. The
/// fixed-vector tests prove a pinned key still verifies; these prove a freshly generated one is encoded the same
/// way it always was, so an upstream default flipping to a seed-based encoding (which would still round-trip,
/// while breaking every persisted key) surfaces as a red test.
/// </summary>
public class MLDsaEncodingContractTests
{
    private static readonly IMLDsaServiceFactory Factory = new MLDsaServiceFactory();
    private static byte[] Message(string s) => System.Text.Encoding.UTF8.GetBytes(s);

    // ML-DSA seed encodings are 32 bytes (and 64 for a seed pair); a signing key is never either.
    private const int SeedLength32 = 32;
    private const int SeedLength64 = 64;

    [Theory]
    [InlineData(MLDsaParameterSet.MLDsa44, 1312, 2560)]
    [InlineData(MLDsaParameterSet.MLDsa65, 1952, 4032)]
    [InlineData(MLDsaParameterSet.MLDsa87, 2592, 4896)]
    public void GenerateKeyPair_ProducesFipsEncodingSizes(
        MLDsaParameterSet parameterSet,
        int publicKeyLength,
        int privateKeyLength)
    {
        var service = Factory.CreateMLDsaService(parameterSet);
        var (publicKey, privateKey) = service.GenerateKeyPair();

        var message = Message($"ML-DSA {parameterSet} encoding contract");
        var signature = service.Sign(message, privateKey);

        Assert.Equal(publicKeyLength, publicKey.Length);
        Assert.Equal(privateKeyLength, privateKey.Length);
        Assert.True(service.Verify(message, signature, publicKey));
    }

    [Theory]
    [InlineData(MLDsaParameterSet.MLDsa44)]
    [InlineData(MLDsaParameterSet.MLDsa65)]
    [InlineData(MLDsaParameterSet.MLDsa87)]
    public void GenerateKeyPair_PrivateKeyIsExpandedNotSeed(MLDsaParameterSet parameterSet)
    {
        var (_, privateKey) = Factory.CreateMLDsaService(parameterSet).GenerateKeyPair();

        Assert.NotEqual(SeedLength32, privateKey.Length);
        Assert.NotEqual(SeedLength64, privateKey.Length);
    }
}
