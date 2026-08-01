using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// Pins the ML-KEM wire encodings the public service hands out: the exact FIPS 203 key, ciphertext and
/// shared-secret sizes for every parameter set, plus the guarantee that the private key is the <em>expanded</em>
/// decapsulation key and never a seed. The fixed-vector tests prove a pinned key still works; these prove a
/// freshly generated one is encoded the same way it always was, so an upstream default flipping to a seed-based
/// encoding (which would still round-trip, while breaking every persisted key) surfaces as a red test.
/// </summary>
public class MLKemEncodingContractTests
{
    private static readonly IMLKemServiceFactory Factory = new MLKemServiceFactory();

    // ML-KEM seed encodings are 32 or 64 bytes; a decapsulation key is never either.
    private const int SeedLength32 = 32;
    private const int SeedLength64 = 64;

    [Theory]
    [InlineData(MLKemParameterSet.MLKem512, 800, 1632, 768, 32)]
    [InlineData(MLKemParameterSet.MLKem768, 1184, 2400, 1088, 32)]
    [InlineData(MLKemParameterSet.MLKem1024, 1568, 3168, 1568, 32)]
    public void GenerateEncapsulateDecapsulate_ProducesFipsEncodingSizes(
        MLKemParameterSet parameterSet,
        int publicKeyLength,
        int privateKeyLength,
        int ciphertextLength,
        int sharedSecretLength)
    {
        var service = Factory.CreateMLKemService(parameterSet);
        var (publicKey, privateKey) = service.GenerateKeyPair();

        var (ciphertext, sharedSecret) = service.Encapsulate(publicKey);
        var recovered = service.Decapsulate(ciphertext, privateKey);

        Assert.Equal(publicKeyLength, publicKey.Length);
        Assert.Equal(privateKeyLength, privateKey.Length);
        Assert.Equal(ciphertextLength, ciphertext.Length);
        Assert.Equal(sharedSecretLength, sharedSecret.Length);
        Assert.Equal(sharedSecret, recovered);
    }

    [Theory]
    [InlineData(MLKemParameterSet.MLKem512)]
    [InlineData(MLKemParameterSet.MLKem768)]
    [InlineData(MLKemParameterSet.MLKem1024)]
    public void GenerateKeyPair_PrivateKeyIsExpandedNotSeed(MLKemParameterSet parameterSet)
    {
        var (_, privateKey) = Factory.CreateMLKemService(parameterSet).GenerateKeyPair();

        Assert.NotEqual(SeedLength32, privateKey.Length);
        Assert.NotEqual(SeedLength64, privateKey.Length);
    }
}
