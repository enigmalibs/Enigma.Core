using System;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// Factory behaviour for ML-KEM: it returns concrete <see cref="MLKemService"/> instances, defaults to
/// <see cref="MLKemParameterSet.MLKem768"/>, maps each parameter set to the matching BouncyCastle security level
/// (verified through the FIPS 203 public-key size, which is unique per set), and rejects undefined enum values.
/// Backs acceptance criterion 8.
/// </summary>
public class MLKemServiceFactoryTests
{
    private readonly IMLKemServiceFactory _factory = new MLKemServiceFactory();

    [Fact]
    public void CreateMLKemService_ReturnsMLKemService()
        => Assert.IsType<MLKemService>(_factory.CreateMLKemService());

    [Fact]
    public void CreateMLKemService_ReturnsFreshInstancePerCall()
        => Assert.NotSame(_factory.CreateMLKemService(), _factory.CreateMLKemService());

    [Fact]
    public void CreateMLKemService_DefaultsToMLKem768()
    {
        // The default overload must select ML-KEM-768: its public key is 1184 bytes.
        var (publicKey, _) = _factory.CreateMLKemService().GenerateKeyPair();
        Assert.Equal(1184, publicKey.Length);
    }

    [Theory]
    [InlineData(MLKemParameterSet.MLKem512, 800)]
    [InlineData(MLKemParameterSet.MLKem768, 1184)]
    [InlineData(MLKemParameterSet.MLKem1024, 1568)]
    public void CreateMLKemService_MapsParameterSetToSecurityLevel(MLKemParameterSet parameterSet, int publicKeyLength)
    {
        // The FIPS 203 public-key length is distinct per parameter set, so matching it proves the enum mapped to
        // the intended ml_kem_512 / ml_kem_768 / ml_kem_1024 internally.
        var (publicKey, _) = _factory.CreateMLKemService(parameterSet).GenerateKeyPair();
        Assert.Equal(publicKeyLength, publicKey.Length);
    }

    [Fact]
    public void CreateMLKemService_UndefinedParameterSet_ThrowsArgumentOutOfRange()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => _factory.CreateMLKemService((MLKemParameterSet)999));
}
