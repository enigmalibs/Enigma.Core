using System;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// Factory behaviour for ML-DSA: it returns concrete <see cref="MLDsaService"/> instances, defaults to
/// <see cref="MLDsaParameterSet.MLDsa65"/>, maps each parameter set to the matching BouncyCastle security level
/// (verified through the FIPS 204 public-key size, which is unique per set), and rejects undefined enum values.
/// Backs acceptance criterion 8.
/// </summary>
public class MLDsaServiceFactoryTests
{
    private readonly IMLDsaServiceFactory _factory = new MLDsaServiceFactory();

    [Fact]
    public void CreateMLDsaService_ReturnsMLDsaService()
        => Assert.IsType<MLDsaService>(_factory.CreateMLDsaService());

    [Fact]
    public void CreateMLDsaService_ReturnsFreshInstancePerCall()
        => Assert.NotSame(_factory.CreateMLDsaService(), _factory.CreateMLDsaService());

    [Fact]
    public void CreateMLDsaService_DefaultsToMLDsa65()
    {
        // The default overload must select ML-DSA-65: its public key is 1952 bytes.
        var (publicKey, _) = _factory.CreateMLDsaService().GenerateKeyPair();
        Assert.Equal(1952, publicKey.Length);
    }

    [Theory]
    [InlineData(MLDsaParameterSet.MLDsa44, 1312)]
    [InlineData(MLDsaParameterSet.MLDsa65, 1952)]
    [InlineData(MLDsaParameterSet.MLDsa87, 2592)]
    public void CreateMLDsaService_MapsParameterSetToSecurityLevel(MLDsaParameterSet parameterSet, int publicKeyLength)
    {
        // The FIPS 204 public-key length is distinct per parameter set, so matching it proves the enum mapped to
        // the intended ml_dsa_44 / ml_dsa_65 / ml_dsa_87 internally.
        var (publicKey, _) = _factory.CreateMLDsaService(parameterSet).GenerateKeyPair();
        Assert.Equal(publicKeyLength, publicKey.Length);
    }

    [Fact]
    public void CreateMLDsaService_UndefinedParameterSet_ThrowsArgumentOutOfRange()
        => Assert.Throws<ArgumentOutOfRangeException>(
            () => _factory.CreateMLDsaService((MLDsaParameterSet)999));
}
