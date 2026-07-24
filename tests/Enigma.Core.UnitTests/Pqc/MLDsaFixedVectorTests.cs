using System.IO;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// Fixed-vector verification for ML-DSA-87 against pinned material: the raw
/// FIPS 204 public keys (<c>dsa87_A_public.key</c> / <c>dsa87_B_public.key</c>, regenerated from the legacy PEM
/// fixtures as raw key bytes), the signed <c>message.txt</c> and the <c>signature.bin</c> produced against key A.
/// The signature must verify true under key A and false under the unrelated key B (acceptance criterion 4).
/// </summary>
public class MLDsaFixedVectorTests
{
    private static IMLDsaService Service()
        => new MLDsaServiceFactory().CreateMLDsaService(MLDsaParameterSet.MLDsa87);

    private static byte[] Fixture(string name) => File.ReadAllBytes(Path.Combine("Pqc", name));

    [Fact]
    public void Verify_ValidSignature_WithCorrectKey_ReturnsTrue()
    {
        var isValid = Service().Verify(
            Fixture("message.txt"), Fixture("signature.bin"), Fixture("dsa87_A_public.key"));

        Assert.True(isValid);
    }

    [Fact]
    public void Verify_ValidSignature_WithWrongKey_ReturnsFalse()
    {
        var isValid = Service().Verify(
            Fixture("message.txt"), Fixture("signature.bin"), Fixture("dsa87_B_public.key"));

        Assert.False(isValid);
    }
}
