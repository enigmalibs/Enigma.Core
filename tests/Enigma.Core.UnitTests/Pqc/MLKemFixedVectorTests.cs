using System.IO;
using Enigma.Core.Asymmetric.Pqc;
using Xunit;

namespace Enigma.Core.UnitTests.Pqc;

/// <summary>
/// Fixed-vector decapsulation for ML-KEM-1024 against pinned material: the raw
/// FIPS 203 private keys (<c>kem1024_A_private.key</c> / <c>kem1024_B_private.key</c>, regenerated from the legacy
/// encrypted-PKCS#8 PEM fixtures as raw unencrypted key bytes), the <c>encapsulation.bin</c> ciphertext and the
/// expected 32-byte <c>secret.bin</c>. Key A must recover the known secret; the unrelated key B must not
/// (acceptance criterion 5).
/// </summary>
public class MLKemFixedVectorTests
{
    private static IMLKemService Service()
        => new MLKemServiceFactory().CreateMLKemService(MLKemParameterSet.MLKem1024);

    private static byte[] Fixture(string name) => File.ReadAllBytes(Path.Combine("Pqc", name));

    [Fact]
    public void Decapsulate_MatchingPrivateKey_RecoversKnownSecret()
    {
        var recovered = Service().Decapsulate(Fixture("encapsulation.bin"), Fixture("kem1024_A_private.key"));

        Assert.Equal(Fixture("secret.bin"), recovered);
    }

    [Fact]
    public void Decapsulate_WrongPrivateKey_DoesNotRecoverKnownSecret()
    {
        var recovered = Service().Decapsulate(Fixture("encapsulation.bin"), Fixture("kem1024_B_private.key"));

        Assert.NotEqual(Fixture("secret.bin"), recovered);
    }
}
