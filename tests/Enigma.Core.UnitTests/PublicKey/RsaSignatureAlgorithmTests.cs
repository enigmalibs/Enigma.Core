using Enigma.Core;
using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// Behavioural proof that every <see cref="RsaSignatureAlgorithm"/> value maps to a resolvable JCA signer
/// (<c>SHA1withRSA</c>/<c>SHA256withRSA</c>/<c>SHA384withRSA</c>/<c>SHA512withRSA</c>): each signs and then
/// verifies. The raw JCA names are internal, so this replaces the old string-constant test.
/// </summary>
[Collection(RsaKeyCollection.Name)]
public class RsaSignatureAlgorithmTests(RsaKeyFixture keys)
{
    private static IPublicKeyService Service() => new PublicKeyServiceFactory().CreatePublicKeyService();

    [Theory]
    [InlineData(RsaSignatureAlgorithm.Sha1WithRsa)]
    [InlineData(RsaSignatureAlgorithm.Sha256WithRsa)]
    [InlineData(RsaSignatureAlgorithm.Sha384WithRsa)]
    [InlineData(RsaSignatureAlgorithm.Sha512WithRsa)]
    public void SignVerify_RoundTrips_ForEveryAlgorithm(RsaSignatureAlgorithm algorithm)
    {
        var service = Service();
        var data = System.Text.Encoding.UTF8.GetBytes($"signed with {algorithm}");

        var signature = service.Sign(data, keys.PrivateKeyPem, algorithm);

        Assert.True(service.Verify(data, signature, keys.PublicKeyPem, algorithm));
    }

    [Fact]
    public void DefaultSignatureAlgorithm_IsSha256WithRsa()
    {
        var service = Service();
        var data = System.Text.Encoding.UTF8.GetBytes("default signature algorithm");

        // The default Sign must be verifiable by an explicit SHA-256 Verify.
        var signature = service.Sign(data, keys.PrivateKeyPem);

        Assert.True(service.Verify(data, signature, keys.PublicKeyPem, RsaSignatureAlgorithm.Sha256WithRsa));
    }
}
