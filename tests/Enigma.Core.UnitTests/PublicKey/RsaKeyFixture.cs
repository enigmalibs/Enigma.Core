using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// Generate-once RSA-2048 key material shared across the public-key tests. Generating an RSA key pair is
/// expensive, so the round-trip tests reuse a single pair (public key + unencrypted private key PEM) through
/// an xUnit collection fixture rather than regenerating it in every test.
/// </summary>
public sealed class RsaKeyFixture
{
    public RsaKeyFixture()
    {
        var (publicKeyPem, privateKeyPem) =
            new PublicKeyServiceFactory().CreatePublicKeyService().GenerateRsaKeyPair(2048);
        PublicKeyPem = publicKeyPem;
        PrivateKeyPem = privateKeyPem;
    }

    /// <summary>A 2048-bit RSA public key, PEM-encoded.</summary>
    public string PublicKeyPem { get; }

    /// <summary>The matching unencrypted RSA private key, PEM-encoded.</summary>
    public string PrivateKeyPem { get; }
}

/// <summary>Binds <see cref="RsaKeyFixture"/> to the shared public-key test collection.</summary>
[CollectionDefinition(Name)]
public sealed class RsaKeyCollection : ICollectionFixture<RsaKeyFixture>
{
    public const string Name = "rsa-keys";
}
