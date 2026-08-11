using Enigma.Core.Asymmetric.PublicKey;
using Xunit;

namespace Enigma.Core.UnitTests.PublicKey;

/// <summary>
/// Generate-once RSA-2048 key material shared across the public-key tests. Generating an RSA key is expensive,
/// so the round-trip tests reuse a single key — as the two <see cref="RsaKey"/> handles the service now takes,
/// plus their PEM serializations for the tests that exercise the import side — through an xUnit collection
/// fixture rather than regenerating it in every test.
/// </summary>
public sealed class RsaKeyFixture
{
    public RsaKeyFixture()
    {
        PrivateKey = new PublicKeyServiceFactory().CreatePublicKeyService().GenerateRsaKey(2048);
        PrivateKeyPem = PrivateKey.ExportPrivateKeyPem();
        PublicKeyPem = PrivateKey.ExportPublicKeyPem();
        PublicKey = RsaKey.ImportPublicKeyPem(PublicKeyPem);
    }

    /// <summary>A 2048-bit RSA private key handle; its public half is derived from the private components.</summary>
    public RsaKey PrivateKey { get; }

    /// <summary>A public-only handle over the matching public key.</summary>
    public RsaKey PublicKey { get; }

    /// <summary>The same private key as an unencrypted PKCS#8 PEM, for the tests that import one.</summary>
    public string PrivateKeyPem { get; }

    /// <summary>The matching public key as a <c>PUBLIC KEY</c> PEM.</summary>
    public string PublicKeyPem { get; }
}

/// <summary>Binds <see cref="RsaKeyFixture"/> to the shared public-key test collection.</summary>
[CollectionDefinition(Name)]
public sealed class RsaKeyCollection : ICollectionFixture<RsaKeyFixture>
{
    public const string Name = "rsa-keys";
}
