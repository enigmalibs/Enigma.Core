using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Certificates;
using Xunit;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// Generate-once RSA-2048 key material shared across the certificate tests. RSA key generation is expensive,
/// so a small set of independent private keys (root / intermediate / leaf, plus one password-encrypted key) is
/// produced a single time through an xUnit collection fixture rather than regenerated per test. Every
/// certificate operation takes only the private-key PEM; the public half is derived internally.
/// </summary>
public sealed class CertificateKeyFixture
{
    /// <summary>The passphrase protecting <see cref="EncryptedPrivateKeyPem"/>.</summary>
    public char[] EncryptedKeyPassword { get; } = "correct horse battery staple".ToCharArray();

    public CertificateKeyFixture()
    {
        // The certificate API still takes private keys as PEM text (it moves onto the RsaKey handle in a later
        // work item), so each generated handle is exported straight to the PEM the fixture hands out.
        var keyGen = new PublicKeyServiceFactory().CreatePublicKeyService();
        RootPrivateKeyPem = keyGen.GenerateRsaKey(2048).ExportPrivateKeyPem();
        IntermediatePrivateKeyPem = keyGen.GenerateRsaKey(2048).ExportPrivateKeyPem();
        LeafPrivateKeyPem = keyGen.GenerateRsaKey(2048).ExportPrivateKeyPem();
        UnrelatedRootPrivateKeyPem = keyGen.GenerateRsaKey(2048).ExportPrivateKeyPem();
        EncryptedPrivateKeyPem = keyGen.GenerateRsaKey(2048).ExportPrivateKeyPem(EncryptedKeyPassword);
    }

    /// <summary>An unencrypted 2048-bit RSA private key, PEM-encoded (used as the root / self-signed key).</summary>
    public string RootPrivateKeyPem { get; }

    /// <summary>A second, independent unencrypted 2048-bit RSA private key, PEM-encoded (used as an intermediate CA key).</summary>
    public string IntermediatePrivateKeyPem { get; }

    /// <summary>A third, independent unencrypted 2048-bit RSA private key, PEM-encoded (used as a leaf / requester key).</summary>
    public string LeafPrivateKeyPem { get; }

    /// <summary>A fourth, independent unencrypted 2048-bit RSA private key, PEM-encoded (used as an unrelated/untrusted root key).</summary>
    public string UnrelatedRootPrivateKeyPem { get; }

    /// <summary>A 2048-bit RSA private key encrypted (PBES2: PBKDF2-HMAC-SHA256 + AES-256-CBC) under <see cref="EncryptedKeyPassword"/>, PEM-encoded.</summary>
    public string EncryptedPrivateKeyPem { get; }

    /// <summary>Creates a fresh X.509 certificate service through the public factory.</summary>
    public IX509CertificateService NewService() =>
        new X509CertificateServiceFactory().CreateX509CertificateService();
}

/// <summary>Binds <see cref="CertificateKeyFixture"/> to the shared certificate test collection.</summary>
[CollectionDefinition(Name)]
public sealed class CertificateKeyCollection : ICollectionFixture<CertificateKeyFixture>
{
    public const string Name = "certificate-keys";
}
