using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Certificates;
using Xunit;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// Generate-once RSA-2048 key material shared across the certificate tests. RSA key generation is expensive,
/// so a small set of independent private keys (root / intermediate / leaf, plus one password-encrypted key) is
/// produced a single time through an xUnit collection fixture rather than regenerated per test. Every
/// certificate operation takes an <see cref="RsaKey"/> handle; the public half is derived internally.
/// </summary>
public sealed class CertificateKeyFixture
{
    /// <summary>The passphrase protecting <see cref="EncryptedPrivateKeyPem"/>.</summary>
    public char[] EncryptedKeyPassword { get; } = "correct horse battery staple".ToCharArray();

    public CertificateKeyFixture()
    {
        var keyGen = new PublicKeyServiceFactory().CreatePublicKeyService();
        RootPrivateKey = keyGen.GenerateRsaKey(2048);
        IntermediatePrivateKey = keyGen.GenerateRsaKey(2048);
        LeafPrivateKey = keyGen.GenerateRsaKey(2048);
        UnrelatedRootPrivateKey = keyGen.GenerateRsaKey(2048);
        // The encrypted scenario stays a PEM: the passphrase is consumed once, at RsaKey.ImportPrivateKeyPem,
        // which is the only place a password meets key material now that the certificate API takes handles.
        EncryptedPrivateKeyPem = keyGen.GenerateRsaKey(2048).ExportPrivateKeyPem(EncryptedKeyPassword);
    }

    /// <summary>An unencrypted 2048-bit RSA private key (used as the root / self-signed key).</summary>
    public RsaKey RootPrivateKey { get; }

    /// <summary>A second, independent unencrypted 2048-bit RSA private key (used as an intermediate CA key).</summary>
    public RsaKey IntermediatePrivateKey { get; }

    /// <summary>A third, independent unencrypted 2048-bit RSA private key (used as a leaf / requester key).</summary>
    public RsaKey LeafPrivateKey { get; }

    /// <summary>A fourth, independent unencrypted 2048-bit RSA private key (used as an unrelated/untrusted root key).</summary>
    public RsaKey UnrelatedRootPrivateKey { get; }

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
