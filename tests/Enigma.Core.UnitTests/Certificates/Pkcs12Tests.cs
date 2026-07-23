using System;
using System.Security.Cryptography;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Certificates;
using Xunit;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// PKCS#12 (PFX) export/import over the PEM contract: <c>ExportPkcs12</c> bundles a certificate + private key
/// (optionally with a chain) into a password-protected archive (binary <see cref="byte"/>[] — the documented
/// exception to the all-PEM rule), and <c>ImportPkcs12</c> extracts them back as PEM. A wrong password surfaces
/// as <see cref="CryptographicException"/>.
/// </summary>
[Collection(CertificateKeyCollection.Name)]
public class Pkcs12Tests(CertificateKeyFixture keys)
{
    private static readonly DateTimeOffset NotBefore = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2035, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Fact]
    public void ExportImportPkcs12_RoundTrip_PreservesCertificate()
    {
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=PFX Test", keys.RootPrivateKeyPem, NotBefore, NotAfter);
        var password = "password123".ToCharArray();

        var pfx = service.ExportPkcs12(cert, keys.RootPrivateKeyPem, password);
        var (certPem, privateKeyPem) = service.ImportPkcs12(pfx, password);

        Assert.Equal(service.GetCertificateInfo(cert).Thumbprint, service.GetCertificateInfo(certPem).Thumbprint);
        Assert.Contains("PRIVATE KEY", privateKeyPem);
    }

    [Fact]
    public void ImportPkcs12_ExtractedKeyCanSign()
    {
        var publicKeyService = new PublicKeyServiceFactory().CreatePublicKeyService();
        var (publicKeyPem, privateKeyPem) = publicKeyService.GenerateRsaKeyPair(2048);
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=PFX Sign Test", privateKeyPem, NotBefore, NotAfter);
        var password = "password123".ToCharArray();

        var pfx = service.ExportPkcs12(cert, privateKeyPem, password);
        var (_, extractedKeyPem) = service.ImportPkcs12(pfx, password);

        // Sign with the extracted private key; verify with the original public key.
        var data = "test data"u8.ToArray();
        var signature = publicKeyService.Sign(data, extractedKeyPem);
        Assert.True(publicKeyService.Verify(data, signature, publicKeyPem));
    }

    [Fact]
    public void ExportPkcs12_WithChain_RoundTrips()
    {
        var service = keys.NewService();
        var root = service.GenerateSelfSignedCertificate("CN=Root CA", keys.RootPrivateKeyPem, NotBefore, NotAfter,
            options: new X509CertificateOptions { IsCertificateAuthority = true });
        var csr = service.GenerateCertificateSigningRequest("CN=Leaf", keys.LeafPrivateKeyPem);
        var leaf = service.IssueCertificate(csr, root, keys.RootPrivateKeyPem, NotBefore, NotAfter);
        var password = "pass".ToCharArray();

        var pfx = service.ExportPkcs12(leaf, keys.LeafPrivateKeyPem, password, [root]);
        var (certPem, _) = service.ImportPkcs12(pfx, password);

        Assert.Equal(service.GetCertificateInfo(leaf).Thumbprint, service.GetCertificateInfo(certPem).Thumbprint);

        // The chain is not surfaced by ImportPkcs12, so crack the archive open test-side to prove the root was
        // actually bundled — otherwise a regression dropping chainPems would still pass the round-trip assertion.
        var chainSubjects = TestPkcs12Builder.ReadKeyEntryChainSubjects(pfx, password);
        Assert.Equal(2, chainSubjects.Count);
        Assert.Contains(chainSubjects, s => s.Contains("CN=Leaf"));
        Assert.Contains(chainSubjects, s => s.Contains("CN=Root CA"));
    }

    [Fact]
    public void ImportPkcs12_WrongPassword_ThrowsCryptographicException()
    {
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=PFX Test", keys.RootPrivateKeyPem, NotBefore, NotAfter);
        var pfx = service.ExportPkcs12(cert, keys.RootPrivateKeyPem, "correct-password".ToCharArray());

        Assert.Throws<CryptographicException>(() => service.ImportPkcs12(pfx, "wrong-password".ToCharArray()));
    }

    [Fact]
    public void ExportImportPkcs12_EmptyPassword_RoundTrips()
    {
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=Empty Password", keys.RootPrivateKeyPem, NotBefore, NotAfter);

        var pfx = service.ExportPkcs12(cert, keys.RootPrivateKeyPem, []);
        var (certPem, _) = service.ImportPkcs12(pfx, []);

        Assert.Equal(service.GetCertificateInfo(cert).Thumbprint, service.GetCertificateInfo(certPem).Thumbprint);
    }

    [Fact]
    public void ImportPkcs12_MalformedArchive_ThrowsCryptographicException()
    {
        Assert.Throws<CryptographicException>(() =>
            keys.NewService().ImportPkcs12([0x00, 0x01, 0x02, 0x03], "pass".ToCharArray()));
    }

    [Fact]
    public void ImportPkcs12_EmptyArchive_Throws()
    {
        Assert.Throws<ArgumentException>(() => keys.NewService().ImportPkcs12([], "pass".ToCharArray()));
    }

    [Fact]
    public void ImportPkcs12_ValidDerButNotArchive_ThrowsCryptographicException()
    {
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=Not A PFX", keys.RootPrivateKeyPem, NotBefore, NotAfter);
        // Well-formed DER, but the wrong ASN.1 shape for a PKCS#12 — BouncyCastle's Pfx parser rejects it with a
        // raw ArgumentException, which must be mapped to CryptographicException (not leaked) like any unreadable archive.
        var derCertificate = service.ExportCertificateToDer(cert);

        Assert.Throws<CryptographicException>(() => service.ImportPkcs12(derCertificate, "pass".ToCharArray()));
    }

    [Fact]
    public void ImportPkcs12_ValidArchiveWithNoKeyEntry_Throws()
    {
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=Cert Only", keys.RootPrivateKeyPem, NotBefore, NotAfter);
        var password = "pass".ToCharArray();
        // A structurally valid, MAC-correct archive that carries only a certificate entry (no key entry).
        var certificateOnly = TestPkcs12Builder.CreateCertificateOnlyArchive(cert, password);

        Assert.Throws<ArgumentException>(() => service.ImportPkcs12(certificateOnly, password));
    }

    [Fact]
    public void ExportPkcs12_NullPassword_Throws()
    {
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=Test", keys.RootPrivateKeyPem, NotBefore, NotAfter);

        Assert.Throws<ArgumentNullException>(() => service.ExportPkcs12(cert, keys.RootPrivateKeyPem, null!));
    }
}
