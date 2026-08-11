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
        var cert = service.GenerateSelfSignedCertificate("CN=PFX Test", keys.RootPrivateKey, NotBefore, NotAfter);
        var password = "password123".ToCharArray();

        var pfx = service.ExportPkcs12(cert, keys.RootPrivateKey, password);
        var (certPem, privateKey) = service.ImportPkcs12(pfx, password);

        var original = service.GetCertificateInfo(cert);
        var recovered = service.GetCertificateInfo(certPem);
        Assert.Equal(original.Thumbprint, recovered.Thumbprint);
        Assert.Equal(original.Subject, recovered.Subject);
        Assert.Equal(original.SerialNumber, recovered.SerialNumber);

        // The recovered handle is the same key that went in: a private handle of the same modulus, exporting the
        // same public half. (Comparing the public PEM compares the modulus and exponent.)
        Assert.True(privateKey.HasPrivateKey);
        Assert.Equal(keys.RootPrivateKey.KeySizeBits, privateKey.KeySizeBits);
        Assert.Equal(keys.RootPrivateKey.ExportPublicKeyPem(), privateKey.ExportPublicKeyPem());
    }

    [Fact]
    public void ImportPkcs12_ExtractedKeyCanSign()
    {
        var publicKeyService = new PublicKeyServiceFactory().CreatePublicKeyService();
        var rsaKey = publicKeyService.GenerateRsaKey(2048);
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=PFX Sign Test", rsaKey, NotBefore, NotAfter);
        var password = "password123".ToCharArray();

        var pfx = service.ExportPkcs12(cert, rsaKey, password);
        var (_, extractedKey) = service.ImportPkcs12(pfx, password);

        // Sign with the extracted private key; verify with the original key's public half. The handle comes back
        // ready to use — no intermediate PEM is written or re-parsed on this path, and no passphrase is involved.
        var data = "test data"u8.ToArray();
        var signature = publicKeyService.Sign(data, extractedKey);
        Assert.True(publicKeyService.Verify(data, signature, rsaKey));
    }

    [Fact]
    public void ImportPkcs12_ExtractedKeySignatureVerifiesAgainstReturnedCertificate()
    {
        var publicKeyService = new PublicKeyServiceFactory().CreatePublicKeyService();
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=PFX Cert Match", keys.LeafPrivateKey, NotBefore, NotAfter);
        var password = "password123".ToCharArray();

        var pfx = service.ExportPkcs12(cert, keys.LeafPrivateKey, password);
        var (certPem, privateKey) = service.ImportPkcs12(pfx, password);

        // The returned handle and the returned certificate belong together: a signature made with the handle
        // verifies under the public key the *returned certificate* certifies (read back test-side, since the
        // product API exposes no certificate-to-public-key accessor).
        var data = "bound to the certificate"u8.ToArray();
        var signature = publicKeyService.Sign(data, privateKey);
        var certifiedPublicKey = RsaKey.ImportPublicKeyPem(TestPkcs12Builder.ReadCertificatePublicKeyPem(certPem));

        Assert.True(publicKeyService.Verify(data, signature, certifiedPublicKey));
    }

    [Fact]
    public void ExportPkcs12_WithChain_RoundTrips()
    {
        var service = keys.NewService();
        var root = service.GenerateSelfSignedCertificate("CN=Root CA", keys.RootPrivateKey, NotBefore, NotAfter,
            options: new X509CertificateOptions { IsCertificateAuthority = true });
        var csr = service.GenerateCertificateSigningRequest("CN=Leaf", keys.LeafPrivateKey);
        var leaf = service.IssueCertificate(csr, root, keys.RootPrivateKey, NotBefore, NotAfter);
        var password = "pass".ToCharArray();

        var pfx = service.ExportPkcs12(leaf, keys.LeafPrivateKey, password, [root]);
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
        var cert = service.GenerateSelfSignedCertificate("CN=PFX Test", keys.RootPrivateKey, NotBefore, NotAfter);
        var pfx = service.ExportPkcs12(cert, keys.RootPrivateKey, "correct-password".ToCharArray());

        Assert.Throws<CryptographicException>(() => service.ImportPkcs12(pfx, "wrong-password".ToCharArray()));
    }

    [Fact]
    public void ExportImportPkcs12_EmptyPassword_RoundTrips()
    {
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=Empty Password", keys.RootPrivateKey, NotBefore, NotAfter);

        var pfx = service.ExportPkcs12(cert, keys.RootPrivateKey, []);
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
        var cert = service.GenerateSelfSignedCertificate("CN=Not A PFX", keys.RootPrivateKey, NotBefore, NotAfter);
        // Well-formed DER, but the wrong ASN.1 shape for a PKCS#12 — BouncyCastle's Pfx parser rejects it with a
        // raw ArgumentException, which must be mapped to CryptographicException (not leaked) like any unreadable archive.
        var derCertificate = service.ExportCertificateToDer(cert);

        Assert.Throws<CryptographicException>(() => service.ImportPkcs12(derCertificate, "pass".ToCharArray()));
    }

    [Fact]
    public void ImportPkcs12_ValidArchiveWithNoKeyEntry_Throws()
    {
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=Cert Only", keys.RootPrivateKey, NotBefore, NotAfter);
        var password = "pass".ToCharArray();
        // A structurally valid, MAC-correct archive that carries only a certificate entry (no key entry).
        var certificateOnly = TestPkcs12Builder.CreateCertificateOnlyArchive(cert, password);

        Assert.Throws<ArgumentException>(() => service.ImportPkcs12(certificateOnly, password));
    }

    [Fact]
    public void ImportPkcs12_NonRsaKeyEntry_Throws()
    {
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=Non-RSA Key", keys.RootPrivateKey, NotBefore, NotAfter);
        var password = "pass".ToCharArray();
        // A structurally valid, MAC-correct archive whose key entry is Ed25519: there is no RsaKey to hand back,
        // so the archive is rejected as a bad argument rather than surfacing a mis-typed or raw BouncyCastle key.
        var nonRsaArchive = TestPkcs12Builder.CreateNonRsaKeyArchive(cert, password);

        Assert.Equal("pkcs12",
            Assert.Throws<ArgumentException>(() => service.ImportPkcs12(nonRsaArchive, password)).ParamName);
    }

    [Fact]
    public void ExportPkcs12_NullPrivateKey_Throws()
    {
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=Test", keys.RootPrivateKey, NotBefore, NotAfter);

        Assert.Equal("privateKey", Assert.Throws<ArgumentNullException>(() =>
            service.ExportPkcs12(cert, null!, "pass".ToCharArray())).ParamName);
    }

    [Fact]
    public void ExportPkcs12_PublicOnlyKey_ThrowsArgumentExceptionNamingTheKey()
    {
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=Test", keys.RootPrivateKey, NotBefore, NotAfter);
        var publicOnly = RsaKey.ImportPublicKeyPem(keys.RootPrivateKey.ExportPublicKeyPem());

        Assert.Equal("privateKey", Assert.Throws<ArgumentException>(() =>
            service.ExportPkcs12(cert, publicOnly, "pass".ToCharArray())).ParamName);
    }

    [Fact]
    public void ExportPkcs12_NullPassword_Throws()
    {
        var service = keys.NewService();
        var cert = service.GenerateSelfSignedCertificate("CN=Test", keys.RootPrivateKey, NotBefore, NotAfter);

        Assert.Throws<ArgumentNullException>(() => service.ExportPkcs12(cert, keys.RootPrivateKey, null!));
    }
}
