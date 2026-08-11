using System;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Certificates;
using Xunit;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// Issuance of a certificate from a CSR over the PEM contract: the issued leaf carries the CA's subject as its
/// issuer and the CSR's subject as its own, and a CA-capable three-level hierarchy can be built (its end-to-end
/// path validation lands with chain validation in the next phase). Issuance also verifies the CSR internally and
/// rejects a malformed one.
/// </summary>
[Collection(CertificateKeyCollection.Name)]
public class IssueCertificateTests(CertificateKeyFixture keys)
{
    private static readonly DateTimeOffset NotBefore = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly X509CertificateOptions CaOptions = new()
    {
        IsCertificateAuthority = true,
        KeyUsage = X509KeyUsage.KeyCertSign | X509KeyUsage.CrlSign,
    };

    [Fact]
    public void IssueCertificate_IssuerIsCaSubject_SubjectIsCsrSubject()
    {
        var service = keys.NewService();
        var caPem = service.GenerateSelfSignedCertificate("CN=Test CA", keys.RootPrivateKey, NotBefore, NotAfter, options: CaOptions);
        var csrPem = service.GenerateCertificateSigningRequest("CN=leaf.example.com,O=CSR Org", keys.LeafPrivateKey);

        var leafPem = service.IssueCertificate(csrPem, caPem, keys.RootPrivateKey, NotBefore, NotAfter);

        var caInfo = service.GetCertificateInfo(caPem);
        var leafInfo = service.GetCertificateInfo(leafPem);
        Assert.Equal(caInfo.Subject, leafInfo.Issuer);
        Assert.Contains("CN=leaf.example.com", leafInfo.Subject);
        Assert.Contains("O=CSR Org", leafInfo.Subject);
    }

    [Fact]
    public void IssueCertificate_LeafHasOwnSerialNotSharedWithIssuer()
    {
        var service = keys.NewService();
        var caPem = service.GenerateSelfSignedCertificate("CN=CA", keys.RootPrivateKey, NotBefore, NotAfter, options: CaOptions);
        var csrPem = service.GenerateCertificateSigningRequest("CN=Leaf", keys.LeafPrivateKey);

        var leafPem = service.IssueCertificate(csrPem, caPem, keys.RootPrivateKey, NotBefore, NotAfter);

        Assert.NotEqual(service.GetCertificateInfo(caPem).SerialNumber, service.GetCertificateInfo(leafPem).SerialNumber);
    }

    [Fact]
    public void IssueCertificate_BuildsThreeLevelHierarchy()
    {
        var service = keys.NewService();

        var rootPem = service.GenerateSelfSignedCertificate(
            "CN=Root CA", keys.RootPrivateKey, NotBefore, NotAfter, options: CaOptions);

        var intermediateCsr = service.GenerateCertificateSigningRequest("CN=Intermediate CA", keys.IntermediatePrivateKey);
        var intermediatePem = service.IssueCertificate(
            intermediateCsr, rootPem, keys.RootPrivateKey, NotBefore, NotAfter, options: CaOptions);

        var leafCsr = service.GenerateCertificateSigningRequest("CN=leaf.example.com", keys.LeafPrivateKey);
        var leafPem = service.IssueCertificate(
            leafCsr, intermediatePem, keys.IntermediatePrivateKey, NotBefore, NotAfter);

        var rootInfo = service.GetCertificateInfo(rootPem);
        var intermediateInfo = service.GetCertificateInfo(intermediatePem);
        var leafInfo = service.GetCertificateInfo(leafPem);

        Assert.Equal(rootInfo.Subject, rootInfo.Issuer);                     // self-signed root
        Assert.Equal(rootInfo.Subject, intermediateInfo.Issuer);            // intermediate issued by root
        Assert.Equal(intermediateInfo.Subject, leafInfo.Issuer);           // leaf issued by intermediate
        Assert.Contains("CN=leaf.example.com", leafInfo.Subject);
    }

    [Fact]
    public void IssueCertificate_MalformedCsr_Throws()
    {
        var service = keys.NewService();
        var caPem = service.GenerateSelfSignedCertificate("CN=CA", keys.RootPrivateKey, NotBefore, NotAfter, options: CaOptions);

        Assert.Throws<ArgumentException>(() =>
            service.IssueCertificate("not a csr pem", caPem, keys.RootPrivateKey, NotBefore, NotAfter));
    }

    [Fact]
    public void IssueCertificate_MalformedIssuerCertificate_Throws()
    {
        var service = keys.NewService();
        var csrPem = service.GenerateCertificateSigningRequest("CN=Leaf", keys.LeafPrivateKey);

        Assert.Throws<ArgumentException>(() =>
            service.IssueCertificate(csrPem, "not a certificate", keys.RootPrivateKey, NotBefore, NotAfter));
    }

    [Fact]
    public void IssueCertificate_NullIssuerPrivateKey_Throws()
    {
        var service = keys.NewService();
        var caPem = service.GenerateSelfSignedCertificate("CN=CA", keys.RootPrivateKey, NotBefore, NotAfter, options: CaOptions);
        var csrPem = service.GenerateCertificateSigningRequest("CN=Leaf", keys.LeafPrivateKey);

        Assert.Equal("issuerPrivateKey", Assert.Throws<ArgumentNullException>(() =>
            service.IssueCertificate(csrPem, caPem, null!, NotBefore, NotAfter)).ParamName);
    }

    [Fact]
    public void IssueCertificate_PublicOnlyIssuerKey_ThrowsArgumentExceptionNamingTheKey()
    {
        var service = keys.NewService();
        var caPem = service.GenerateSelfSignedCertificate("CN=CA", keys.RootPrivateKey, NotBefore, NotAfter, options: CaOptions);
        var csrPem = service.GenerateCertificateSigningRequest("CN=Leaf", keys.LeafPrivateKey);
        var publicOnly = RsaKey.ImportPublicKeyPem(keys.RootPrivateKey.ExportPublicKeyPem());

        Assert.Equal("issuerPrivateKey", Assert.Throws<ArgumentException>(() =>
            service.IssueCertificate(csrPem, caPem, publicOnly, NotBefore, NotAfter)).ParamName);
    }
}
