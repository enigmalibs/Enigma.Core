using System;
using System.Security.Cryptography;
using Enigma.Core.Certificates;
using Xunit;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// Certificate format conversions over the PEM contract: DER export/import (the documented binary exception),
/// PEM/DER equivalence, and the uppercase-hex SHA-256 <see cref="CertificateInfo.Thumbprint"/> against an
/// independently computed digest (KAT).
/// </summary>
[Collection(CertificateKeyCollection.Name)]
public class CertificateFormatTests(CertificateKeyFixture keys)
{
    private static readonly DateTimeOffset NotBefore = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2035, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private string SelfSigned(string dn) =>
        keys.NewService().GenerateSelfSignedCertificate(dn, keys.RootPrivateKeyPem, NotBefore, NotAfter);

    [Fact]
    public void ExportImportDer_RoundTrip_PreservesCertificate()
    {
        var service = keys.NewService();
        var pem = SelfSigned("CN=DER Test");

        var der = service.ExportCertificateToDer(pem);
        var pemFromDer = service.ImportCertificateFromDer(der);

        // The DER round-trip must denote the same certificate (identical thumbprint) ...
        Assert.Equal(service.GetCertificateInfo(pem).Thumbprint, service.GetCertificateInfo(pemFromDer).Thumbprint);
        // ... and re-exporting must reproduce byte-identical DER.
        Assert.Equal(der, service.ExportCertificateToDer(pemFromDer));
    }

    [Fact]
    public void PemAndDer_DenoteSameCertificate()
    {
        var service = keys.NewService();
        var pem = SelfSigned("CN=Equivalence Test");

        var der = service.ExportCertificateToDer(pem);
        var pemFromDer = service.ImportCertificateFromDer(der);

        var fromPem = service.GetCertificateInfo(pem);
        var fromDer = service.GetCertificateInfo(pemFromDer);

        Assert.Equal(fromPem.SerialNumber, fromDer.SerialNumber);
        Assert.Equal(fromPem.Subject, fromDer.Subject);
        Assert.Equal(fromPem.Thumbprint, fromDer.Thumbprint);
    }

    [Fact]
    public void ExportCertificateToDer_MalformedPem_Throws()
    {
        Assert.Throws<ArgumentException>(() => keys.NewService().ExportCertificateToDer("not a certificate"));
    }

    [Fact]
    public void ImportCertificateFromDer_InvalidBytes_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            keys.NewService().ImportCertificateFromDer([0x00, 0x01, 0x02, 0x03]));
    }

    [Fact]
    public void ImportCertificateFromDer_EmptyBytes_Throws()
    {
        Assert.Throws<ArgumentException>(() => keys.NewService().ImportCertificateFromDer([]));
    }

    [Fact]
    public void Thumbprint_EqualsIndependentUppercaseHexSha256OfDer()
    {
        var service = keys.NewService();
        var pem = SelfSigned("CN=Thumbprint KAT");

        var der = service.ExportCertificateToDer(pem);
        using var sha256 = SHA256.Create();
        var expected = BitConverter.ToString(sha256.ComputeHash(der)).Replace("-", string.Empty);

        Assert.Equal(expected, service.GetCertificateInfo(pem).Thumbprint);
        Assert.Matches("^[0-9A-F]{64}$", service.GetCertificateInfo(pem).Thumbprint);
    }
}
