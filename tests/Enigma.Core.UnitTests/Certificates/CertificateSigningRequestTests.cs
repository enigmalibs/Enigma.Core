using System;
using Enigma.Core.Certificates;
using Xunit;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// PKCS#10 CSR generation and verification over the PEM contract: a generated CSR is well-formed and its
/// self-signature verifies (<see cref="IX509CertificateService.IsCertificateSigningRequestValid"/> true), while a
/// corrupted or non-CSR PEM is rejected. Acceptance by <c>IssueCertificate</c> is covered by the issuance tests.
/// </summary>
[Collection(CertificateKeyCollection.Name)]
public class CertificateSigningRequestTests(CertificateKeyFixture keys)
{
    private string Csr(string dn) =>
        keys.NewService().GenerateCertificateSigningRequest(dn, keys.LeafPrivateKeyPem);

    [Fact]
    public void GenerateCsr_ReturnsCsrPem()
    {
        var pem = Csr("CN=test.example.com,O=TestOrg");

        Assert.Contains("BEGIN CERTIFICATE REQUEST", pem);
        Assert.Contains("END CERTIFICATE REQUEST", pem);
    }

    [Fact]
    public void GenerateCsr_SignatureIsValid()
    {
        Assert.True(keys.NewService().IsCertificateSigningRequestValid(Csr("CN=Test")));
    }

    [Fact]
    public void IsCertificateSigningRequestValid_CorruptedCsrPem_Throws()
    {
        var pem = Csr("CN=Test");
        // Corrupt a run of base64 characters in the body so the PEM no longer decodes to a valid CSR structure.
        var corrupted = MutateBody(pem);

        Assert.Throws<ArgumentException>(() => keys.NewService().IsCertificateSigningRequestValid(corrupted));
    }

    [Fact]
    public void IsCertificateSigningRequestValid_CertificatePemInsteadOfCsr_Throws()
    {
        var certificatePem = keys.NewService().GenerateSelfSignedCertificate(
            "CN=Test", keys.RootPrivateKeyPem,
            new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));

        Assert.Throws<ArgumentException>(() => keys.NewService().IsCertificateSigningRequestValid(certificatePem));
    }

    [Fact]
    public void IsCertificateSigningRequestValid_EmptyPem_Throws()
    {
        Assert.Throws<ArgumentException>(() => keys.NewService().IsCertificateSigningRequestValid("   "));
    }

    // Replaces the first full line of base64 body with a same-length run of 'A's, corrupting the encoded structure.
    private static string MutateBody(string pem)
    {
        var lines = pem.Replace("\r\n", "\n").Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (!lines[i].StartsWith("-----", StringComparison.Ordinal) && lines[i].Length > 0)
            {
                lines[i] = new string('A', lines[i].Length);
                break;
            }
        }

        return string.Join("\n", lines);
    }
}
