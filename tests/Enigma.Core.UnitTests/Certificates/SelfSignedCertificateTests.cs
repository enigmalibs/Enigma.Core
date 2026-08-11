using System;
using System.Numerics;
using Enigma.Core.Asymmetric.PublicKey;
using Enigma.Core.Certificates;
using Xunit;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// Self-signed generation over the PEM contract, read back through <see cref="IX509CertificateService.GetCertificateInfo"/>.
/// Chain validation of a self-signed root and read-back of the CA/KeyUsage/SAN extensions are exercised by the
/// later phases (chain validation, certificate-info); here we prove the certificate is well-formed and carries
/// the requested identity, validity and algorithm.
/// </summary>
[Collection(CertificateKeyCollection.Name)]
public class SelfSignedCertificateTests(CertificateKeyFixture keys)
{
    private static readonly DateTimeOffset NotBefore = new(2025, 6, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2026, 6, 1, 0, 0, 0, TimeSpan.Zero);

    private string SelfSigned(string dn, RsaSignatureAlgorithm alg = RsaSignatureAlgorithm.Sha256WithRsa, X509CertificateOptions? options = null) =>
        keys.NewService().GenerateSelfSignedCertificate(dn, keys.RootPrivateKey, NotBefore, NotAfter, alg, options);

    [Fact]
    public void GenerateSelfSigned_ReturnsCertificatePem()
    {
        var pem = SelfSigned("CN=Test");

        Assert.Contains("BEGIN CERTIFICATE", pem);
        Assert.Contains("END CERTIFICATE", pem);
    }

    [Fact]
    public void GenerateSelfSigned_HasRequestedSubject()
    {
        var info = keys.NewService().GetCertificateInfo(SelfSigned("CN=test.example.com,O=TestOrg,C=US"));

        Assert.Contains("CN=test.example.com", info.Subject);
        Assert.Contains("O=TestOrg", info.Subject);
    }

    [Fact]
    public void GenerateSelfSigned_IssuerEqualsSubject()
    {
        var info = keys.NewService().GetCertificateInfo(SelfSigned("CN=SelfSigned"));

        Assert.Equal(info.Subject, info.Issuer);
    }

    [Fact]
    public void GenerateSelfSigned_IsVersion3()
    {
        var info = keys.NewService().GetCertificateInfo(SelfSigned("CN=Test"));

        Assert.Equal(3, info.Version);
    }

    [Fact]
    public void GenerateSelfSigned_ValidityMatchesInputs()
    {
        var info = keys.NewService().GetCertificateInfo(SelfSigned("CN=Test"));

        Assert.Equal(NotBefore.ToUnixTimeSeconds(), info.NotBefore.ToUnixTimeSeconds());
        Assert.Equal(NotAfter.ToUnixTimeSeconds(), info.NotAfter.ToUnixTimeSeconds());
    }

    [Fact]
    public void GenerateSelfSigned_HasPositiveSerialNumber()
    {
        var info = keys.NewService().GetCertificateInfo(SelfSigned("CN=Test"));

        Assert.True(info.SerialNumber > BigInteger.Zero);
    }

    [Fact]
    public void GenerateSelfSigned_SerialNumbersAreRandomPerCertificate()
    {
        var first = keys.NewService().GetCertificateInfo(SelfSigned("CN=Test"));
        var second = keys.NewService().GetCertificateInfo(SelfSigned("CN=Test"));

        Assert.NotEqual(first.SerialNumber, second.SerialNumber);
    }

    [Theory]
    [InlineData(RsaSignatureAlgorithm.Sha1WithRsa, "SHA1")]
    [InlineData(RsaSignatureAlgorithm.Sha256WithRsa, "SHA256")]
    [InlineData(RsaSignatureAlgorithm.Sha384WithRsa, "SHA384")]
    [InlineData(RsaSignatureAlgorithm.Sha512WithRsa, "SHA512")]
    public void GenerateSelfSigned_ReportsRequestedSignatureAlgorithm(RsaSignatureAlgorithm algorithm, string expectedHash)
    {
        var info = keys.NewService().GetCertificateInfo(SelfSigned("CN=Test", algorithm));

        Assert.Contains("RSA", info.SignatureAlgorithm, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(expectedHash, info.SignatureAlgorithm.Replace("-", string.Empty), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GenerateSelfSigned_ThumbprintIsUppercaseHexSha256()
    {
        var info = keys.NewService().GetCertificateInfo(SelfSigned("CN=Test"));

        // 32-byte SHA-256 digest -> 64 uppercase hex characters.
        Assert.Equal(64, info.Thumbprint.Length);
        Assert.Matches("^[0-9A-F]{64}$", info.Thumbprint);
    }

    [Fact]
    public void GenerateSelfSigned_WithCaOptions_ProducesWellFormedCertificate()
    {
        var options = new X509CertificateOptions
        {
            IsCertificateAuthority = true,
            KeyUsage = X509KeyUsage.KeyCertSign | X509KeyUsage.CrlSign,
        };

        var info = keys.NewService().GetCertificateInfo(SelfSigned("CN=Test CA", options: options));

        // Read-back of the CA / KeyUsage bits arrives with GetCertificateInfo's extension fields (later phase);
        // here we confirm a CA-option certificate still generates and parses as a valid v3 certificate.
        Assert.Equal(info.Subject, info.Issuer);
        Assert.Equal(3, info.Version);
    }

    [Fact]
    public void GenerateSelfSigned_WithSubjectAlternativeNames_ProducesWellFormedCertificate()
    {
        var options = new X509CertificateOptions
        {
            SubjectAlternativeNames = ["example.com", "www.example.com"],
        };

        var info = keys.NewService().GetCertificateInfo(SelfSigned("CN=example.com", options: options));

        Assert.Contains("CN=example.com", info.Subject);
    }

    [Fact]
    public void GenerateSelfSigned_NullSubject_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            keys.NewService().GenerateSelfSignedCertificate(null!, keys.RootPrivateKey, NotBefore, NotAfter));
    }

    [Fact]
    public void GenerateSelfSigned_NullPrivateKey_Throws()
    {
        // Replaces the former malformed-PEM test: with key material crossing as a handle there is no PEM string to
        // malform here, and RsaKeyTests already owns that assertion at the import boundary where the PEM now lives.
        Assert.Equal("privateKey", Assert.Throws<ArgumentNullException>(() =>
            keys.NewService().GenerateSelfSignedCertificate("CN=Test", null!, NotBefore, NotAfter)).ParamName);
    }

    [Fact]
    public void GenerateSelfSigned_PublicOnlyKey_ThrowsArgumentExceptionNamingTheKey()
    {
        var publicOnly = RsaKey.ImportPublicKeyPem(keys.RootPrivateKey.ExportPublicKeyPem());

        Assert.Equal("privateKey", Assert.Throws<ArgumentException>(() =>
            keys.NewService().GenerateSelfSignedCertificate("CN=Test", publicOnly, NotBefore, NotAfter)).ParamName);
    }
}
