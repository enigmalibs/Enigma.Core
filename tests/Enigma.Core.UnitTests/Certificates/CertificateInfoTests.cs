using System;
using System.IO;
using System.Numerics;
using Enigma.Core.Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Xunit;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// <see cref="IX509CertificateService.GetCertificateInfo"/> read-back over the PEM contract, including the
/// restored extension fields <see cref="CertificateInfo.IsCertificateAuthority"/>,
/// <see cref="CertificateInfo.KeyUsage"/> and <see cref="CertificateInfo.SubjectAlternativeNames"/>.
/// </summary>
[Collection(CertificateKeyCollection.Name)]
public class CertificateInfoTests(CertificateKeyFixture keys)
{
    private static readonly DateTimeOffset NotBefore = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset NotAfter = new(2035, 12, 31, 23, 59, 59, TimeSpan.Zero);

    private string SelfSigned(string dn, X509CertificateOptions? options = null) =>
        keys.NewService().GenerateSelfSignedCertificate(dn, keys.RootPrivateKey, NotBefore, NotAfter, options: options);

    [Fact]
    public void GetCertificateInfo_Issued_IssuerDiffersFromSubject()
    {
        var service = keys.NewService();
        var ca = service.GenerateSelfSignedCertificate("CN=CA", keys.RootPrivateKey, NotBefore, NotAfter,
            options: new X509CertificateOptions { IsCertificateAuthority = true });
        var csr = service.GenerateCertificateSigningRequest("CN=Leaf", keys.LeafPrivateKey);
        var leaf = service.IssueCertificate(csr, ca, keys.RootPrivateKey, NotBefore, NotAfter);

        var info = service.GetCertificateInfo(leaf);

        Assert.Contains("CN=CA", info.Issuer);
        Assert.Contains("CN=Leaf", info.Subject);
        Assert.NotEqual(info.Subject, info.Issuer);
    }

    [Fact]
    public void GetCertificateInfo_PositiveSerial_AndValidityAndAlgorithmAndVersion()
    {
        var info = keys.NewService().GetCertificateInfo(SelfSigned("CN=Test"));

        Assert.True(info.SerialNumber > BigInteger.Zero);
        Assert.Equal(NotBefore.ToUnixTimeSeconds(), info.NotBefore.ToUnixTimeSeconds());
        Assert.Equal(NotAfter.ToUnixTimeSeconds(), info.NotAfter.ToUnixTimeSeconds());
        Assert.Contains("RSA", info.SignatureAlgorithm, StringComparison.OrdinalIgnoreCase);
        Assert.Equal(3, info.Version);
    }

    [Fact]
    public void GetCertificateInfo_IsCertificateAuthority_True()
    {
        var info = keys.NewService().GetCertificateInfo(
            SelfSigned("CN=CA", new X509CertificateOptions { IsCertificateAuthority = true }));

        Assert.True(info.IsCertificateAuthority);
    }

    [Fact]
    public void GetCertificateInfo_IsCertificateAuthority_False_WhenExplicitlyFalse()
    {
        var info = keys.NewService().GetCertificateInfo(
            SelfSigned("CN=Leaf", new X509CertificateOptions { IsCertificateAuthority = false }));

        Assert.False(info.IsCertificateAuthority);
    }

    [Fact]
    public void GetCertificateInfo_IsCertificateAuthority_False_WhenExtensionAbsent()
    {
        var info = keys.NewService().GetCertificateInfo(SelfSigned("CN=Plain"));

        Assert.False(info.IsCertificateAuthority);
    }

    [Fact]
    public void GetCertificateInfo_KeyUsage_ReadsBackRequestedFlags()
    {
        const X509KeyUsage requested = X509KeyUsage.DigitalSignature | X509KeyUsage.KeyEncipherment;
        var info = keys.NewService().GetCertificateInfo(
            SelfSigned("CN=Test", new X509CertificateOptions { KeyUsage = requested }));

        Assert.Equal(requested, info.KeyUsage);
    }

    [Fact]
    public void GetCertificateInfo_KeyUsage_ReadsBackCaFlags()
    {
        const X509KeyUsage requested = X509KeyUsage.KeyCertSign | X509KeyUsage.CrlSign;
        var info = keys.NewService().GetCertificateInfo(
            SelfSigned("CN=CA", new X509CertificateOptions { KeyUsage = requested }));

        Assert.Equal(requested, info.KeyUsage);
    }

    [Fact]
    public void GetCertificateInfo_NoKeyUsage_ReturnsNull()
    {
        var info = keys.NewService().GetCertificateInfo(SelfSigned("CN=Test"));

        Assert.Null(info.KeyUsage);
    }

    [Fact]
    public void GetCertificateInfo_SubjectAlternativeNames_ReadsBackDnsNames()
    {
        var info = keys.NewService().GetCertificateInfo(
            SelfSigned("CN=example.com", new X509CertificateOptions
            {
                SubjectAlternativeNames = ["example.com", "www.example.com"],
            }));

        Assert.Equal(2, info.SubjectAlternativeNames.Count);
        Assert.Contains("example.com", info.SubjectAlternativeNames);
        Assert.Contains("www.example.com", info.SubjectAlternativeNames);
    }

    [Fact]
    public void GetCertificateInfo_NoSans_ReturnsEmpty()
    {
        var info = keys.NewService().GetCertificateInfo(SelfSigned("CN=Test"));

        Assert.Empty(info.SubjectAlternativeNames);
    }

    [Fact]
    public void GetCertificateInfo_MalformedSan_ReturnsEmpty()
    {
        // A certificate that loads normally but whose SubjectAlternativeName extension value is structurally
        // invalid (a dNSName [2] tag implicitly wrapping a constructed SEQUENCE). BouncyCastle stores extension
        // values as opaque octets and decodes SAN lazily, so the certificate parses fine but decoding the SAN
        // throws — the internal extractor must swallow that and return an empty list, not surface it.
        var malformedSanValue = new DerSequence(
            new DerTaggedObject(isExplicit: false, GeneralName.DnsName, new DerSequence(DerInteger.ValueOf(1))));
        // The helper signs with BouncyCastle directly, and the test project cannot see RsaKey's internal
        // BouncyCastle key, so the signing key reaches it as a PEM.
        var certPem = BuildSelfSignedCertWithRawSan(keys.RootPrivateKey.ExportPrivateKeyPem(), malformedSanValue);

        var info = keys.NewService().GetCertificateInfo(certPem);

        Assert.Empty(info.SubjectAlternativeNames);
    }

    // Builds a self-signed certificate carrying a caller-supplied (here deliberately malformed) raw
    // SubjectAlternativeName extension value, using BouncyCastle directly (test-only; never touches the product API).
    private static string BuildSelfSignedCertWithRawSan(string privateKeyPem, Asn1Encodable rawSanValue)
    {
        var privateKey = ReadPrivateKey(privateKeyPem);
        var crt = (RsaPrivateCrtKeyParameters)privateKey;
        var publicKey = new RsaKeyParameters(isPrivate: false, crt.Modulus, crt.PublicExponent);

        var dn = new X509Name("CN=Malformed SAN");
        var generator = new Org.BouncyCastle.X509.X509V3CertificateGenerator();
        generator.SetSerialNumber(Org.BouncyCastle.Math.BigInteger.One);
        generator.SetIssuerDN(dn);
        generator.SetSubjectDN(dn);
        generator.SetNotBefore(DateTime.UtcNow.AddDays(-1));
        generator.SetNotAfter(DateTime.UtcNow.AddYears(1));
        generator.SetPublicKey(publicKey);
        generator.AddExtension(X509Extensions.SubjectAlternativeName, critical: false, rawSanValue);

        var certificate = generator.Generate(new Asn1SignatureFactory("SHA256withRSA", privateKey));
        using var writer = new StringWriter();
        new PemWriter(writer).WriteObject(certificate);
        return writer.ToString();
    }

    private static AsymmetricKeyParameter ReadPrivateKey(string pem)
    {
        using var reader = new StringReader(pem);
        return new PemReader(reader).ReadObject() switch
        {
            AsymmetricCipherKeyPair pair => pair.Private,
            AsymmetricKeyParameter { IsPrivate: true } key => key,
            var other => throw new InvalidOperationException($"Expected an RSA private key PEM, got {other?.GetType().Name ?? "null"}."),
        };
    }
}
