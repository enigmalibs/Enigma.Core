using System;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Enigma.Core.UnitTests.Certificates;

/// <summary>
/// Test-only helper that builds signed X.509 v2 CRL fixtures with BouncyCastle directly. CRL <em>generation</em>
/// is deliberately outside the product API (the service only <em>reads</em> CRLs, via <c>IsRevoked</c>), so the
/// revocation tests mint their own issuer-signed CRLs here and hand them to the service as PEM. This BouncyCastle
/// usage is confined to the test project and never touches <c>Enigma.Core</c>'s public surface.
/// </summary>
internal static class TestCrlBuilder
{
    private const string SignatureAlgorithm = "SHA256withRSA";

    /// <summary>
    /// Builds a CRL issued (and signed) by <paramref name="issuerCertificatePem"/> /
    /// <paramref name="issuerPrivateKeyPem"/>, revoking every certificate in
    /// <paramref name="revokedCertificatePems"/> (by serial number). Returns the CRL as a PEM string. An empty
    /// <paramref name="revokedCertificatePems"/> yields a valid, empty CRL.
    /// </summary>
    internal static string CreateCrl(string issuerCertificatePem, string issuerPrivateKeyPem, params string[] revokedCertificatePems)
    {
        var issuerCertificate = ReadCertificate(issuerCertificatePem);
        var issuerPrivateKey = ReadPrivateKey(issuerPrivateKeyPem);

        var now = DateTime.UtcNow;
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(issuerCertificate.SubjectDN);
        generator.SetThisUpdate(now.AddDays(-1));
        generator.SetNextUpdate(now.AddDays(1));

        foreach (var revokedPem in revokedCertificatePems)
            generator.AddCrlEntry(ReadCertificate(revokedPem).SerialNumber, now.AddDays(-1), CrlReason.KeyCompromise);

        var crl = generator.Generate(new Asn1SignatureFactory(SignatureAlgorithm, issuerPrivateKey));
        return WritePem(crl);
    }

    /// <summary>
    /// Builds a CRL carrying <paramref name="issuerCertificatePem"/>'s issuer DN but signed with a freshly
    /// generated <b>Ed25519</b> key (deliberately a different key type than the RSA issuer). Used to prove that
    /// verifying such a CRL against the RSA issuer surfaces as <see cref="System.Security.Cryptography.CryptographicException"/>
    /// rather than leaking a raw key-type-cast failure.
    /// </summary>
    internal static string CreateEd25519SignedCrl(string issuerCertificatePem, params string[] revokedCertificatePems)
    {
        var issuerCertificate = ReadCertificate(issuerCertificatePem);

        var edGenerator = new Ed25519KeyPairGenerator();
        edGenerator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var edKeyPair = edGenerator.GenerateKeyPair();

        var now = DateTime.UtcNow;
        var generator = new X509V2CrlGenerator();
        generator.SetIssuerDN(issuerCertificate.SubjectDN);
        generator.SetThisUpdate(now.AddDays(-1));
        generator.SetNextUpdate(now.AddDays(1));

        foreach (var revokedPem in revokedCertificatePems)
            generator.AddCrlEntry(ReadCertificate(revokedPem).SerialNumber, now.AddDays(-1), CrlReason.KeyCompromise);

        var crl = generator.Generate(new Asn1SignatureFactory("Ed25519", edKeyPair.Private));
        return WritePem(crl);
    }

    /// <summary>
    /// Builds a CRL RSA-signed by <paramref name="issuerCertificatePem"/> / <paramref name="issuerPrivateKeyPem"/>,
    /// then rewrites its signature-algorithm identifier (both the inner <c>tbsCertList.signature</c> and the outer
    /// <c>signatureAlgorithm</c>) to an <b>unrecognised OID</b>. The result still parses into an <see cref="X509Crl"/>,
    /// but no verifier can be constructed for it, so verifying it raises BouncyCastle's
    /// <c>SecurityUtilityException</c> ("Signing mechanism … not recognised."). Used to prove that
    /// <c>IsRevoked</c> surfaces that as <see cref="System.Security.Cryptography.CryptographicException"/> rather
    /// than leaking the raw BouncyCastle type.
    /// </summary>
    internal static string CreateCrlWithUnknownSignatureAlgorithm(string issuerCertificatePem, string issuerPrivateKeyPem, params string[] revokedCertificatePems)
    {
        var validCrl = ReadCrl(CreateCrl(issuerCertificatePem, issuerPrivateKeyPem, revokedCertificatePems));

        // OID 1.2.3.4.5.6.7.8.9 maps to no known signing mechanism.
        var unknownAlgorithm = new AlgorithmIdentifier(new DerObjectIdentifier("1.2.3.4.5.6.7.8.9")).ToAsn1Object();
        var certificateList = (Asn1Sequence)Asn1Object.FromByteArray(validCrl.GetEncoded());

        // A v2 CRL's TBSCertList is [0]=version, [1]=signature AlgorithmIdentifier, … — replace element 1.
        var tbsItems = ((Asn1Sequence)certificateList[0]).ToArray();
        tbsItems[1] = unknownAlgorithm;
        var outerItems = certificateList.ToArray();
        outerItems[0] = new DerSequence(tbsItems);
        outerItems[1] = unknownAlgorithm;

        return WritePem(new X509Crl(CertificateList.GetInstance(new DerSequence(outerItems))));
    }

    private static X509Crl ReadCrl(string pem)
    {
        using var reader = new StringReader(pem);
        return (X509Crl)new PemReader(reader).ReadObject();
    }

    private static X509Certificate ReadCertificate(string pem)
    {
        using var reader = new StringReader(pem);
        return (X509Certificate)new PemReader(reader).ReadObject();
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

    private static string WritePem(object pemObject)
    {
        using var writer = new StringWriter();
        new PemWriter(writer).WriteObject(pemObject);
        return writer.ToString();
    }
}
