using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Enigma.Core.Asymmetric.PublicKey;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Enigma.Core.Certificates;

/// <summary>
/// Provides X.509 certificate generation, CSR handling, issuance, chain validation and inspection, backed by
/// BouncyCastle behind a PEM-string contract.
/// </summary>
/// <remarks>
/// Certificates, CSRs and keys cross the API as PEM text and passphrases as <see cref="char"/> arrays, so no
/// BouncyCastle type appears on the public surface (principle 1). BouncyCastle parse/signing failures never
/// escape: malformed input surfaces as <see cref="ArgumentException"/> and signing/decryption failures as
/// <see cref="CryptographicException"/>.
/// </remarks>
public sealed class X509CertificateService : IX509CertificateService
{
    private readonly SecureRandom _random = new();

    /// <inheritdoc />
    public string GenerateSelfSignedCertificate(string subjectDistinguishedName, string privateKeyPem, DateTimeOffset notBefore, DateTimeOffset notAfter, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null, X509CertificateOptions? options = null)
    {
        if (subjectDistinguishedName is null) throw new ArgumentNullException(nameof(subjectDistinguishedName));

        var subject = X509CertUtils.ParseDistinguishedName(subjectDistinguishedName, nameof(subjectDistinguishedName));
        var privateKey = PemUtils.ParsePrivateKey(privateKeyPem, password);
        var publicKey = X509CertUtils.DerivePublicKey(privateKey);

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(X509CertUtils.GenerateSerialNumber(_random));
        generator.SetIssuerDN(subject);
        generator.SetSubjectDN(subject);
        generator.SetNotBefore(notBefore.UtcDateTime);
        generator.SetNotAfter(notAfter.UtcDateTime);
        generator.SetPublicKey(publicKey);
        X509CertUtils.ApplyExtensions(generator, options);

        return X509CertUtils.WritePem(Sign(generator, signatureAlgorithm, privateKey));
    }

    /// <inheritdoc />
    public string GenerateCertificateSigningRequest(string subjectDistinguishedName, string privateKeyPem, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null)
    {
        if (subjectDistinguishedName is null) throw new ArgumentNullException(nameof(subjectDistinguishedName));

        var subject = X509CertUtils.ParseDistinguishedName(subjectDistinguishedName, nameof(subjectDistinguishedName));
        var privateKey = PemUtils.ParsePrivateKey(privateKeyPem, password);
        var publicKey = X509CertUtils.DerivePublicKey(privateKey);

        Pkcs10CertificationRequest csr;
        try
        {
            csr = new Pkcs10CertificationRequest(
                SignatureAlgorithms.ToJcaName(signatureAlgorithm), subject, publicKey, attributes: null, privateKey);
        }
        catch (CryptoException ex)
        {
            throw new CryptographicException("Certificate signing request generation failed.", ex);
        }

        return X509CertUtils.WritePem(csr);
    }

    /// <inheritdoc />
    public bool IsCertificateSigningRequestValid(string certificateSigningRequestPem)
    {
        var csr = X509CertUtils.ReadCsr(certificateSigningRequestPem, nameof(certificateSigningRequestPem));
        return VerifyCsr(csr);
    }

    /// <inheritdoc />
    public string IssueCertificate(string certificateSigningRequestPem, string issuerCertificatePem, string issuerPrivateKeyPem, DateTimeOffset notBefore, DateTimeOffset notAfter, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null, X509CertificateOptions? options = null)
    {
        var csr = X509CertUtils.ReadCsr(certificateSigningRequestPem, nameof(certificateSigningRequestPem));
        if (!VerifyCsr(csr))
            throw new CryptographicException("The certificate signing request signature is invalid.");

        var issuerCertificate = X509CertUtils.ReadCertificate(issuerCertificatePem, nameof(issuerCertificatePem));
        var issuerPrivateKey = PemUtils.ParsePrivateKey(issuerPrivateKeyPem, password);
        var csrInfo = csr.GetCertificationRequestInfo();

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(X509CertUtils.GenerateSerialNumber(_random));
        generator.SetIssuerDN(issuerCertificate.SubjectDN);
        generator.SetSubjectDN(csrInfo.Subject);
        generator.SetNotBefore(notBefore.UtcDateTime);
        generator.SetNotAfter(notAfter.UtcDateTime);
        generator.SetPublicKey(csr.GetPublicKey());
        X509CertUtils.ApplyExtensions(generator, options);

        return X509CertUtils.WritePem(Sign(generator, signatureAlgorithm, issuerPrivateKey));
    }

    /// <inheritdoc />
    public bool ValidateChain(string certificatePem, IReadOnlyList<string> trustedRootPems, IReadOnlyList<string>? intermediatePems = null) => throw new NotImplementedException();

    /// <inheritdoc />
    public bool IsRevoked(string certificatePem, string crlPem, string issuerCertificatePem) => throw new NotImplementedException();

    /// <inheritdoc />
    public CertificateInfo GetCertificateInfo(string certificatePem)
    {
        var certificate = X509CertUtils.ReadCertificate(certificatePem, nameof(certificatePem));
        return X509CertUtils.ExtractInfo(certificate);
    }

    // Signs the assembled certificate, wrapping a BouncyCastle signing failure as CryptographicException.
    private X509Certificate Sign(X509V3CertificateGenerator generator, RsaSignatureAlgorithm algorithm, AsymmetricKeyParameter signingKey)
    {
        try
        {
            var factory = new Asn1SignatureFactory(SignatureAlgorithms.ToJcaName(algorithm), signingKey, _random);
            return generator.Generate(factory);
        }
        catch (CryptoException ex)
        {
            throw new CryptographicException("Certificate signing failed.", ex);
        }
    }

    // Verifies a CSR's self-signature; a structurally valid CSR with a bad signature returns false rather than throwing.
    private static bool VerifyCsr(Pkcs10CertificationRequest csr)
    {
        try
        {
            return csr.Verify();
        }
        catch (Exception ex) when (ex is CryptoException or GeneralSecurityException)
        {
            return false;
        }
    }
}
