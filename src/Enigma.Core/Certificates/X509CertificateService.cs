using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using Enigma.Core.Asymmetric.PublicKey;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;

namespace Enigma.Core.Certificates;

/// <summary>
/// Provides X.509 certificate generation, CSR handling, issuance, chain validation and inspection, backed by
/// BouncyCastle behind a PEM-string contract.
/// </summary>
/// <remarks>
/// Certificates, CSRs and CRLs cross the API as PEM text and key material as <see cref="RsaKey"/> handles, so no
/// BouncyCastle type appears on the public surface (principle 1). BouncyCastle parse/signing failures never
/// escape: malformed input surfaces as <see cref="ArgumentException"/> and signing/decryption failures as
/// <see cref="CryptographicException"/>.
/// </remarks>
public sealed class X509CertificateService : IX509CertificateService
{
    private readonly SecureRandom _random = new();

    /// <inheritdoc />
    public string GenerateSelfSignedCertificate(string subjectDistinguishedName, RsaKey privateKey, DateTimeOffset notBefore, DateTimeOffset notAfter, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, X509CertificateOptions? options = null)
    {
        if (subjectDistinguishedName is null) throw new ArgumentNullException(nameof(subjectDistinguishedName));
        if (privateKey is null) throw new ArgumentNullException(nameof(privateKey));

        var subject = X509CertUtils.ParseDistinguishedName(subjectDistinguishedName, nameof(subjectDistinguishedName));
        var signingKey = RequirePrivate(privateKey, nameof(privateKey));
        var publicKey = X509CertUtils.DerivePublicKey(signingKey);

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(X509CertUtils.GenerateSerialNumber(_random));
        generator.SetIssuerDN(subject);
        generator.SetSubjectDN(subject);
        generator.SetNotBefore(notBefore.UtcDateTime);
        generator.SetNotAfter(notAfter.UtcDateTime);
        generator.SetPublicKey(publicKey);
        X509CertUtils.ApplyExtensions(generator, options);

        return X509CertUtils.WritePem(Sign(generator, signatureAlgorithm, signingKey));
    }

    /// <inheritdoc />
    public string GenerateCertificateSigningRequest(string subjectDistinguishedName, RsaKey privateKey, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa)
    {
        if (subjectDistinguishedName is null) throw new ArgumentNullException(nameof(subjectDistinguishedName));
        if (privateKey is null) throw new ArgumentNullException(nameof(privateKey));

        var subject = X509CertUtils.ParseDistinguishedName(subjectDistinguishedName, nameof(subjectDistinguishedName));
        var signingKey = RequirePrivate(privateKey, nameof(privateKey));
        var publicKey = X509CertUtils.DerivePublicKey(signingKey);

        Pkcs10CertificationRequest csr;
        try
        {
            csr = new Pkcs10CertificationRequest(
                SignatureAlgorithms.ToJcaName(signatureAlgorithm), subject, publicKey, attributes: null, signingKey);
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
    public string IssueCertificate(string certificateSigningRequestPem, string issuerCertificatePem, RsaKey issuerPrivateKey, DateTimeOffset notBefore, DateTimeOffset notAfter, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, X509CertificateOptions? options = null)
    {
        if (issuerPrivateKey is null) throw new ArgumentNullException(nameof(issuerPrivateKey));

        var csr = X509CertUtils.ReadCsr(certificateSigningRequestPem, nameof(certificateSigningRequestPem));
        if (!VerifyCsr(csr))
            throw new CryptographicException("The certificate signing request signature is invalid.");

        var issuerCertificate = X509CertUtils.ReadCertificate(issuerCertificatePem, nameof(issuerCertificatePem));
        var issuerSigningKey = RequirePrivate(issuerPrivateKey, nameof(issuerPrivateKey));
        var csrInfo = csr.GetCertificationRequestInfo();

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(X509CertUtils.GenerateSerialNumber(_random));
        generator.SetIssuerDN(issuerCertificate.SubjectDN);
        generator.SetSubjectDN(csrInfo.Subject);
        generator.SetNotBefore(notBefore.UtcDateTime);
        generator.SetNotAfter(notAfter.UtcDateTime);
        generator.SetPublicKey(csr.GetPublicKey());
        X509CertUtils.ApplyExtensions(generator, options);

        return X509CertUtils.WritePem(Sign(generator, signatureAlgorithm, issuerSigningKey));
    }

    /// <inheritdoc />
    public bool ValidateChain(string certificatePem, IReadOnlyList<string> trustedRootPems, IReadOnlyList<string>? intermediatePems = null)
    {
        if (trustedRootPems is null) throw new ArgumentNullException(nameof(trustedRootPems));

        var certificate = X509CertUtils.ReadCertificate(certificatePem, nameof(certificatePem));

        // No trusted roots means nothing can serve as an anchor: the chain cannot be trusted.
        if (trustedRootPems.Count == 0)
            return false;

        var trustAnchors = new HashSet<TrustAnchor>();
        foreach (var rootPem in trustedRootPems)
            trustAnchors.Add(new TrustAnchor(X509CertUtils.ReadCertificate(rootPem, nameof(trustedRootPems)), nameConstraints: null));

        // Candidate certificates the builder may use to assemble the path: the leaf plus any supplied
        // intermediates. Order is irrelevant — a path *builder* discovers the correct leaf→anchor ordering,
        // unlike a validator (which only checks an already-ordered path). The anchors are supplied separately.
        var candidateCertificates = new List<X509Certificate> { certificate };
        if (intermediatePems is not null)
            foreach (var intermediatePem in intermediatePems)
                candidateCertificates.Add(X509CertUtils.ReadCertificate(intermediatePem, nameof(intermediatePems)));

        try
        {
            var target = new X509CertStoreSelector { Certificate = certificate };
            // Revocation is intentionally NOT checked here — that is the separate IsRevoked responsibility.
            var parameters = new PkixBuilderParameters(trustAnchors, target) { IsRevocationEnabled = false };
            parameters.AddStoreCert(CollectionUtilities.CreateStore(candidateCertificates));
            new PkixCertPathBuilder().Build(parameters);
            return true;
        }
        catch (PkixCertPathBuilderException)
        {
            // No valid path could be built or validated (untrusted root, missing intermediate, expired /
            // not-yet-valid, broken signature) — reported as invalid rather than raised.
            return false;
        }
    }

    /// <inheritdoc />
    public bool IsRevoked(string certificatePem, string crlPem, string issuerCertificatePem)
    {
        var certificate = X509CertUtils.ReadCertificate(certificatePem, nameof(certificatePem));
        var issuerCertificate = X509CertUtils.ReadCertificate(issuerCertificatePem, nameof(issuerCertificatePem));
        var crl = X509CertUtils.ReadCrl(crlPem, nameof(crlPem));

        try
        {
            // Only trust a CRL that is genuinely signed by the named issuer.
            crl.Verify(issuerCertificate.GetPublicKey());
        }
        // Any failure to construct or run the CRL's signature verifier is treated as an unverifiable CRL. Besides
        // GeneralSecurityException/CryptoException, BouncyCastle's verifier setup surfaces a key-type mismatch (e.g.
        // an Ed25519-signed CRL against an RSA issuer) as InvalidCastException, and an unrecognised signature-algorithm
        // OID as SecurityUtilityException; none of these may escape as a non-contract exception.
        catch (Exception ex) when (ex is GeneralSecurityException or CryptoException or InvalidCastException or SecurityUtilityException)
        {
            throw new CryptographicException(
                "The CRL signature could not be verified against the issuer certificate.", ex);
        }

        return crl.GetRevokedCertificate(certificate.SerialNumber) is not null;
    }

    /// <inheritdoc />
    public CertificateInfo GetCertificateInfo(string certificatePem)
    {
        var certificate = X509CertUtils.ReadCertificate(certificatePem, nameof(certificatePem));
        return X509CertUtils.ExtractInfo(certificate);
    }

    /// <inheritdoc />
    public byte[] ExportPkcs12(string certificatePem, RsaKey privateKey, char[] password, IReadOnlyList<string>? chainPems = null)
    {
        if (privateKey is null) throw new ArgumentNullException(nameof(privateKey));
        // The sole password protects the produced archive; the key handle carries no passphrase of its own.
        if (password is null) throw new ArgumentNullException(nameof(password));

        var certificate = X509CertUtils.ReadCertificate(certificatePem, nameof(certificatePem));
        var key = RequirePrivate(privateKey, nameof(privateKey));

        var chain = new List<X509Certificate>();
        if (chainPems is not null)
            foreach (var chainPem in chainPems)
                chain.Add(X509CertUtils.ReadCertificate(chainPem, nameof(chainPems)));

        return X509CertUtils.ExportPkcs12(certificate, key, password, chain, _random);
    }

    /// <inheritdoc />
    public (string certificatePem, RsaKey privateKey) ImportPkcs12(byte[] pkcs12, char[] password)
    {
        if (password is null) throw new ArgumentNullException(nameof(password));

        var (certificate, privateKey) = X509CertUtils.ImportPkcs12(pkcs12, password, nameof(pkcs12));

        // The extracted key becomes a handle directly: no private-key PEM is written here for the caller to
        // re-parse, which is the whole point of the handle crossing this API.
        if (privateKey is not RsaKeyParameters { IsPrivate: true } rsaPrivateKey)
            throw new ArgumentException(
                "The PKCS#12 archive's key entry is not an RSA private key.", nameof(pkcs12));

        return (X509CertUtils.WritePem(certificate), RsaKey.FromBcKey(rsaPrivateKey));
    }

    /// <inheritdoc />
    public byte[] ExportCertificateToDer(string certificatePem)
        => X509CertUtils.ToDer(X509CertUtils.ReadCertificate(certificatePem, nameof(certificatePem)));

    /// <inheritdoc />
    public string ImportCertificateFromDer(byte[] derEncodedCertificate)
        => X509CertUtils.WritePem(X509CertUtils.ReadCertificateFromDer(derEncodedCertificate, nameof(derEncodedCertificate)));

    // The BouncyCastle key a signing / bundling operation runs on. A public-only handle is a bad argument to the
    // method rather than a broken handle, so it is reported as ArgumentException naming the parameter the caller
    // passed — the same mapping PublicKeyService applies to its own private-key operations.
    private static RsaKeyParameters RequirePrivate(RsaKey key, string paramName)
    {
        if (!key.HasPrivateKey)
            throw new ArgumentException(
                "The key holds only a public key; this operation requires a private key.", paramName);

        return key.BcKey;
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
