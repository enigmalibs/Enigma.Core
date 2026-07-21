using System;
using System.Collections.Generic;

namespace Enigma.Core.Certificates;

/// <summary>
/// Provides X.509 certificate operations: self-signed certificate generation, certificate signing
/// request (CSR / PKCS#10) generation, issuance of a certificate from a CSR, chain validation against a
/// set of trusted roots, and revocation checking against a certificate revocation list (CRL).
/// </summary>
/// <remarks>
/// Certificates, CSRs, CRLs and keys cross this API as PEM-encoded text; no BouncyCastle types are
/// exposed. All data is small and structured, so every operation works in memory rather than on streams.
/// Where a private-key PEM is encrypted, the passphrase is passed directly as a <see cref="char"/> array.
/// </remarks>
public interface IX509CertificateService
{
    /// <summary>Generates a self-signed X.509 certificate for the given subject and key.</summary>
    /// <param name="subjectDistinguishedName">The subject (and, being self-signed, issuer) distinguished name.</param>
    /// <param name="privateKeyPem">The private key that both certifies the subject and signs the certificate, PEM-encoded.</param>
    /// <param name="notBefore">The inclusive start of the certificate's validity period.</param>
    /// <param name="notAfter">The inclusive end of the certificate's validity period.</param>
    /// <param name="signatureAlgorithm">The algorithm used to sign the certificate. Defaults to <see cref="RsaSignatureAlgorithm.Sha256WithRsa"/>.</param>
    /// <param name="password">The passphrase protecting an encrypted private-key PEM, or <see langword="null"/> if the PEM is not encrypted.</param>
    /// <returns>The self-signed certificate, PEM-encoded.</returns>
    string GenerateSelfSignedCertificate(string subjectDistinguishedName, string privateKeyPem, DateTimeOffset notBefore, DateTimeOffset notAfter, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null);

    /// <summary>Generates a PKCS#10 certificate signing request (CSR) for the given subject and key.</summary>
    /// <param name="subjectDistinguishedName">The subject distinguished name to request a certificate for.</param>
    /// <param name="privateKeyPem">The private key whose public half is certified and which signs the request, PEM-encoded.</param>
    /// <param name="signatureAlgorithm">The algorithm used to sign the request. Defaults to <see cref="RsaSignatureAlgorithm.Sha256WithRsa"/>.</param>
    /// <param name="password">The passphrase protecting an encrypted private-key PEM, or <see langword="null"/> if the PEM is not encrypted.</param>
    /// <returns>The certificate signing request, PEM-encoded.</returns>
    string GenerateCertificateSigningRequest(string subjectDistinguishedName, string privateKeyPem, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null);

    /// <summary>Issues a certificate by signing a certificate signing request with an issuer's certificate and key.</summary>
    /// <param name="certificateSigningRequestPem">The CSR to issue a certificate for, PEM-encoded.</param>
    /// <param name="issuerCertificatePem">The issuing (CA) certificate, PEM-encoded; its subject becomes the issued certificate's issuer.</param>
    /// <param name="issuerPrivateKeyPem">The issuer's private key, used to sign the issued certificate, PEM-encoded.</param>
    /// <param name="notBefore">The inclusive start of the issued certificate's validity period.</param>
    /// <param name="notAfter">The inclusive end of the issued certificate's validity period.</param>
    /// <param name="signatureAlgorithm">The algorithm used to sign the issued certificate. Defaults to <see cref="RsaSignatureAlgorithm.Sha256WithRsa"/>.</param>
    /// <param name="password">The passphrase protecting an encrypted issuer private-key PEM, or <see langword="null"/> if the PEM is not encrypted.</param>
    /// <returns>The issued certificate, PEM-encoded.</returns>
    string IssueCertificate(string certificateSigningRequestPem, string issuerCertificatePem, string issuerPrivateKeyPem, DateTimeOffset notBefore, DateTimeOffset notAfter, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null);

    /// <summary>Validates that a certificate chains to one of the supplied trusted roots.</summary>
    /// <param name="certificatePem">The leaf certificate to validate, PEM-encoded.</param>
    /// <param name="trustedRootPems">The trusted root (anchor) certificates, PEM-encoded.</param>
    /// <param name="intermediatePems">Additional untrusted intermediate certificates that may be needed to build the chain, PEM-encoded, or <see langword="null"/> if none.</param>
    /// <returns><see langword="true"/> if a valid chain to a trusted root can be built; otherwise <see langword="false"/>.</returns>
    bool ValidateChain(string certificatePem, IReadOnlyList<string> trustedRootPems, IReadOnlyList<string>? intermediatePems = null);

    /// <summary>Determines whether a certificate is revoked according to a certificate revocation list (CRL).</summary>
    /// <param name="certificatePem">The certificate to check, PEM-encoded.</param>
    /// <param name="crlPem">The certificate revocation list, PEM-encoded.</param>
    /// <param name="issuerCertificatePem">The issuer certificate whose key signed the CRL, used to verify the CRL's authenticity, PEM-encoded.</param>
    /// <returns><see langword="true"/> if the certificate is listed as revoked; otherwise <see langword="false"/>.</returns>
    bool IsRevoked(string certificatePem, string crlPem, string issuerCertificatePem);

    /// <summary>Reads the descriptive fields from a certificate.</summary>
    /// <param name="certificatePem">The certificate to inspect, PEM-encoded.</param>
    /// <returns>The parsed certificate fields.</returns>
    CertificateInfo GetCertificateInfo(string certificatePem);
}
