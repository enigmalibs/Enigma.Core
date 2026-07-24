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
    /// <param name="options">Optional X.509 v3 extensions (CA flag, key usage, subject alternative names) to embed, or <see langword="null"/> to embed none.</param>
    /// <returns>The self-signed certificate, PEM-encoded.</returns>
    string GenerateSelfSignedCertificate(string subjectDistinguishedName, string privateKeyPem, DateTimeOffset notBefore, DateTimeOffset notAfter, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null, X509CertificateOptions? options = null);

    /// <summary>Generates a PKCS#10 certificate signing request (CSR) for the given subject and key.</summary>
    /// <param name="subjectDistinguishedName">The subject distinguished name to request a certificate for.</param>
    /// <param name="privateKeyPem">The private key whose public half is certified and which signs the request, PEM-encoded.</param>
    /// <param name="signatureAlgorithm">The algorithm used to sign the request. Defaults to <see cref="RsaSignatureAlgorithm.Sha256WithRsa"/>.</param>
    /// <param name="password">The passphrase protecting an encrypted private-key PEM, or <see langword="null"/> if the PEM is not encrypted.</param>
    /// <returns>The certificate signing request, PEM-encoded.</returns>
    string GenerateCertificateSigningRequest(string subjectDistinguishedName, string privateKeyPem, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null);

    /// <summary>Determines whether a certificate signing request is well-formed and carries a valid self-signature.</summary>
    /// <param name="certificateSigningRequestPem">The certificate signing request to verify, PEM-encoded.</param>
    /// <returns><see langword="true"/> if the CSR parses and its signature verifies against its own embedded public key; otherwise <see langword="false"/>.</returns>
    /// <exception cref="System.ArgumentException"><paramref name="certificateSigningRequestPem"/> is empty or is not a well-formed CSR PEM.</exception>
    bool IsCertificateSigningRequestValid(string certificateSigningRequestPem);

    /// <summary>Issues a certificate by signing a certificate signing request with an issuer's certificate and key.</summary>
    /// <param name="certificateSigningRequestPem">The CSR to issue a certificate for, PEM-encoded.</param>
    /// <param name="issuerCertificatePem">The issuing (CA) certificate, PEM-encoded; its subject becomes the issued certificate's issuer.</param>
    /// <param name="issuerPrivateKeyPem">The issuer's private key, used to sign the issued certificate, PEM-encoded.</param>
    /// <param name="notBefore">The inclusive start of the issued certificate's validity period.</param>
    /// <param name="notAfter">The inclusive end of the issued certificate's validity period.</param>
    /// <param name="signatureAlgorithm">The algorithm used to sign the issued certificate. Defaults to <see cref="RsaSignatureAlgorithm.Sha256WithRsa"/>.</param>
    /// <param name="password">The passphrase protecting an encrypted issuer private-key PEM, or <see langword="null"/> if the PEM is not encrypted.</param>
    /// <param name="options">Optional X.509 v3 extensions (CA flag, key usage, subject alternative names) to embed on the issued certificate, or <see langword="null"/> to embed none.</param>
    /// <returns>The issued certificate, PEM-encoded.</returns>
    string IssueCertificate(string certificateSigningRequestPem, string issuerCertificatePem, string issuerPrivateKeyPem, DateTimeOffset notBefore, DateTimeOffset notAfter, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null, X509CertificateOptions? options = null);

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

    /// <summary>Bundles a certificate and its private key (optionally with a chain) into a password-protected PKCS#12 (PFX).</summary>
    /// <param name="certificatePem">The end-entity certificate to bundle, PEM-encoded.</param>
    /// <param name="privateKeyPem">The (unencrypted) private key matching the certificate, PEM-encoded.</param>
    /// <param name="password">The passphrase protecting the produced PKCS#12. May be empty; must not be <see langword="null"/>.</param>
    /// <param name="chainPems">Additional chain certificates to include (for example the issuing CA), PEM-encoded, or <see langword="null"/> for none.</param>
    /// <returns>The PKCS#12 (PFX) archive. PKCS#12 is a binary format, so this is the one documented exception to the all-PEM contract.</returns>
    /// <exception cref="System.ArgumentException">An input PEM is empty or malformed.</exception>
    byte[] ExportPkcs12(string certificatePem, string privateKeyPem, char[] password, IReadOnlyList<string>? chainPems = null);

    /// <summary>Extracts the end-entity certificate and its private key from a password-protected PKCS#12 (PFX).</summary>
    /// <param name="pkcs12">The PKCS#12 (PFX) archive.</param>
    /// <param name="password">The passphrase unlocking the PKCS#12. May be empty; must not be <see langword="null"/>.</param>
    /// <returns>The extracted certificate (PEM-encoded) and its unencrypted private key (PEM-encoded).</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The PKCS#12 cannot be read with the supplied password (wrong password or corrupt archive).</exception>
    /// <exception cref="System.ArgumentException"><paramref name="pkcs12"/> is empty, or contains no key entry with a certificate.</exception>
    (string certificatePem, string privateKeyPem) ImportPkcs12(byte[] pkcs12, char[] password);

    /// <summary>Converts a PEM-encoded certificate to its raw DER (binary) encoding.</summary>
    /// <param name="certificatePem">The certificate to convert, PEM-encoded.</param>
    /// <returns>The DER-encoded certificate bytes. DER is a binary format, so this is a documented exception to the all-PEM contract.</returns>
    /// <exception cref="System.ArgumentException"><paramref name="certificatePem"/> is empty or malformed.</exception>
    byte[] ExportCertificateToDer(string certificatePem);

    /// <summary>Converts a raw DER-encoded certificate to PEM.</summary>
    /// <param name="derEncodedCertificate">The DER-encoded certificate bytes.</param>
    /// <returns>The certificate, PEM-encoded.</returns>
    /// <exception cref="System.ArgumentException"><paramref name="derEncodedCertificate"/> is empty or is not a well-formed DER certificate.</exception>
    string ImportCertificateFromDer(byte[] derEncodedCertificate);
}
