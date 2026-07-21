using System;
using System.Collections.Generic;

namespace Enigma.Core.Certificates;

/// <summary>
/// Provides X.509 certificate generation, issuance and validation.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete X.509 logic arrives with the certificate implementation feature.
/// </remarks>
public sealed class X509CertificateService : IX509CertificateService
{
    /// <inheritdoc />
    public string GenerateSelfSignedCertificate(string subjectDistinguishedName, string privateKeyPem, DateTimeOffset notBefore, DateTimeOffset notAfter, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null) => throw new NotImplementedException();

    /// <inheritdoc />
    public string GenerateCertificateSigningRequest(string subjectDistinguishedName, string privateKeyPem, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null) => throw new NotImplementedException();

    /// <inheritdoc />
    public string IssueCertificate(string certificateSigningRequestPem, string issuerCertificatePem, string issuerPrivateKeyPem, DateTimeOffset notBefore, DateTimeOffset notAfter, RsaSignatureAlgorithm signatureAlgorithm = RsaSignatureAlgorithm.Sha256WithRsa, char[]? password = null) => throw new NotImplementedException();

    /// <inheritdoc />
    public bool ValidateChain(string certificatePem, IReadOnlyList<string> trustedRootPems, IReadOnlyList<string>? intermediatePems = null) => throw new NotImplementedException();

    /// <inheritdoc />
    public bool IsRevoked(string certificatePem, string crlPem, string issuerCertificatePem) => throw new NotImplementedException();

    /// <inheritdoc />
    public CertificateInfo GetCertificateInfo(string certificatePem) => throw new NotImplementedException();
}
