using System.Collections.Generic;

namespace Enigma.Core.Certificates;

/// <summary>
/// Optional X.509 v3 extensions to embed when generating a self-signed certificate or issuing a certificate
/// from a CSR. Every property is optional: a <see langword="null"/> options argument, or a <see langword="null"/>
/// property, omits the corresponding extension. Expressed with BouncyCastle-free types (<see cref="bool"/>,
/// <see cref="X509KeyUsage"/> and a string list) so no provider type appears on the public surface; the values
/// are mapped to the <c>BasicConstraints</c>, <c>KeyUsage</c> and <c>SubjectAlternativeName</c> extensions internally.
/// </summary>
public sealed record X509CertificateOptions
{
    /// <summary>
    /// Whether the certificate is a certificate authority. When set, emits the (critical) <c>BasicConstraints</c>
    /// extension with the <c>cA</c> flag accordingly; when <see langword="null"/>, the extension is omitted. A
    /// value of <see langword="true"/> is required for a certificate that must act as a trust anchor or an
    /// intermediate in a validated chain.
    /// </summary>
    public bool? IsCertificateAuthority { get; init; }

    /// <summary>
    /// The permitted key usages. When set, emits the (critical) <c>KeyUsage</c> extension with the corresponding
    /// bits; when <see langword="null"/>, the extension is omitted.
    /// </summary>
    public X509KeyUsage? KeyUsage { get; init; }

    /// <summary>
    /// The subject alternative names (for example DNS names) to embed. When non-<see langword="null"/> and
    /// non-empty, emits the (non-critical) <c>SubjectAlternativeName</c> extension; when <see langword="null"/>
    /// or empty, the extension is omitted. Each entry is treated as a DNS name.
    /// </summary>
    public IReadOnlyList<string>? SubjectAlternativeNames { get; init; }
}
