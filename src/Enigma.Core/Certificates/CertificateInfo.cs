using System;
using System.Numerics;

namespace Enigma.Core.Certificates;

/// <summary>
/// Describes the fields read back from a parsed X.509 certificate. This is a pure, immutable data carrier:
/// the values are decoded from an existing certificate, never used to select behaviour.
/// </summary>
public sealed record CertificateInfo
{
    /// <summary>The subject distinguished name (e.g. <c>CN=example.com, O=Example, C=US</c>).</summary>
    public required string Subject { get; init; }

    /// <summary>The issuer distinguished name. Equal to <see cref="Subject"/> for a self-signed certificate.</summary>
    public required string Issuer { get; init; }

    /// <summary>The certificate serial number, as a non-negative integer of arbitrary size.</summary>
    public required BigInteger SerialNumber { get; init; }

    /// <summary>The inclusive start of the certificate's validity period.</summary>
    public required DateTimeOffset NotBefore { get; init; }

    /// <summary>The inclusive end of the certificate's validity period.</summary>
    public required DateTimeOffset NotAfter { get; init; }

    /// <summary>
    /// The name of the algorithm the certificate was signed with, as recorded in the certificate. This is a
    /// read-back value and may name any algorithm (not only the RSA variants selectable at generation time).
    /// </summary>
    public required string SignatureAlgorithm { get; init; }

    /// <summary>The X.509 version number (e.g. <c>3</c> for a v3 certificate).</summary>
    public required int Version { get; init; }

    /// <summary>The certificate thumbprint (fingerprint), as an uppercase hexadecimal string.</summary>
    public required string Thumbprint { get; init; }
}
