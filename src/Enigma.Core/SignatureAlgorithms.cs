using System;

namespace Enigma.Core;

/// <summary>
/// Single internal source of truth mapping the public <see cref="RsaSignatureAlgorithm"/> enum to the
/// JCA / BouncyCastle standard-algorithm-name strings (e.g. <c>SHA256withRSA</c>) that the underlying
/// signer and <c>Asn1SignatureFactory</c> consume. Kept internal — the public API selects the algorithm
/// through the enum, never the raw name — and shared by RSA signing and X.509 certificate signing so the
/// two never drift on casing.
/// </summary>
internal static class SignatureAlgorithms
{
    /// <summary>Maps an <see cref="RsaSignatureAlgorithm"/> value to its JCA standard algorithm name.</summary>
    internal static string ToJcaName(RsaSignatureAlgorithm algorithm) => algorithm switch
    {
        RsaSignatureAlgorithm.Sha1WithRsa => "SHA1withRSA",
        RsaSignatureAlgorithm.Sha256WithRsa => "SHA256withRSA",
        RsaSignatureAlgorithm.Sha384WithRsa => "SHA384withRSA",
        RsaSignatureAlgorithm.Sha512WithRsa => "SHA512withRSA",
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, "Unsupported RSA signature algorithm."),
    };
}
