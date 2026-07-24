namespace Enigma.Core;

/// <summary>
/// Canonical RSA signature algorithms shared across the library — used by RSA signing and X.509
/// certificate signing. Each value pairs a hash function with RSA (RSASSA-PKCS1-v1_5). Selecting the
/// algorithm through this enum, rather than a raw algorithm-name string, gives a single, discoverable
/// source of truth and keeps the public API free of the underlying provider's naming convention.
/// </summary>
public enum RsaSignatureAlgorithm
{
    /// <summary>SHA-1 with RSA.</summary>
    Sha1WithRsa,

    /// <summary>SHA-256 with RSA. The library-wide default.</summary>
    Sha256WithRsa,

    /// <summary>SHA-384 with RSA.</summary>
    Sha384WithRsa,

    /// <summary>SHA-512 with RSA.</summary>
    Sha512WithRsa,
}
