namespace Enigma.Core.KeyDerivation;

/// <summary>
/// The pseudorandom function (PRF) used by PBKDF2 to derive key material. PBKDF2 repeatedly applies an
/// HMAC over the password and salt; this selects which hash algorithm backs that HMAC.
/// </summary>
public enum Pbkdf2Prf
{
    /// <summary>HMAC using SHA-1. Provided for legacy interoperability; prefer a stronger PRF.</summary>
    HmacSha1,

    /// <summary>HMAC using SHA-256.</summary>
    HmacSha256,

    /// <summary>HMAC using SHA-384.</summary>
    HmacSha384,

    /// <summary>HMAC using SHA-512.</summary>
    HmacSha512,
}
