namespace Enigma.Core.Otp;

/// <summary>
/// The hash algorithm backing the HMAC used to generate one-time passwords. HOTP and TOTP derive each
/// code from an HMAC over a moving factor (a counter or a time step); this selects which hash that HMAC
/// uses. Authenticator apps default to SHA-1.
/// </summary>
public enum OtpHashAlgorithm
{
    /// <summary>HMAC using SHA-1. The default assumed by most authenticator apps (RFC 4226 / RFC 6238).</summary>
    Sha1,

    /// <summary>HMAC using SHA-256.</summary>
    Sha256,

    /// <summary>HMAC using SHA-512.</summary>
    Sha512,
}
