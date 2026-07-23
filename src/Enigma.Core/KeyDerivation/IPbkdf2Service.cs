namespace Enigma.Core.KeyDerivation;

/// <summary>
/// Derives cryptographic key material from a password using PBKDF2 (Password-Based Key Derivation
/// Function 2). Iterating an HMAC over the password and salt slows brute-force attacks.
/// </summary>
public interface IPbkdf2Service
{
    /// <summary>
    /// Derives a key of the requested length from a password and salt.
    /// </summary>
    /// <param name="password">The password bytes to derive from.</param>
    /// <param name="salt">The salt. Should be random and unique per password.</param>
    /// <param name="iterations">
    /// The iteration count (work factor). Higher values increase resistance to brute-force attacks at
    /// the cost of more computation.
    /// </param>
    /// <param name="keySizeBytes">The desired length of the derived key, in bytes.</param>
    /// <param name="prf">
    /// The pseudorandom function backing the derivation. Defaults to <see cref="Pbkdf2Prf.HmacSha256"/>.
    /// </param>
    /// <returns>The derived key, <paramref name="keySizeBytes"/> bytes long.</returns>
    /// <remarks>
    /// Choose <paramref name="iterations"/> as high as your latency budget allows. As a floor, OWASP
    /// recommends at least 600,000 iterations for PBKDF2-HMAC-SHA256 (2023 guidance). The
    /// <paramref name="password"/> array is used as-is: it is neither re-encoded nor cleared, so the
    /// caller owns both its encoding and its lifetime.
    /// </remarks>
    /// <exception cref="System.ArgumentNullException">
    /// <paramref name="password"/> or <paramref name="salt"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="System.ArgumentException">
    /// <paramref name="iterations"/> or <paramref name="keySizeBytes"/> is not greater than zero.
    /// </exception>
    byte[] DeriveKey(
        byte[] password,
        byte[] salt,
        int iterations,
        int keySizeBytes,
        Pbkdf2Prf prf = Pbkdf2Prf.HmacSha256);
}
