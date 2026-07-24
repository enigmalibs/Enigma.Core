namespace Enigma.Core.Otp;

/// <summary>
/// Generates and verifies HMAC-based one-time passwords (HOTP, RFC 4226). Each code is derived from a
/// shared secret and a monotonically increasing counter. The number of digits and the backing hash
/// algorithm are fixed when the service is created by the factory.
/// </summary>
public interface IHotpService
{
    /// <summary>
    /// Generates the HOTP code for the given counter value.
    /// </summary>
    /// <param name="secret">The shared secret key.</param>
    /// <param name="counter">The moving factor (event counter). Must match between generator and verifier.</param>
    /// <returns>
    /// The one-time password as a numeric string, zero-padded to the digit count the service was created
    /// for.
    /// </returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="secret"/> is <see langword="null"/>.</exception>
    string GenerateCode(byte[] secret, long counter);

    /// <summary>
    /// Verifies that a code matches the HOTP generated for the given counter value.
    /// </summary>
    /// <param name="secret">The shared secret key.</param>
    /// <param name="counter">The moving factor (event counter) to check against.</param>
    /// <param name="code">The candidate one-time password to verify.</param>
    /// <returns><see langword="true"/> if the code is valid for the counter; otherwise <see langword="false"/>.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="secret"/> or <paramref name="code"/> is <see langword="null"/>.</exception>
    bool VerifyCode(byte[] secret, long counter, string code);

    /// <summary>
    /// Verifies a code against the HOTP for the given counter and a forward look-ahead window, tolerating
    /// server-side counter drift (RFC 4226 §7.4 resynchronization).
    /// </summary>
    /// <param name="secret">The shared secret key.</param>
    /// <param name="counter">The starting counter value.</param>
    /// <param name="code">The candidate one-time password to verify.</param>
    /// <param name="window">
    /// The number of counter values after <paramref name="counter"/> to also accept (inclusive). Must be
    /// non-negative; 0 checks only <paramref name="counter"/>.
    /// </param>
    /// <returns><see langword="true"/> if the code is valid within the window; otherwise <see langword="false"/>.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="secret"/> or <paramref name="code"/> is <see langword="null"/>.</exception>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="window"/> is negative.</exception>
    bool VerifyCode(byte[] secret, long counter, string code, int window);

    /// <summary>
    /// Verifies a code against the HOTP for the given counter and a forward look-ahead window, reporting
    /// which counter value matched so a server can resynchronize its counter after drift.
    /// </summary>
    /// <param name="secret">The shared secret key.</param>
    /// <param name="counter">The starting counter value.</param>
    /// <param name="code">The candidate one-time password to verify.</param>
    /// <param name="window">
    /// The number of counter values after <paramref name="counter"/> to also accept (inclusive). Must be
    /// non-negative; 0 checks only <paramref name="counter"/>.
    /// </param>
    /// <param name="matchedCounter">
    /// When this method returns, the counter value that matched, or <c>-1</c> if none did. The whole
    /// window is scanned without early exit, so verification time does not reveal where a match occurred.
    /// </param>
    /// <returns><see langword="true"/> if the code is valid within the window; otherwise <see langword="false"/>.</returns>
    /// <exception cref="System.ArgumentNullException"><paramref name="secret"/> or <paramref name="code"/> is <see langword="null"/>.</exception>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="window"/> is negative.</exception>
    bool VerifyCode(byte[] secret, long counter, string code, int window, out long matchedCounter);
}
