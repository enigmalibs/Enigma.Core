using System;

namespace Enigma.Core.Otp;

/// <summary>
/// Generates and verifies time-based one-time passwords (TOTP, RFC 6238). TOTP extends HOTP by deriving
/// the moving factor from the current time divided into fixed-length steps. The digit count, time-step
/// length and backing hash algorithm are fixed when the service is created by the factory.
/// </summary>
public interface ITotpService
{
    /// <summary>
    /// Generates the TOTP code valid for the time step containing the given instant.
    /// </summary>
    /// <param name="secret">The shared secret key.</param>
    /// <param name="timestamp">The instant to generate the code for.</param>
    /// <returns>
    /// The one-time password as a numeric string, zero-padded to the digit count the service was created
    /// for.
    /// </returns>
    /// <exception cref="ArgumentNullException"><paramref name="secret"/> is <see langword="null"/>.</exception>
    string GenerateCode(byte[] secret, DateTimeOffset timestamp);

    /// <summary>
    /// Generates the TOTP code valid for the time step containing the current UTC instant.
    /// </summary>
    /// <param name="secret">The shared secret key.</param>
    /// <returns>The one-time password for the current time step.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="secret"/> is <see langword="null"/>.</exception>
    string GenerateCode(byte[] secret);

    /// <summary>
    /// Verifies that a code matches a TOTP valid at the given instant, tolerating clock drift within the
    /// specified window of adjacent time steps.
    /// </summary>
    /// <param name="secret">The shared secret key.</param>
    /// <param name="code">The candidate one-time password to verify.</param>
    /// <param name="timestamp">The instant to verify against.</param>
    /// <param name="window">
    /// The number of time steps before and after <paramref name="timestamp"/> to also accept, absorbing
    /// clock drift between generator and verifier. Defaults to 1 (±1 step).
    /// </param>
    /// <returns><see langword="true"/> if the code is valid within the window; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="secret"/> or <paramref name="code"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="window"/> is negative.</exception>
    bool VerifyCode(byte[] secret, string code, DateTimeOffset timestamp, int window = 1);

    /// <summary>
    /// Verifies a code against the current UTC instant, tolerating clock drift within the specified window
    /// of adjacent time steps.
    /// </summary>
    /// <param name="secret">The shared secret key.</param>
    /// <param name="code">The candidate one-time password to verify.</param>
    /// <param name="window">
    /// The number of time steps before and after now to also accept. Defaults to 1 (±1 step).
    /// </param>
    /// <returns><see langword="true"/> if the code is valid within the window; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="secret"/> or <paramref name="code"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="window"/> is negative.</exception>
    bool VerifyCode(byte[] secret, string code, int window = 1);

    /// <summary>
    /// Verifies a code against the given instant within a drift window, reporting which time step matched
    /// so callers can reject replays by accepting only steps later than the last one accepted.
    /// </summary>
    /// <param name="secret">The shared secret key.</param>
    /// <param name="code">The candidate one-time password to verify.</param>
    /// <param name="timestamp">The instant to verify against.</param>
    /// <param name="window">
    /// The number of time steps before and after <paramref name="timestamp"/> to also accept. Must be
    /// non-negative.
    /// </param>
    /// <param name="matchedStep">
    /// When this method returns, the time step that matched, or <c>-1</c> if none did.
    /// </param>
    /// <returns><see langword="true"/> if the code is valid within the window; otherwise <see langword="false"/>.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="secret"/> or <paramref name="code"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="window"/> is negative.</exception>
    bool VerifyCode(byte[] secret, string code, DateTimeOffset timestamp, int window, out long matchedStep);

    /// <summary>
    /// Returns the number of seconds remaining in the time step containing the given instant, for driving
    /// a countdown in a UI.
    /// </summary>
    /// <param name="timestamp">The instant to measure from.</param>
    /// <returns>The seconds left in the current step, from 1 up to the configured period.</returns>
    int GetRemainingSeconds(DateTimeOffset timestamp);

    /// <summary>
    /// Returns the number of seconds remaining in the time step containing the current UTC instant.
    /// </summary>
    /// <returns>The seconds left in the current step, from 1 up to the configured period.</returns>
    int GetRemainingSeconds();
}
