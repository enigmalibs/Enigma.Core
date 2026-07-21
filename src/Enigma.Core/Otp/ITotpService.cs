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
    string GenerateCode(byte[] secret, DateTimeOffset timestamp);

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
    bool VerifyCode(byte[] secret, string code, DateTimeOffset timestamp, int window = 1);
}
