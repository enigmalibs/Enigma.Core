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
    string GenerateCode(byte[] secret, long counter);

    /// <summary>
    /// Verifies that a code matches the HOTP generated for the given counter value.
    /// </summary>
    /// <param name="secret">The shared secret key.</param>
    /// <param name="counter">The moving factor (event counter) to check against.</param>
    /// <param name="code">The candidate one-time password to verify.</param>
    /// <returns><see langword="true"/> if the code is valid for the counter; otherwise <see langword="false"/>.</returns>
    bool VerifyCode(byte[] secret, long counter, string code);
}
