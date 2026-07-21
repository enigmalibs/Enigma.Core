namespace Enigma.Core.Otp;

/// <summary>
/// Factory for creating <see cref="ITotpService"/> instances. The digit count, time-step length and
/// backing hash algorithm define the authenticator configuration and are fixed at creation; the secret
/// and timestamp are supplied per call on the returned service.
/// </summary>
public interface ITotpServiceFactory
{
    /// <summary>Creates a TOTP service (RFC 6238).</summary>
    /// <param name="digits">The number of digits in each generated code. Defaults to 6.</param>
    /// <param name="periodSeconds">The length of each time step, in seconds. Defaults to 30.</param>
    /// <param name="hashAlgorithm">The hash algorithm backing the HMAC. Defaults to <see cref="OtpHashAlgorithm.Sha1"/>.</param>
    /// <returns>A configured TOTP service.</returns>
    ITotpService CreateTotpService(int digits = 6, int periodSeconds = 30, OtpHashAlgorithm hashAlgorithm = OtpHashAlgorithm.Sha1);
}
