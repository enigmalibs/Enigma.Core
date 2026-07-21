namespace Enigma.Core.Otp;

/// <summary>
/// Factory for creating <see cref="IHotpService"/> instances. The digit count and backing hash algorithm
/// define the authenticator configuration and are fixed at creation; the secret and counter are supplied
/// per call on the returned service.
/// </summary>
public interface IHotpServiceFactory
{
    /// <summary>Creates an HOTP service (RFC 4226).</summary>
    /// <param name="digits">The number of digits in each generated code. Defaults to 6.</param>
    /// <param name="hashAlgorithm">The hash algorithm backing the HMAC. Defaults to <see cref="OtpHashAlgorithm.Sha1"/>.</param>
    /// <returns>A configured HOTP service.</returns>
    IHotpService CreateHotpService(int digits = 6, OtpHashAlgorithm hashAlgorithm = OtpHashAlgorithm.Sha1);
}
