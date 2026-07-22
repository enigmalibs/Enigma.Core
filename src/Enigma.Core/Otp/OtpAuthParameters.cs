namespace Enigma.Core.Otp;

/// <summary>
/// Read-only parameters carried by a TOTP <c>otpauth://</c> provisioning URI, as produced by
/// <see cref="IOtpProvisioningService.ParseUri"/> and consumed by
/// <see cref="IOtpProvisioningService.BuildUri"/>.
/// </summary>
public sealed class OtpAuthParameters
{
    /// <summary>
    /// Initializes a new instance of the <see cref="OtpAuthParameters"/> class.
    /// </summary>
    /// <param name="issuer">The issuer, or <c>null</c> if the URI carried none.</param>
    /// <param name="accountName">The account name.</param>
    /// <param name="secret">The decoded shared secret.</param>
    /// <param name="digits">The number of digits in generated codes.</param>
    /// <param name="periodSeconds">The time step in seconds.</param>
    /// <param name="algorithm">The HMAC hash algorithm.</param>
    public OtpAuthParameters(
        string? issuer,
        string accountName,
        byte[] secret,
        int digits,
        int periodSeconds,
        OtpHashAlgorithm algorithm)
    {
        Issuer = issuer;
        AccountName = accountName;
        Secret = secret;
        Digits = digits;
        PeriodSeconds = periodSeconds;
        Algorithm = algorithm;
    }

    /// <summary>
    /// The issuer (service or organization) the credential belongs to, or <c>null</c> if the URI
    /// carried none.
    /// </summary>
    public string? Issuer { get; }

    /// <summary>
    /// The account name (typically a username or email) the credential identifies.
    /// </summary>
    public string AccountName { get; }

    /// <summary>
    /// The decoded shared secret.
    /// </summary>
    public byte[] Secret { get; }

    /// <summary>
    /// The number of digits in generated codes.
    /// </summary>
    public int Digits { get; }

    /// <summary>
    /// The time step in seconds.
    /// </summary>
    public int PeriodSeconds { get; }

    /// <summary>
    /// The HMAC hash algorithm.
    /// </summary>
    public OtpHashAlgorithm Algorithm { get; }
}
