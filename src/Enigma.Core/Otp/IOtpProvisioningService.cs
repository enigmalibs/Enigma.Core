using System;

namespace Enigma.Core.Otp;

/// <summary>
/// Provisions TOTP authenticators: generates shared secrets and builds/parses <c>otpauth://totp/</c>
/// URIs in the Key URI Format understood by authenticator apps. QR-code image generation is
/// intentionally out of scope (it would require an external dependency). Instances are created by
/// <see cref="IOtpProvisioningServiceFactory"/>.
/// </summary>
public interface IOtpProvisioningService
{
    /// <summary>
    /// Builds an <c>otpauth://totp/</c> provisioning URI for the given parameters. The secret is encoded
    /// as unpadded Base32 (the authenticator-app convention).
    /// </summary>
    /// <param name="parameters">
    /// The credential parameters. <see cref="OtpAuthParameters.AccountName"/> is required;
    /// <see cref="OtpAuthParameters.Issuer"/> may be <c>null</c> or empty to omit it, though supplying it
    /// is strongly recommended for correct display in authenticator apps.
    /// </param>
    /// <returns>The provisioning URI.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="parameters"/> or its <see cref="OtpAuthParameters.Secret"/> is <c>null</c>.</exception>
    /// <exception cref="ArgumentException"><see cref="OtpAuthParameters.AccountName"/> is <c>null</c> or blank, or <see cref="OtpAuthParameters.Algorithm"/> is not a defined value.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><see cref="OtpAuthParameters.Digits"/> is outside the range 4–9, or <see cref="OtpAuthParameters.PeriodSeconds"/> is not positive.</exception>
    string BuildUri(OtpAuthParameters parameters);

    /// <summary>
    /// Parses an <c>otpauth://totp/</c> provisioning URI into its parameters. Absent optional parameters
    /// fall back to their defaults (algorithm SHA1, 6 digits, 30-second period). The issuer is taken from
    /// the <c>issuer</c> query parameter when present, otherwise from the label prefix.
    /// </summary>
    /// <param name="uri">The provisioning URI.</param>
    /// <returns>The parsed parameters.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="uri"/> is <c>null</c>.</exception>
    /// <exception cref="FormatException">
    /// The URI is not a well-formed <c>otpauth://totp/</c> URI, has no secret, or carries an unrecognized
    /// algorithm or non-numeric digits/period.
    /// </exception>
    OtpAuthParameters ParseUri(string uri);

    /// <summary>
    /// Generates a cryptographically random shared secret suitable for TOTP/HOTP enrollment.
    /// </summary>
    /// <param name="sizeBytes">The secret length in bytes. Must be at least 16. Default is 20 (160-bit).</param>
    /// <returns>The generated secret. The caller owns the array and is responsible for clearing it when done.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="sizeBytes"/> is less than 16.</exception>
    byte[] GenerateSecret(int sizeBytes = 20);
}
