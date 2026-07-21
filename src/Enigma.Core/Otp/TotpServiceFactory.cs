using System;

namespace Enigma.Core.Otp;

/// <summary>
/// A factory for creating TOTP services.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete factory logic arrives with the OTP implementation feature.
/// </remarks>
public sealed class TotpServiceFactory : ITotpServiceFactory
{
    /// <inheritdoc />
    public ITotpService CreateTotpService(int digits = 6, int periodSeconds = 30, OtpHashAlgorithm hashAlgorithm = OtpHashAlgorithm.Sha1) => throw new NotImplementedException();
}
