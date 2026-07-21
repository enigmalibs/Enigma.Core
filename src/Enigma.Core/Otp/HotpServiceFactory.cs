using System;

namespace Enigma.Core.Otp;

/// <summary>
/// A factory for creating HOTP services.
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete factory logic arrives with the OTP implementation feature.
/// </remarks>
public sealed class HotpServiceFactory : IHotpServiceFactory
{
    /// <inheritdoc />
    public IHotpService CreateHotpService(int digits = 6, OtpHashAlgorithm hashAlgorithm = OtpHashAlgorithm.Sha1) => throw new NotImplementedException();
}
