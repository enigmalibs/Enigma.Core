using System;

namespace Enigma.Core.Otp;

/// <summary>
/// Generates and verifies HMAC-based one-time passwords (HOTP).
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete HOTP logic arrives with the OTP implementation feature.
/// </remarks>
public sealed class HotpService : IHotpService
{
    /// <inheritdoc />
    public string GenerateCode(byte[] secret, long counter) => throw new NotImplementedException();

    /// <inheritdoc />
    public bool VerifyCode(byte[] secret, long counter, string code) => throw new NotImplementedException();
}
