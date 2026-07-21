using System;

namespace Enigma.Core.Otp;

/// <summary>
/// Generates and verifies time-based one-time passwords (TOTP).
/// </summary>
/// <remarks>
/// Skeleton stub: members are not yet implemented and throw <see cref="NotImplementedException"/>.
/// The concrete TOTP logic arrives with the OTP implementation feature.
/// </remarks>
public sealed class TotpService : ITotpService
{
    /// <inheritdoc />
    public string GenerateCode(byte[] secret, DateTimeOffset timestamp) => throw new NotImplementedException();

    /// <inheritdoc />
    public bool VerifyCode(byte[] secret, string code, DateTimeOffset timestamp, int window = 1) => throw new NotImplementedException();
}
