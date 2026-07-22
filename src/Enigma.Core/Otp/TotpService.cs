using System;

namespace Enigma.Core.Otp;

/// <summary>
/// Generates and verifies time-based one-time passwords (TOTP, RFC 6238), composed on top of an
/// <see cref="IHotpService"/> by mapping time to an HOTP counter.
/// </summary>
/// <remarks>
/// The secret is a per-call argument, caller-owned: it is threaded to the underlying HOTP/HMAC service
/// as-is and is never cleared. The caller is responsible for clearing sensitive key material when done.
/// Instances are created by <see cref="TotpServiceFactory"/> only and are safe to reuse.
/// </remarks>
public sealed class TotpService : ITotpService
{
    private readonly IHotpService _hotp;
    private readonly int _periodSeconds;

    // Internal: only the factory constructs the service. The digit count and algorithm are validated by
    // the HOTP service created here; the secret stays a per-call argument.
    internal TotpService(
        IHotpServiceFactory hotpServiceFactory,
        int digits = 6,
        int periodSeconds = 30,
        OtpHashAlgorithm algorithm = OtpHashAlgorithm.Sha1)
    {
        if (hotpServiceFactory is null) throw new ArgumentNullException(nameof(hotpServiceFactory));
        if (periodSeconds <= 0)
            throw new ArgumentOutOfRangeException(nameof(periodSeconds), periodSeconds,
                "Period must be greater than zero.");

        _periodSeconds = periodSeconds;
        // The HOTP service validates the digit count and algorithm.
        _hotp = hotpServiceFactory.CreateHotpService(digits, algorithm);
    }

    /// <inheritdoc />
    public string GenerateCode(byte[] secret, DateTimeOffset timestamp)
        => _hotp.GenerateCode(secret, GetTimeStep(timestamp));

    /// <inheritdoc />
    public string GenerateCode(byte[] secret)
        => GenerateCode(secret, DateTimeOffset.UtcNow);

    /// <inheritdoc />
    public bool VerifyCode(byte[] secret, string code, DateTimeOffset timestamp, int window = 1)
        => VerifyCode(secret, code, timestamp, window, out _);

    /// <inheritdoc />
    public bool VerifyCode(byte[] secret, string code, int window = 1)
        => VerifyCode(secret, code, DateTimeOffset.UtcNow, window, out _);

    /// <inheritdoc />
    public bool VerifyCode(byte[] secret, string code, DateTimeOffset timestamp, int window, out long matchedStep)
    {
        if (code is null) throw new ArgumentNullException(nameof(code));
        if (window < 0)
            throw new ArgumentOutOfRangeException(nameof(window), window, "Window must be non-negative.");

        var step = GetTimeStep(timestamp);

        // Map the symmetric window [step - window, step + window] onto HOTP's forward-only window, which
        // scans the whole range without early exit to keep verification time constant. HOTP validates
        // the null secret.
        return _hotp.VerifyCode(secret, step - window, code, window * 2, out matchedStep);
    }

    /// <inheritdoc />
    public int GetRemainingSeconds(DateTimeOffset timestamp)
    {
        var elapsed = GetUnixSeconds(timestamp) % _periodSeconds;
        return (int)(_periodSeconds - elapsed);
    }

    /// <inheritdoc />
    public int GetRemainingSeconds()
        => GetRemainingSeconds(DateTimeOffset.UtcNow);

    private long GetTimeStep(DateTimeOffset timestamp)
        => GetUnixSeconds(timestamp) / _periodSeconds;

    private static long GetUnixSeconds(DateTimeOffset timestamp)
        => timestamp.ToUnixTimeSeconds();
}
