using System;
using System.Globalization;
using Enigma.Core.Hashing.Hmac;
using Org.BouncyCastle.Utilities;

namespace Enigma.Core.Otp;

/// <summary>
/// Generates and verifies HMAC-based one-time passwords (HOTP, RFC 4226), composed over Core's
/// <see cref="IHmacService"/>.
/// </summary>
/// <remarks>
/// The secret is a per-call argument, caller-owned: it is handed to the HMAC service as-is and is never
/// cleared. The caller is responsible for clearing sensitive key material when done. A single
/// secret-independent HMAC service is created once at construction and reused across calls and secrets,
/// so an instance is safe to reuse. Instances are created by <see cref="HotpServiceFactory"/> only; the
/// HMAC backend is wired internally, so no BouncyCastle type appears on the public surface.
/// </remarks>
public sealed class HotpService : IHotpService
{
    private const int MinDigits = 4;
    private const int MaxDigits = 9;

    private readonly IHmacService _hmac;
    private readonly int _digits;
    private readonly int _modulo;

    // Internal: only the factory constructs the service. The secret is NOT captured here — it became a
    // per-call argument with the Core HMAC redesign (ComputeHmac(data, key)); the HMAC service created
    // here is secret-independent.
    internal HotpService(
        IHmacServiceFactory hmacServiceFactory,
        int digits = 6,
        OtpHashAlgorithm algorithm = OtpHashAlgorithm.Sha1)
    {
        if (hmacServiceFactory is null) throw new ArgumentNullException(nameof(hmacServiceFactory));
        if (digits < MinDigits || digits > MaxDigits)
            throw new ArgumentOutOfRangeException(nameof(digits), digits,
                $"Digits must be between {MinDigits} and {MaxDigits}.");

        _digits = digits;
        _modulo = Pow10(digits);
        _hmac = algorithm switch
        {
            OtpHashAlgorithm.Sha1 => hmacServiceFactory.CreateHmacSha1Service(),
            OtpHashAlgorithm.Sha256 => hmacServiceFactory.CreateHmacSha256Service(),
            OtpHashAlgorithm.Sha512 => hmacServiceFactory.CreateHmacSha512Service(),
            _ => throw new ArgumentException($"Unsupported OTP hash algorithm: {algorithm}.", nameof(algorithm)),
        };
    }

    /// <inheritdoc />
    public string GenerateCode(byte[] secret, long counter)
    {
        if (secret is null) throw new ArgumentNullException(nameof(secret));

        var counterBytes = new byte[8];
        var value = counter;
        for (var i = 7; i >= 0; i--)
        {
            counterBytes[i] = (byte)(value & 0xff);
            value >>= 8;
        }

        var hmac = _hmac.ComputeHmac(counterBytes, secret);

        // RFC 4226 §5.3 dynamic truncation.
        var offset = hmac[hmac.Length - 1] & 0x0f;
        var binary =
            ((hmac[offset] & 0x7f) << 24)
            | ((hmac[offset + 1] & 0xff) << 16)
            | ((hmac[offset + 2] & 0xff) << 8)
            | (hmac[offset + 3] & 0xff);

        var otp = binary % _modulo;
        return otp.ToString(CultureInfo.InvariantCulture).PadLeft(_digits, '0');
    }

    /// <inheritdoc />
    public bool VerifyCode(byte[] secret, long counter, string code)
        => VerifyCode(secret, counter, code, 0, out _);

    /// <inheritdoc />
    public bool VerifyCode(byte[] secret, long counter, string code, int window)
        => VerifyCode(secret, counter, code, window, out _);

    /// <inheritdoc />
    public bool VerifyCode(byte[] secret, long counter, string code, int window, out long matchedCounter)
    {
        if (secret is null) throw new ArgumentNullException(nameof(secret));
        if (code is null) throw new ArgumentNullException(nameof(code));
        if (window < 0)
            throw new ArgumentOutOfRangeException(nameof(window), window, "Window must be non-negative.");

        matchedCounter = -1;
        var matched = false;

        // Check the whole window without early exit so verification time is independent of where (or
        // whether) a match occurs.
        for (var i = 0; i <= window; i++)
        {
            var current = counter + i;
            var candidate = GenerateCode(secret, current);
            if (ConstantTimeEquals(candidate, code))
            {
                matched = true;
                matchedCounter = current;
            }
        }

        return matched;
    }

    // The sibling namespace Enigma.Core.Encoding shadows the simple name System.Text.Encoding here, so
    // qualify with global::.
    private static bool ConstantTimeEquals(string a, string b)
        => Arrays.FixedTimeEquals(
            global::System.Text.Encoding.UTF8.GetBytes(a),
            global::System.Text.Encoding.UTF8.GetBytes(b));

    private static int Pow10(int exponent)
    {
        var result = 1;
        for (var i = 0; i < exponent; i++)
            result *= 10;
        return result;
    }
}
