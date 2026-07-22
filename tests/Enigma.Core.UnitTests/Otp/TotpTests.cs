using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Otp;
using Enigma.Core.UnitTests.Infrastructure;
using Xunit;

namespace Enigma.Core.UnitTests.Otp;

public class TotpTests
{
    // RFC 6238 Appendix B uses a distinct ASCII seed per algorithm (20 / 32 / 64 bytes). The sibling
    // namespace Enigma.Core.UnitTests.Encoding shadows System.Text.Encoding, so qualify with global::.
    private static byte[] SeedFor(OtpHashAlgorithm algorithm) => algorithm switch
    {
        OtpHashAlgorithm.Sha1 => global::System.Text.Encoding.ASCII.GetBytes("12345678901234567890"),
        OtpHashAlgorithm.Sha256 => global::System.Text.Encoding.ASCII.GetBytes("12345678901234567890123456789012"),
        OtpHashAlgorithm.Sha512 => global::System.Text.Encoding.ASCII.GetBytes("1234567890123456789012345678901234567890123456789012345678901234"),
        _ => throw new ArgumentOutOfRangeException(nameof(algorithm)),
    };

    private static ITotpService CreateService(
        OtpHashAlgorithm algorithm = OtpHashAlgorithm.Sha1,
        int digits = 6,
        int periodSeconds = 30)
        => new TotpServiceFactory(new HotpServiceFactory(new HmacServiceFactory()))
            .CreateTotpService(digits, periodSeconds, algorithm);

    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public void GenerateCode_MatchesRfc6238AppendixB(string algorithm, long time, string expectedCode)
    {
        var algo = Enum.Parse<OtpHashAlgorithm>(algorithm);
        var service = CreateService(algo, digits: 8);
        Assert.Equal(expectedCode, service.GenerateCode(SeedFor(algo), DateTimeOffset.FromUnixTimeSeconds(time)));
    }

    [Fact]
    public void GenerateCode_DefaultTimestamp_UsesCurrentTime()
    {
        var service = CreateService();
        var now = DateTimeOffset.UtcNow;
        // The parameterless overload must agree with an explicit "now" within the same time step.
        Assert.Equal(service.GenerateCode(SeedFor(OtpHashAlgorithm.Sha1), now), service.GenerateCode(SeedFor(OtpHashAlgorithm.Sha1)));
    }

    [Fact]
    public void VerifyCode_ExactStep_ReturnsTrue()
    {
        var service = CreateService();
        var secret = SeedFor(OtpHashAlgorithm.Sha1);
        var when = DateTimeOffset.FromUnixTimeSeconds(1234567890);
        var code = service.GenerateCode(secret, when);
        Assert.True(service.VerifyCode(secret, code, when, window: 0));
    }

    [Fact]
    public void VerifyCode_WrongCode_ReturnsFalse()
    {
        var service = CreateService();
        var secret = SeedFor(OtpHashAlgorithm.Sha1);
        var when = DateTimeOffset.FromUnixTimeSeconds(1234567890);
        var real = service.GenerateCode(secret, when);
        var wrong = real == "000000" ? "111111" : "000000";
        Assert.False(service.VerifyCode(secret, wrong, when, window: 1));
    }

    [Fact]
    public void VerifyCode_PreviousStepWithinWindow_MatchesAndReportsStep()
    {
        var service = CreateService();
        var secret = SeedFor(OtpHashAlgorithm.Sha1);
        var when = DateTimeOffset.FromUnixTimeSeconds(1234567890);
        var previousCode = service.GenerateCode(secret, when.AddSeconds(-30));

        var matched = service.VerifyCode(secret, previousCode, when, window: 1, out var matchedStep);

        Assert.True(matched);
        Assert.Equal(when.ToUnixTimeSeconds() / 30 - 1, matchedStep);
    }

    [Fact]
    public void VerifyCode_NextStepWithinWindow_MatchesAndReportsStep()
    {
        var service = CreateService();
        var secret = SeedFor(OtpHashAlgorithm.Sha1);
        var when = DateTimeOffset.FromUnixTimeSeconds(1234567890);
        var nextCode = service.GenerateCode(secret, when.AddSeconds(30));

        var matched = service.VerifyCode(secret, nextCode, when, window: 1, out var matchedStep);

        Assert.True(matched);
        Assert.Equal(when.ToUnixTimeSeconds() / 30 + 1, matchedStep);
    }

    [Fact]
    public void VerifyCode_OutsideWindow_ReturnsFalseAndReportsNoMatch()
    {
        var service = CreateService();
        var secret = SeedFor(OtpHashAlgorithm.Sha1);
        var when = DateTimeOffset.FromUnixTimeSeconds(1234567890);
        // Code from three steps ago is outside a window of 1.
        var oldCode = service.GenerateCode(secret, when.AddSeconds(-90));

        var matched = service.VerifyCode(secret, oldCode, when, window: 1, out var matchedStep);

        Assert.False(matched);
        Assert.Equal(-1, matchedStep);
    }

    [Fact]
    public void VerifyCode_CurrentTimeConvenience_VerifiesGeneratedCode()
    {
        var service = CreateService();
        var secret = SeedFor(OtpHashAlgorithm.Sha1);
        // Restored convenience: generate + verify against DateTimeOffset.UtcNow (default window 1).
        var code = service.GenerateCode(secret);
        Assert.True(service.VerifyCode(secret, code));
    }

    [Fact]
    public void VerifyCode_NegativeWindow_Throws()
    {
        var service = CreateService();
        Assert.Throws<ArgumentOutOfRangeException>(
            () => service.VerifyCode(SeedFor(OtpHashAlgorithm.Sha1), "123456", -1));
    }

    [Fact]
    public void VerifyCode_NullCode_Throws()
    {
        var service = CreateService();
        var ex = Assert.Throws<ArgumentNullException>(
            () => service.VerifyCode(SeedFor(OtpHashAlgorithm.Sha1), null!));
        Assert.Equal("code", ex.ParamName);
    }

    [Fact]
    public void GenerateCode_NullSecret_Throws()
    {
        var service = CreateService();
        var ex = Assert.Throws<ArgumentNullException>(
            () => service.GenerateCode(null!, DateTimeOffset.FromUnixTimeSeconds(1234567890)));
        Assert.Equal("secret", ex.ParamName);
    }

    [Theory]
    [InlineData(1234567890, 30)] // exact multiple of 30 → full period remains
    [InlineData(1234567895, 25)]
    [InlineData(1234567889, 1)]
    public void GetRemainingSeconds_ReturnsSecondsLeftInStep(long time, int expected)
    {
        var service = CreateService();
        Assert.Equal(expected, service.GetRemainingSeconds(DateTimeOffset.FromUnixTimeSeconds(time)));
    }

    [Fact]
    public void GetRemainingSeconds_CurrentTimeConvenience_InRange()
    {
        var service = CreateService(periodSeconds: 30);
        var remaining = service.GetRemainingSeconds();
        Assert.InRange(remaining, 1, 30);
    }

    [Theory]
    [InlineData(3)]
    [InlineData(10)]
    public void Create_InvalidDigits_Throws(int digits)
    {
        var factory = new TotpServiceFactory(new HotpServiceFactory(new HmacServiceFactory()));
        Assert.Throws<ArgumentOutOfRangeException>(() => factory.CreateTotpService(digits));
    }

    [Fact]
    public void Create_InvalidPeriod_Throws()
    {
        var factory = new TotpServiceFactory(new HotpServiceFactory(new HmacServiceFactory()));
        Assert.Throws<ArgumentOutOfRangeException>(() => factory.CreateTotpService(periodSeconds: 0));
    }

    [Fact]
    public void Ctor_NullHotpFactory_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new TotpServiceFactory(null!));
    }

    public static IEnumerable<object[]> GetCsvValues()
        => CsvData.Rows("Otp", "totp.csv")
            .Select(v => new object[]
            {
                v[0],                                           // algorithm
                long.Parse(v[1], CultureInfo.InvariantCulture), // time (unix seconds)
                v[2],                                           // expected code
            });
}
