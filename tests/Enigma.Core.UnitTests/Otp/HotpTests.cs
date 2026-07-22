using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Enigma.Core.Hashing.Hmac;
using Enigma.Core.Otp;
using Enigma.Core.UnitTests.Infrastructure;
using Xunit;

namespace Enigma.Core.UnitTests.Otp;

public class HotpTests
{
    // RFC 4226 Appendix D shared secret: ASCII "12345678901234567890" (20 bytes). The sibling namespace
    // Enigma.Core.UnitTests.Encoding shadows System.Text.Encoding, so qualify with global::.
    private static readonly byte[] Secret =
        global::System.Text.Encoding.ASCII.GetBytes("12345678901234567890");

    private static IHotpService CreateService(int digits = 6, OtpHashAlgorithm algorithm = OtpHashAlgorithm.Sha1)
        => new HotpServiceFactory(new HmacServiceFactory()).CreateHotpService(digits, algorithm);

    [Theory]
    [MemberData(nameof(GetCsvValues))]
    public void GenerateCode_MatchesRfc4226AppendixD(long counter, string expectedCode)
    {
        var service = CreateService();
        Assert.Equal(expectedCode, service.GenerateCode(Secret, counter));
    }

    [Fact]
    public void GenerateCode_HonorsDigitParameter()
    {
        // RFC 4226 Appendix D: counter 0 truncates to decimal 1284755224 → 8-digit HOTP 84755224.
        var service = CreateService(digits: 8);
        Assert.Equal("84755224", service.GenerateCode(Secret, 0));
    }

    [Fact]
    public void VerifyCode_ExactCounter_ReturnsTrue()
    {
        var service = CreateService();
        Assert.True(service.VerifyCode(Secret, 0, "755224"));
    }

    [Fact]
    public void VerifyCode_WrongCode_ReturnsFalse()
    {
        var service = CreateService();
        Assert.False(service.VerifyCode(Secret, 0, "000000"));
    }

    [Fact]
    public void VerifyCode_DefaultWindow_DoesNotMatchAdjacentCounter()
    {
        var service = CreateService();
        // "287082" is the code for counter 1; it must not match counter 0 with the default (no) window.
        Assert.False(service.VerifyCode(Secret, 0, "287082"));
    }

    [Fact]
    public void VerifyCode_ForwardWindow_FindsDriftedCounter()
    {
        var service = CreateService();
        // Code for counter 3, verified starting at counter 0 with a window of 3.
        var matched = service.VerifyCode(Secret, 0, "969429", window: 3, out var matchedCounter);
        Assert.True(matched);
        Assert.Equal(3, matchedCounter);
    }

    [Fact]
    public void VerifyCode_OutsideWindow_ReturnsFalseAndReportsNoMatch()
    {
        var service = CreateService();
        // Code for counter 5 is outside a window of 3 starting at counter 0.
        var matched = service.VerifyCode(Secret, 0, "254676", window: 3, out var matchedCounter);
        Assert.False(matched);
        Assert.Equal(-1, matchedCounter);
    }

    [Fact]
    public void VerifyCode_NegativeWindow_Throws()
    {
        var service = CreateService();
        Assert.Throws<ArgumentOutOfRangeException>(() => service.VerifyCode(Secret, 0, "755224", -1));
    }

    [Fact]
    public void GenerateCode_NullSecret_Throws()
    {
        var service = CreateService();
        var ex = Assert.Throws<ArgumentNullException>(() => service.GenerateCode(null!, 0));
        Assert.Equal("secret", ex.ParamName);
    }

    [Fact]
    public void VerifyCode_NullSecret_Throws()
    {
        var service = CreateService();
        var ex = Assert.Throws<ArgumentNullException>(() => service.VerifyCode(null!, 0, "755224"));
        Assert.Equal("secret", ex.ParamName);
    }

    [Fact]
    public void VerifyCode_NullCode_Throws()
    {
        var service = CreateService();
        var ex = Assert.Throws<ArgumentNullException>(() => service.VerifyCode(Secret, 0, null!));
        Assert.Equal("code", ex.ParamName);
    }

    [Theory]
    [InlineData(3)]
    [InlineData(10)]
    public void Create_InvalidDigits_Throws(int digits)
    {
        var factory = new HotpServiceFactory(new HmacServiceFactory());
        Assert.Throws<ArgumentOutOfRangeException>(() => factory.CreateHotpService(digits));
    }

    [Fact]
    public void Ctor_NullHmacFactory_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new HotpServiceFactory(null!));
    }

    public static IEnumerable<object[]> GetCsvValues()
        => CsvData.Rows("Otp", "hotp.csv")
            .Select(v => new object[]
            {
                long.Parse(v[0], CultureInfo.InvariantCulture), // counter
                v[1],                                           // expected code
            });
}
