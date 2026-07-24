using System;
using Enigma.Core.Encoding;
using Enigma.Core.Otp;
using Xunit;

namespace Enigma.Core.UnitTests.Otp;

public class OtpProvisioningTests
{
    // ASCII "12345678901234567890" (20 bytes) → unpadded Base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ". The
    // sibling namespace Enigma.Core.UnitTests.Encoding shadows System.Text.Encoding, so qualify with global::.
    private static readonly byte[] Secret =
        global::System.Text.Encoding.ASCII.GetBytes("12345678901234567890");

    private const string SecretBase32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    private static IOtpProvisioningService CreateService()
        => new OtpProvisioningServiceFactory(new EncodingServiceFactory()).CreateOtpProvisioningService();

    private static OtpAuthParameters Params(
        string? issuer,
        string accountName,
        byte[] secret,
        int digits = 6,
        int periodSeconds = 30,
        OtpHashAlgorithm algorithm = OtpHashAlgorithm.Sha1)
        => new OtpAuthParameters(issuer, accountName, secret, digits, periodSeconds, algorithm);

    [Fact]
    public void BuildUri_KnownVector_ProducesExpectedString()
    {
        var uri = CreateService().BuildUri(Params("Example", "alice", Secret));

        Assert.Equal(
            $"otpauth://totp/Example:alice?secret={SecretBase32}&issuer=Example&algorithm=SHA1&digits=6&period=30",
            uri);
    }

    [Fact]
    public void BuildUri_EscapesSpecialCharactersInLabel()
    {
        var uri = CreateService().BuildUri(Params("ACME Co", "alice@acme.com", Secret));

        Assert.StartsWith("otpauth://totp/ACME%20Co:alice%40acme.com?", uri);
        Assert.Contains("&issuer=ACME%20Co", uri);
    }

    [Fact]
    public void BuildUri_NoIssuer_OmitsPrefixAndParameter()
    {
        var uri = CreateService().BuildUri(Params(issuer: "", "alice", Secret));

        Assert.Equal(
            $"otpauth://totp/alice?secret={SecretBase32}&algorithm=SHA1&digits=6&period=30",
            uri);
    }

    [Fact]
    public void BuildThenParse_RoundTrips()
    {
        var service = CreateService();
        var uri = service.BuildUri(Params(
            "ACME Co", "alice@acme.com", Secret,
            digits: 8, periodSeconds: 60, algorithm: OtpHashAlgorithm.Sha256));

        var parsed = service.ParseUri(uri);

        Assert.Equal("ACME Co", parsed.Issuer);
        Assert.Equal("alice@acme.com", parsed.AccountName);
        Assert.Equal(Secret, parsed.Secret);
        Assert.Equal(8, parsed.Digits);
        Assert.Equal(60, parsed.PeriodSeconds);
        Assert.Equal(OtpHashAlgorithm.Sha256, parsed.Algorithm);
    }

    [Fact]
    public void ParseUri_MinimalUri_AppliesDefaults()
    {
        var parsed = CreateService().ParseUri($"otpauth://totp/alice?secret={SecretBase32}");

        Assert.Null(parsed.Issuer);
        Assert.Equal("alice", parsed.AccountName);
        Assert.Equal(Secret, parsed.Secret);
        Assert.Equal(6, parsed.Digits);
        Assert.Equal(30, parsed.PeriodSeconds);
        Assert.Equal(OtpHashAlgorithm.Sha1, parsed.Algorithm);
    }

    [Fact]
    public void ParseUri_IssuerQueryParam_TakesPrecedenceOverLabel()
    {
        var parsed = CreateService().ParseUri(
            $"otpauth://totp/LabelIssuer:alice?secret={SecretBase32}&issuer=ParamIssuer");

        Assert.Equal("ParamIssuer", parsed.Issuer);
        Assert.Equal("alice", parsed.AccountName);
    }

    [Fact]
    public void ParseUri_IssuerFromLabelWhenNoParam()
    {
        var parsed = CreateService().ParseUri($"otpauth://totp/LabelIssuer:alice?secret={SecretBase32}");

        Assert.Equal("LabelIssuer", parsed.Issuer);
        Assert.Equal("alice", parsed.AccountName);
    }

    [Theory]
    [InlineData("https://totp/alice?secret=ABCD")]              // wrong scheme
    [InlineData("otpauth://hotp/alice?secret=ABCD")]            // unsupported type
    [InlineData("otpauth://totp/alice")]                        // no secret
    [InlineData("otpauth://totp/alice?secret=")]                // empty secret
    public void ParseUri_Invalid_Throws(string uri)
    {
        Assert.Throws<FormatException>(() => CreateService().ParseUri(uri));
    }

    [Fact]
    public void ParseUri_NonNumericDigits_Throws()
    {
        Assert.Throws<FormatException>(
            () => CreateService().ParseUri($"otpauth://totp/alice?secret={SecretBase32}&digits=abc"));
    }

    [Fact]
    public void ParseUri_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => CreateService().ParseUri(null!));
    }

    [Fact]
    public void GenerateSecret_DefaultSize_Is20Bytes()
    {
        Assert.Equal(20, CreateService().GenerateSecret().Length);
    }

    [Fact]
    public void GenerateSecret_CustomSize_Honored()
    {
        Assert.Equal(32, CreateService().GenerateSecret(32).Length);
    }

    [Fact]
    public void GenerateSecret_BelowMinimum_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CreateService().GenerateSecret(15));
    }

    [Fact]
    public void BuildUri_NullParameters_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => CreateService().BuildUri(null!));
    }

    [Fact]
    public void BuildUri_NullSecret_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => CreateService().BuildUri(Params("Example", "alice", null!)));
    }

    [Fact]
    public void BuildUri_BlankAccountName_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => CreateService().BuildUri(Params("Example", "  ", Secret)));
    }

    [Theory]
    [InlineData(3)]
    [InlineData(10)]
    public void BuildUri_InvalidDigits_Throws(int digits)
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => CreateService().BuildUri(Params("Example", "alice", Secret, digits: digits)));
    }

    [Fact]
    public void BuildUri_NonPositivePeriod_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(
            () => CreateService().BuildUri(Params("Example", "alice", Secret, periodSeconds: 0)));
    }

    [Fact]
    public void Ctor_NullEncodingFactory_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new OtpProvisioningServiceFactory(null!));
    }

    // Base32 seam test: pins the otpauth secret encoding across the encoding dependency (FEATURE-0399).
    // Encode is canonical padded/uppercase; Decode is tolerant of case and missing padding.
    [Fact]
    public void Base32Seam_EncodesAndToleratesDecode()
    {
        IEncodingService base32 = new EncodingServiceFactory().CreateBase32Service();

        Assert.Equal(SecretBase32, base32.Encode(Secret));
        Assert.Equal(Secret, base32.Decode(SecretBase32.ToLowerInvariant()));
    }
}
