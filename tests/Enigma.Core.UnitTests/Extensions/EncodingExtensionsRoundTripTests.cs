using Enigma.Core.Extensions;
using Xunit;

namespace Enigma.Core.UnitTests.Extensions;

/// <summary>
/// The Base64/Hex/Base32 half of <c>EncodingExtensions</c>. These live in the Encoding feature
/// (FEATURE-0399) rather than the foundation, because the underlying <c>Base64Service</c>,
/// <c>HexService</c> and <c>Base32Service</c> are only implemented here — as stubs in the foundation
/// they threw <see cref="System.NotImplementedException"/>. The <c>System.Text.Encoding</c> half is
/// covered by <see cref="EncodingExtensionsTests"/>.
/// </summary>
public class EncodingExtensionsRoundTripTests
{
    private static readonly byte[] Sample =
        [0x00, 0x01, 0x02, 0x7F, 0x80, 0xFE, 0xFF, 0x10, 0x2A, 0x55];

    [Fact]
    public void Base64_EncodeThenDecode_RoundTrips()
        => Assert.Equal(Sample, Sample.ToBase64String().FromBase64String());

    [Fact]
    public void Base64_KnownVector()
        => Assert.Equal("SGVsbG8sIFdvcmxkIQ==", "Hello, World!"u8.ToArray().ToBase64String());

    [Fact]
    public void Hex_EncodeThenDecode_RoundTrips()
        => Assert.Equal(Sample, Sample.ToHexString().FromHexString());

    [Fact]
    public void Hex_KnownVector_IsLowercase()
        => Assert.Equal("00ff10", new byte[] { 0x00, 0xFF, 0x10 }.ToHexString());

    [Fact]
    public void Base32_EncodeThenDecode_RoundTrips()
        => Assert.Equal(Sample, Sample.ToBase32String().FromBase32String());

    [Fact]
    public void Base32_KnownVector()
        => Assert.Equal("MZXW6YTBOI======", "foobar"u8.ToArray().ToBase32String());

    [Fact]
    public void AllSchemes_EmptyInput_RoundTrip()
    {
        Assert.Empty(System.Array.Empty<byte>().ToBase64String().FromBase64String());
        Assert.Empty(System.Array.Empty<byte>().ToHexString().FromHexString());
        Assert.Empty(System.Array.Empty<byte>().ToBase32String().FromBase32String());
    }
}
