using System;
using Enigma.Core.Encoding;
using Xunit;
using TextEncoding = System.Text.Encoding;

namespace Enigma.Core.UnitTests.Encoding;

public class Base32ServiceTests
{
    private readonly Base32Service _service = new();

    // RFC 4648 §10 test vectors.
    [Theory]
    [InlineData("", "")]
    [InlineData("f", "MY======")]
    [InlineData("fo", "MZXQ====")]
    [InlineData("foo", "MZXW6===")]
    [InlineData("foob", "MZXW6YQ=")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI======")]
    public void Encode_ProducesRfc4648Vector(string input, string expected)
    {
        var encoded = _service.Encode(TextEncoding.ASCII.GetBytes(input));
        Assert.Equal(expected, encoded);
    }

    // RFC 4648 §10 test vectors, decode direction.
    [Theory]
    [InlineData("", "")]
    [InlineData("f", "MY======")]
    [InlineData("fo", "MZXQ====")]
    [InlineData("foo", "MZXW6===")]
    [InlineData("foob", "MZXW6YQ=")]
    [InlineData("fooba", "MZXW6YTB")]
    [InlineData("foobar", "MZXW6YTBOI======")]
    public void Decode_ParsesRfc4648Vector(string expectedText, string encoded)
    {
        var decoded = _service.Decode(encoded);
        Assert.Equal(TextEncoding.ASCII.GetBytes(expectedText), decoded);
    }

    [Fact]
    public void EncodeDecode_RoundTrips()
    {
        var data = new byte[] { 0, 1, 2, 3, 4, 5, 250, 251, 252, 253, 254, 255 };
        var decoded = _service.Decode(_service.Encode(data));
        Assert.Equal(data, decoded);
    }

    [Fact]
    public void EncodeDecode_EmptyInput_ReturnsEmpty()
    {
        Assert.Equal(string.Empty, _service.Encode([]));
        Assert.Empty(_service.Decode(string.Empty));
    }

    // Tolerant decode: lowercase, embedded whitespace and mixed case all decode to "fooba".
    [Theory]
    [InlineData("MZXW6YTB")]
    [InlineData("mzxw6ytb")]
    [InlineData("MZXW 6YTB")]
    [InlineData("mZ xW6Y tb")]
    public void Decode_IsTolerant(string encoded)
    {
        Assert.Equal("fooba"u8.ToArray(), _service.Decode(encoded));
    }

    [Fact]
    public void Decode_MissingPadding_Succeeds()
    {
        // "MY======" stripped of its padding still decodes to "f".
        Assert.Equal("f"u8.ToArray(), _service.Decode("MY"));
    }

    // Characters absent from the Base32 alphabet (0, 1, 8, 9) must be rejected.
    [Theory]
    [InlineData("MZXW6YT0")]
    [InlineData("MZXW6YT1")]
    [InlineData("MZXW6YT8")]
    [InlineData("MZXW6YT9")]
    public void Decode_InvalidCharacter_Throws(string encoded)
    {
        Assert.Throws<FormatException>(() => _service.Decode(encoded));
    }

    [Fact]
    public void Encode_Null_Throws()
        => Assert.Throws<ArgumentNullException>(() => _service.Encode(null!));

    [Fact]
    public void Decode_Null_Throws()
        => Assert.Throws<ArgumentNullException>(() => _service.Decode(null!));
}
