using System;
using Enigma.Core.Encoding;
using Xunit;

namespace Enigma.Core.UnitTests.Encoding;

public class Base64ServiceTests
{
    private readonly Base64Service _service = new();

    [Fact]
    public void EncodeDecode_RoundTrips()
    {
        var data = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var encoded = _service.Encode(data);
        var decoded = _service.Decode(encoded);
        Assert.Equal(data, decoded);
    }

    [Fact]
    public void Encode_KnownVector_MatchesExpected()
    {
        var data = "Hello, World!"u8.ToArray();
        var encoded = _service.Encode(data);
        Assert.Equal("SGVsbG8sIFdvcmxkIQ==", encoded);
    }

    [Fact]
    public void EncodeDecode_EmptyInput_ReturnsEmpty()
    {
        var encoded = _service.Encode([]);
        var decoded = _service.Decode(encoded);
        Assert.Empty(decoded);
    }

    // Locks the internal-BouncyCastle-backend decision: the BC Base64 decoder tolerates embedded
    // whitespace (line breaks/spaces), whereas the built-in Convert.FromBase64String would reject
    // interior spaces. PEM/MIME-style wrapped Base64 must decode to the same bytes.
    [Fact]
    public void Decode_WithEmbeddedWhitespace_Succeeds()
    {
        const string wrapped = "SGVsbG8s\nIFdvcmxk IQ==";
        Assert.Equal("Hello, World!"u8.ToArray(), _service.Decode(wrapped));
    }

    [Fact]
    public void Encode_Null_Throws()
        => Assert.Throws<ArgumentNullException>(() => _service.Encode(null!));

    [Fact]
    public void Decode_Null_Throws()
        => Assert.Throws<ArgumentNullException>(() => _service.Decode(null!));
}
