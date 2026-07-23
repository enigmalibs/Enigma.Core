using System;
using Enigma.Core.Encoding;
using Xunit;

namespace Enigma.Core.UnitTests.Encoding;

public class HexServiceTests
{
    private readonly HexService _service = new();

    [Fact]
    public void EncodeDecode_RoundTrips()
    {
        var data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var encoded = _service.Encode(data);
        var decoded = _service.Decode(encoded);
        Assert.Equal(data, decoded);
    }

    // Output is lowercase (locks the casing decision).
    [Fact]
    public void Encode_KnownVector_MatchesExpectedLowercase()
    {
        var data = new byte[] { 0x48, 0x65, 0x6C, 0x6C, 0x6F };
        var encoded = _service.Encode(data);
        Assert.Equal("48656c6c6f", encoded);
    }

    [Fact]
    public void Encode_HighBytes_AreLowercase()
        => Assert.Equal("00ff10", _service.Encode([0x00, 0xFF, 0x10]));

    [Fact]
    public void EncodeDecode_EmptyInput_ReturnsEmpty()
    {
        var encoded = _service.Encode([]);
        var decoded = _service.Decode(encoded);
        Assert.Empty(decoded);
    }

    [Fact]
    public void Encode_Null_Throws()
        => Assert.Throws<ArgumentNullException>(() => _service.Encode(null!));

    [Fact]
    public void Decode_Null_Throws()
        => Assert.Throws<ArgumentNullException>(() => _service.Decode(null!));
}
