using Enigma.Core.Extensions;
using Xunit;
using TextEncoding = System.Text.Encoding;

namespace Enigma.Core.UnitTests.Extensions;

/// <summary>
/// Foundation covers only the <see cref="System.Text.Encoding"/>-backed half of
/// <c>EncodingExtensions</c>: the UTF-8-default contract and the explicit-encoding helpers. The
/// Base64/Hex/Base32 round-trip tests move to the Encoding feature, where those services are
/// implemented (they throw <see cref="System.NotImplementedException"/> as stubs here).
/// </summary>
/// <remarks>
/// TextEncoding aliases System.Text.Encoding: this test namespace lives under Enigma.Core, so a bare
/// Encoding would otherwise bind to the Enigma.Core.Encoding namespace (the same collision the source
/// resolves with the same alias).
/// </remarks>
public class EncodingExtensionsTests
{
    // --- Default-encoding contract (the CODE-REVIEW-001 UTF-8-default fix) -------------------
    // The no-argument overloads must default to UTF-8, NOT Encoding.Default. Encoding.Default
    // resolves to UTF-8 on modern .NET but to the system ANSI code page on netstandard2.0/.NET
    // Framework, so a platform-default would make the same call produce different bytes across
    // target frameworks. The euro sign distinguishes the two: 3 bytes (E2 82 AC) in UTF-8 vs a
    // single byte (0x80) in Windows-1252 ANSI.

    [Fact]
    public void GetBytes_NoEncoding_UsesUtf8()
    {
        const string s = "€"; // €
        var bytes = s.GetBytes();
        Assert.Equal(TextEncoding.UTF8.GetBytes(s), bytes);
        Assert.Equal(3, bytes.Length);
    }

    [Fact]
    public void GetBytes_NoEncoding_MatchesExplicitUtf8Overload()
    {
        const string s = "Héllo, € world";
        Assert.Equal(s.GetUtf8Bytes(), s.GetBytes());
    }

    [Fact]
    public void GetString_NoEncoding_UsesUtf8()
    {
        var bytes = TextEncoding.UTF8.GetBytes("Héllo, € world");
        Assert.Equal(TextEncoding.UTF8.GetString(bytes), bytes.GetString());
    }

    [Fact]
    public void GetString_NoEncoding_MatchesExplicitUtf8Overload()
    {
        var bytes = new byte[] { 0xE2, 0x82, 0xAC }; // € in UTF-8
        Assert.Equal(bytes.GetUtf8String(), bytes.GetString());
    }

    [Fact]
    public void RoundTrip_NoEncoding_IsLossless()
    {
        const string s = "The quick brown föx — €£¥";
        Assert.Equal(s, s.GetBytes().GetString());
    }

    // --- Explicit encoding is honored -------------------------------------------------------

    [Fact]
    public void GetBytes_WithEncoding_UsesProvidedEncoding()
    {
        const string s = "abc";
        Assert.Equal(TextEncoding.ASCII.GetBytes(s), s.GetBytes(TextEncoding.ASCII));
    }

    [Fact]
    public void GetString_WithEncoding_UsesProvidedEncoding()
    {
        var bytes = new byte[] { 0x61, 0x62, 0x63 };
        Assert.Equal("abc", bytes.GetString(TextEncoding.ASCII));
    }

    [Fact]
    public void Utf8_Helpers_RoundTrip()
    {
        const string s = "€é utf8";
        Assert.Equal(s, s.GetUtf8Bytes().GetUtf8String());
    }

    [Fact]
    public void Ascii_Helpers_RoundTrip()
    {
        const string s = "plain ascii 123";
        Assert.Equal(s, s.GetAsciiBytes().GetAsciiString());
    }
}
