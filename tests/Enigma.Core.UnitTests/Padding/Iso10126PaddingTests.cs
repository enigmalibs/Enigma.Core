using System.Linq;
using Enigma.Core.Padding;
using Xunit;

namespace Enigma.Core.UnitTests.Padding;

/// <summary>
/// ISO 10126-2 fills the padding with random bytes, so it has no fixed known-answer vectors. These
/// tests instead assert the structural invariants (block-aligned output, trailing length byte) and a
/// Pad/Unpad round-trip that recovers the original data.
/// </summary>
public class Iso10126PaddingTests
{
    private const int BlockSize = 16;

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(31)]
    [InlineData(100)]
    public void PadThenUnpad_RoundTrips(int length)
    {
        var service = new PaddingServiceFactory().CreateIso10126Service();
        var data = Enumerable.Range(0, length).Select(i => (byte)(i % 251)).ToArray();

        var padded = service.Pad(data, BlockSize);

        // Output is block-aligned and strictly larger than the input (1..BlockSize padding bytes added).
        Assert.Equal(0, padded.Length % BlockSize);
        Assert.InRange(padded.Length - data.Length, 1, BlockSize);
        // Final byte carries the padding count (the only deterministic byte of the padding).
        Assert.Equal(padded.Length - data.Length, padded[^1]);

        var unpadded = service.Unpad(padded, BlockSize);

        Assert.Equal(data, unpadded);
    }
}
