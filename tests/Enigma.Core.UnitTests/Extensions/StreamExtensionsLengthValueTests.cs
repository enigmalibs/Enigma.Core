using Enigma.Core.Extensions;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Enigma.Core.UnitTests.Extensions;

public class StreamExtensionsLengthValueTests
{
    [Fact]
    public void WriteThenRead_LengthValue_RoundTrips()
    {
        using var output = new MemoryStream();
        output.WriteLengthValue([0, 1, 254, 255]);

        using var input = new MemoryStream(output.ToArray());
        var result = input.ReadLengthValue();
        Assert.Equal([0, 1, 254, 255], result);
    }

    [Fact]
    public async Task WriteThenReadAsync_LengthValue_RoundTrips()
    {
        using var output = new MemoryStream();
        await output.WriteLengthValueAsync([0, 1, 254, 255], TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());
        var result = await input.ReadLengthValueAsync(cancellationToken: TestContext.Current.CancellationToken);
        Assert.Equal([0, 1, 254, 255], result);
    }

    [Fact]
    public void ReadLengthValue_NegativeLength_Throws()
    {
        // A negative length prefix must be rejected rather than passed to ReadBytes.
        using var output = new MemoryStream();
        output.WriteInt(-1);

        using var input = new MemoryStream(output.ToArray());
        Assert.Throws<InvalidOperationException>(() => input.ReadLengthValue());
    }

    [Fact]
    public void ReadLengthValue_LengthExceedsMax_Throws()
    {
        // A length prefix larger than maxLength must be rejected (guards against oversized allocation).
        using var output = new MemoryStream();
        output.WriteInt(100);

        using var input = new MemoryStream(output.ToArray());
        Assert.Throws<InvalidOperationException>(() => input.ReadLengthValue(maxLength: 10));
    }

    [Fact]
    public async Task ReadLengthValueAsync_NegativeLength_Throws()
    {
        using var output = new MemoryStream();
        output.WriteInt(-1);

        using var input = new MemoryStream(output.ToArray());
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            input.ReadLengthValueAsync(cancellationToken: TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task ReadLengthValueAsync_LengthExceedsMax_Throws()
    {
        using var output = new MemoryStream();
        output.WriteInt(100);

        using var input = new MemoryStream(output.ToArray());
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            input.ReadLengthValueAsync(maxLength: 10, cancellationToken: TestContext.Current.CancellationToken));
    }
}
