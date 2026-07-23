using Enigma.Core.Extensions;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Enigma.Core.UnitTests.Extensions;

public class StreamExtensionsInt16Tests
{
    [Fact]
    public void WriteThenRead_Int16_RoundTrips()
    {
        using var output = new MemoryStream();
        output.WriteShort(short.MaxValue);
        output.WriteShort(short.MinValue);

        using var input = new MemoryStream(output.ToArray());

        var result = input.ReadShort();
        Assert.Equal(short.MaxValue, result);
        result = input.ReadShort();
        Assert.Equal(short.MinValue, result);
    }

    [Fact]
    public async Task WriteThenReadAsync_Int16_RoundTrips()
    {
        using var output = new MemoryStream();
        await output.WriteShortAsync(short.MaxValue, TestContext.Current.CancellationToken);
        await output.WriteShortAsync(short.MinValue, TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());

        var result = await input.ReadShortAsync(TestContext.Current.CancellationToken);
        Assert.Equal(short.MaxValue, result);
        result = await input.ReadShortAsync(TestContext.Current.CancellationToken);
        Assert.Equal(short.MinValue, result);
    }

    [Fact]
    public void WriteThenRead_UInt16_RoundTrips()
    {
        using var output = new MemoryStream();
        output.WriteUShort(ushort.MaxValue);
        output.WriteUShort(ushort.MinValue);

        using var input = new MemoryStream(output.ToArray());

        var result = input.ReadUShort();
        Assert.Equal(ushort.MaxValue, result);
        result = input.ReadUShort();
        Assert.Equal(ushort.MinValue, result);
    }

    [Fact]
    public async Task WriteThenReadAsync_UInt16_RoundTrips()
    {
        using var output = new MemoryStream();
        await output.WriteUShortAsync(ushort.MaxValue, TestContext.Current.CancellationToken);
        await output.WriteUShortAsync(ushort.MinValue, TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());

        var result = await input.ReadUShortAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ushort.MaxValue, result);
        result = await input.ReadUShortAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ushort.MinValue, result);
    }
}
