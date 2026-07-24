using Enigma.Core.Extensions;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Enigma.Core.UnitTests.Extensions;

public class StreamExtensionsInt64Tests
{
    [Fact]
    public void WriteThenRead_Int64_RoundTrips()
    {
        using var output = new MemoryStream();
        output.WriteLong(long.MaxValue);
        output.WriteLong(long.MinValue);

        using var input = new MemoryStream(output.ToArray());

        var result = input.ReadLong();
        Assert.Equal(long.MaxValue, result);
        result = input.ReadLong();
        Assert.Equal(long.MinValue, result);
    }

    [Fact]
    public async Task WriteThenReadAsync_Int64_RoundTrips()
    {
        using var output = new MemoryStream();
        await output.WriteLongAsync(long.MaxValue, TestContext.Current.CancellationToken);
        await output.WriteLongAsync(long.MinValue, TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());

        var result = await input.ReadLongAsync(TestContext.Current.CancellationToken);
        Assert.Equal(long.MaxValue, result);
        result = await input.ReadLongAsync(TestContext.Current.CancellationToken);
        Assert.Equal(long.MinValue, result);
    }

    [Fact]
    public void WriteThenRead_UInt64_RoundTrips()
    {
        using var output = new MemoryStream();
        output.WriteULong(ulong.MaxValue);
        output.WriteULong(ulong.MinValue);

        using var input = new MemoryStream(output.ToArray());

        var result = input.ReadULong();
        Assert.Equal(ulong.MaxValue, result);
        result = input.ReadULong();
        Assert.Equal(ulong.MinValue, result);
    }

    [Fact]
    public async Task WriteThenReadAsync_UInt64_RoundTrips()
    {
        using var output = new MemoryStream();
        await output.WriteULongAsync(ulong.MaxValue, TestContext.Current.CancellationToken);
        await output.WriteULongAsync(ulong.MinValue, TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());

        var result = await input.ReadULongAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ulong.MaxValue, result);
        result = await input.ReadULongAsync(TestContext.Current.CancellationToken);
        Assert.Equal(ulong.MinValue, result);
    }
}
