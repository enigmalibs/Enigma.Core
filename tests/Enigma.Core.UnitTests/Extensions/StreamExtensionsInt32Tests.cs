using Enigma.Core.Extensions;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Enigma.Core.UnitTests.Extensions;

public class StreamExtensionsInt32Tests
{
    [Fact]
    public void WriteThenRead_Int32_RoundTrips()
    {
        using var output = new MemoryStream();
        output.WriteInt(int.MaxValue);
        output.WriteInt(int.MinValue);

        using var input = new MemoryStream(output.ToArray());

        var result = input.ReadInt();
        Assert.Equal(int.MaxValue, result);
        result = input.ReadInt();
        Assert.Equal(int.MinValue, result);
    }

    [Fact]
    public async Task WriteThenReadAsync_Int32_RoundTrips()
    {
        using var output = new MemoryStream();
        await output.WriteIntAsync(int.MaxValue, TestContext.Current.CancellationToken);
        await output.WriteIntAsync(int.MinValue, TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());

        var result = await input.ReadIntAsync(TestContext.Current.CancellationToken);
        Assert.Equal(int.MaxValue, result);
        result = await input.ReadIntAsync(TestContext.Current.CancellationToken);
        Assert.Equal(int.MinValue, result);
    }

    [Fact]
    public void WriteThenRead_UInt32_RoundTrips()
    {
        using var output = new MemoryStream();
        output.WriteUInt(uint.MaxValue);
        output.WriteUInt(uint.MinValue);

        using var input = new MemoryStream(output.ToArray());

        var result = input.ReadUInt();
        Assert.Equal(uint.MaxValue, result);
        result = input.ReadUInt();
        Assert.Equal(uint.MinValue, result);
    }

    [Fact]
    public async Task WriteThenReadAsync_UInt32_RoundTrips()
    {
        using var output = new MemoryStream();
        await output.WriteUIntAsync(uint.MaxValue, TestContext.Current.CancellationToken);
        await output.WriteUIntAsync(uint.MinValue, TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());

        var result = await input.ReadUIntAsync(TestContext.Current.CancellationToken);
        Assert.Equal(uint.MaxValue, result);
        result = await input.ReadUIntAsync(TestContext.Current.CancellationToken);
        Assert.Equal(uint.MinValue, result);
    }
}
