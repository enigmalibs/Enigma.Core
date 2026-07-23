using Enigma.Core.Extensions;
using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace Enigma.Core.UnitTests.Extensions;

public class StreamExtensionsBytesTests
{
    [Fact]
    public async Task WriteThenReadAsync_Byte_RoundTrips()
    {
        using var output = new MemoryStream();
        await output.WriteByteAsync(byte.MaxValue, TestContext.Current.CancellationToken);
        await output.WriteByteAsync(byte.MinValue, TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());

        var result = await input.ReadByteAsync(TestContext.Current.CancellationToken);
        Assert.Equal(byte.MaxValue, result);
        result = await input.ReadByteAsync(TestContext.Current.CancellationToken);
        Assert.Equal(byte.MinValue, result);
    }

    [Fact]
    public void WriteThenRead_Bytes_RoundTrips()
    {
        using var output = new MemoryStream();
        output.WriteBytes([0, 1, 254, 255]);

        using var input = new MemoryStream(output.ToArray());

        var result = input.ReadBytes(4);
        Assert.Equal([0, 1, 254, 255], result);
    }

    [Fact]
    public async Task WriteThenReadAsync_Bytes_RoundTrips()
    {
        using var output = new MemoryStream();
        await output.WriteBytesAsync([0, 1, 254, 255], TestContext.Current.CancellationToken);

        using var input = new MemoryStream(output.ToArray());

        var result = await input.ReadBytesAsync(4, TestContext.Current.CancellationToken);
        Assert.Equal([0, 1, 254, 255], result);
    }
}
